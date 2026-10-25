#!/usr/bin/env python3
"""Mirror vendor CIDR lists (Telegram, Google, Apple) and serve them per provider.

Each list is fetched on a schedule, validated, split into IPv4 / IPv6 and served
from your own domain so pfSense (URL Table alias) can pull it.

Endpoints (optionally under /<PATH_PREFIX>/):
    /<provider>/v4.txt    IPv4 ranges, one per line
    /<provider>/v6.txt    IPv6 ranges, one per line
    /<provider>/all.txt   both
    POST /ingest/<provider>   report IPs you actually saw (needs INGEST_TOKEN)
    /healthz              liveness check (never behind the prefix)

    e.g. https://cidr.example.com/telegram/v4.txt
         https://cidr.example.com/google/all.txt
         https://cidr.example.com/apple/v4.txt

Environment variables:
    PROVIDERS      enabled providers, comma separated  (default: telegram,google,apple)
    <NAME>_URL     override a provider's source URL, e.g. GOOGLE_URL
                   (set APPLE_URL to use a published Apple list; the default is
                   Apple's own static allocation)
    OUT_DIR        where files are written  (default: /data)
    REFRESH_HOURS  refresh interval         (default: 24)
    PORT           listen port              (default: 8080)
    <NAME>_HOSTS   hostnames to resolve and add to that provider's list (comma separated);
                   apple has a built-in set (developer.apple.com, idmsa.apple.com, ...)
    RESOLVE_MINUTES  how often hostnames are re-resolved   (default: 30)
    EXPIRE_DAYS      forget learned IPs not seen for this long, 0 = never  (default: 90)
    INGEST_TOKEN   enables POST /ingest/<provider>; send "Authorization: Bearer <token>"
                   and a body of "<ip> <hostname>" lines. Only hostnames that belong to
                   the provider (e.g. *.apple.com) are accepted.
    PATH_PREFIX    optional secret path segment, e.g. "k3x9q2" -> /k3x9q2/telegram/v4.txt

CLI (no server):
    python app.py --once                               fetch every provider, write files, exit
    python app.py --once --provider google             only one provider
    python app.py --once --provider telegram --from-file cidr.txt
    python app.py --once --out ./out                   write somewhere else

Learned IPs (from hostname resolution and /ingest) live in OUT_DIR/seen.db (SQLite) and
are merged with the provider's base ranges into the served files.
"""
import argparse
import ipaddress
import json
import socket
import logging
import os
import hmac
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUT_DIR = Path(os.getenv("OUT_DIR", "/data"))
REFRESH_HOURS = float(os.getenv("REFRESH_HOURS", "24"))
PORT = int(os.getenv("PORT", "8080"))
PATH_PREFIX = os.getenv("PATH_PREFIX", "").strip("/")

RESOLVE_MINUTES = float(os.getenv("RESOLVE_MINUTES", "30"))
EXPIRE_DAYS = float(os.getenv("EXPIRE_DAYS", "90"))
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")
MAX_INGEST_BYTES = 256_000

RETRY_SECONDS = 600
MAX_BYTES = 20_000_000
FILES = ("v4.txt", "v6.txt", "all.txt")

# fmt: "text" = one CIDR per line (first comma field, '#' comments ignored)
#      "google" = goog.json style {"prefixes": [{"ipv4Prefix"|"ipv6Prefix": ...}]}
# min_v4 / min_v6: sanity floor, rejects an upstream file that looks truncated.
# fallback: written until the first successful fetch so the URL works immediately.
PROVIDERS = {
    "telegram": {
        "url": "https://core.telegram.org/resources/cidr.txt",
        "fmt": "text",
        "min_v4": 5,
        "min_v6": 2,
        "fallback": """
91.108.56.0/22
91.108.4.0/22
91.108.8.0/22
91.108.16.0/22
91.108.12.0/22
149.154.160.0/20
91.105.192.0/23
91.108.20.0/22
185.76.151.0/24
2001:b28:f23d::/48
2001:b28:f23f::/48
2001:67c:4e8::/48
2001:b28:f23c::/48
2a0a:f280::/32
""",
    },
    "google": {
        "url": "https://www.gstatic.com/ipranges/goog.json",
        "fmt": "google",
        "min_v4": 10,
        "min_v6": 2,
        "fallback": "",
    },
    "apple": {
        # Apple publishes no official list; the base is its own static allocation, plus
        # the prefixes announced by "asns" (RIPEstat) and every IP the "hosts" resolve to
        # (CDN-fronted services). Set APPLE_URL to use a text/CSV list as the base instead.
        "url": "",
        "fmt": "text",
        "min_v4": 1,
        "min_v6": 0,
        "fallback": """
17.0.0.0/8
2620:149::/32
""",
        "asns": ["714", "6185"],
        "hosts": [
            "developer.apple.com",
            "appstoreconnect.apple.com",
            "api.appstoreconnect.apple.com",
            "idmsa.apple.com",
            "appleid.apple.com",
            "account.apple.com",
            "developerservices2.apple.com",
            "contentdelivery.itunes.apple.com",
            "ppq.apple.com",
            "init.itunes.apple.com",
            "buy.itunes.apple.com",
            "is1-ssl.mzstatic.com",
            "is2-ssl.mzstatic.com",
            "is3-ssl.mzstatic.com",
            "is4-ssl.mzstatic.com",
            "is5-ssl.mzstatic.com",
        ],
        # /ingest only accepts hostnames equal to or under these domains
        "suffixes": ["apple.com", "mzstatic.com", "icloud.com", "cdn-apple.com", "aaplimg.com", "apple-dns.net"],
    },
}

log = logging.getLogger("cidr-mirror")


def enabled_providers():
    names = [n.strip().lower() for n in os.getenv("PROVIDERS", ",".join(PROVIDERS)).split(",") if n.strip()]
    unknown = [n for n in names if n not in PROVIDERS]
    if unknown:
        sys.exit(f"unknown provider(s): {', '.join(unknown)} (available: {', '.join(PROVIDERS)})")
    return names


def source_url(name):
    return os.getenv(f"{name.upper()}_URL", PROVIDERS[name]["url"])


def hosts(name):
    env = os.getenv(f"{name.upper()}_HOSTS")
    if env is not None:
        return [h.strip().lower() for h in env.split(",") if h.strip()]
    return PROVIDERS[name].get("hosts", [])


def learns(name):
    return bool(hosts(name) or PROVIDERS[name].get("suffixes"))


BASE = {}  # provider -> (v4, v6) last fetched base ranges
LOCK = threading.RLock()


def db(out):
    out.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(out / "seen.db")
    con.execute(
        "CREATE TABLE IF NOT EXISTS seen (provider TEXT, ip TEXT, host TEXT, first_seen INTEGER,"
        " last_seen INTEGER, PRIMARY KEY (provider, ip))"
    )
    return con


def record(name, pairs, out):
    """Store (ip, host) pairs. Returns how many IPs were new."""
    now = int(time.time())
    new = 0
    with LOCK, db(out) as con:
        for ip, host in pairs:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not addr.is_global:
                continue
            ip = str(addr)
            if con.execute("SELECT 1 FROM seen WHERE provider=? AND ip=?", (name, ip)).fetchone():
                con.execute("UPDATE seen SET last_seen=? WHERE provider=? AND ip=?", (now, name, ip))
            else:
                con.execute("INSERT INTO seen VALUES (?,?,?,?,?)", (name, ip, host, now, now))
                new += 1
        expired = 0
        if EXPIRE_DAYS > 0:
            expired = con.execute(
                "DELETE FROM seen WHERE provider=? AND last_seen<?", (name, now - int(EXPIRE_DAYS * 86400))
            ).rowcount
    con.close()
    return new, expired


def learned(name, out):
    with LOCK, db(out) as con:
        rows = con.execute("SELECT ip FROM seen WHERE provider=?", (name,)).fetchall()
    con.close()
    return [r[0] for r in rows]


def _add(nets, value):
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        log.warning("skipping invalid entry: %r", value)
        return
    nets[net.version].add(net)


def parse(text, fmt="text"):
    """Return (sorted_v4, sorted_v6) networks from raw list content."""
    nets = {4: set(), 6: set()}
    if fmt == "google":
        for p in json.loads(text).get("prefixes", []):
            value = p.get("ipv4Prefix") or p.get("ipv6Prefix")
            if value:
                _add(nets, value)
    else:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].split(",", 1)[0].strip()
            if line:
                _add(nets, line)
    return sorted(nets[4]), sorted(nets[6])


def write_atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def write_set(d, prefix, v4, v6):
    l4 = [str(n) for n in v4]
    l6 = [str(n) for n in v6]
    write_atomic(d / f"{prefix}v4.txt", "".join(f"{x}\n" for x in l4))
    write_atomic(d / f"{prefix}v6.txt", "".join(f"{x}\n" for x in l6))
    write_atomic(d / f"{prefix}all.txt", "".join(f"{x}\n" for x in l4 + l6))


def save(name, v4, v6, out):
    cfg = PROVIDERS[name]
    if len(v4) < cfg["min_v4"] or len(v6) < cfg["min_v6"]:
        raise ValueError(f"suspicious list: {len(v4)} IPv4 / {len(v6)} IPv6 ranges")
    write_set(out / name, "", v4, v6)


def build(name, out):
    """Merge base ranges with learned IPs and write the files."""
    with LOCK:
        v4, v6 = BASE.get(name) or parse(PROVIDERS[name]["fallback"])
        if learns(name) or PROVIDERS[name].get("asns"):
            base = {4: set(v4), 6: set(v6)}
            for ip in learned(name, out):
                _add(base, ip)
            v4 = list(ipaddress.collapse_addresses(base[4]))
            v6 = list(ipaddress.collapse_addresses(base[6]))
        save(name, sorted(v4), sorted(v6), out)
    return len(v4), len(v6)


def asn_prefixes(asns):
    text = ""
    for asn in asns:
        try:
            data = json.loads(fetch(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"))
            text += "".join(p["prefix"] + "\n" for p in data["data"]["prefixes"])
        except Exception as exc:  # noqa: BLE001
            log.warning("AS%s prefixes unavailable: %s", asn, exc)
    return text


def resolve(name, out):
    """Resolve the provider's hostnames and remember every IP. Returns True if files changed."""
    pairs = []
    for host in hosts(name):
        try:
            for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                pairs.append((info[4][0], host))
        except OSError as exc:
            log.warning("%s: cannot resolve %s: %s", name, host, exc)
    new, expired = record(name, pairs, out)
    if new or expired:
        log.info("%s: learned %d new IPs, expired %d", name, new, expired)
    return bool(new or expired)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cidr-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read(MAX_BYTES).decode("utf-8")


def refresh(name, out):
    """Fetch + parse + save. On any failure the previous files are left untouched."""
    try:
        url = source_url(name)
        text = fetch(url) if url else PROVIDERS[name]["fallback"]
        text += asn_prefixes(PROVIDERS[name].get("asns", []))
        v4, v6 = parse(text, PROVIDERS[name]["fmt"])
        BASE[name] = (v4, v6)
        v4n, v6n = build(name, out)
    except Exception as exc:  # noqa: BLE001
        log.error("%s: refresh failed, keeping previous files: %s", name, exc)
        return False
    log.info("%s: refreshed: %d IPv4, %d IPv6 ranges", name, v4n, v6n)
    return True


def refresher(name):
    stop = threading.Event()
    while True:
        ok = refresh(name, OUT_DIR)
        stop.wait(REFRESH_HOURS * 3600 if ok else RETRY_SECONDS)


def resolver(name):
    stop = threading.Event()
    while True:
        try:
            if resolve(name, OUT_DIR):
                build(name, OUT_DIR)
        except Exception as exc:  # noqa: BLE001
            log.error("%s: resolve failed: %s", name, exc)
        stop.wait(RESOLVE_MINUTES * 60)


class Handler(BaseHTTPRequestHandler):
    server_version = "cidr-mirror"
    providers = ()

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        prefix = f"/{PATH_PREFIX}/" if PATH_PREFIX else "/"
        parts = path[len(prefix):].split("/") if path.startswith(prefix) else []
        if not INGEST_TOKEN or len(parts) != 2 or parts[0] != "ingest" or parts[1] not in self.providers:
            return self._send(404, b"not found\n", True)
        name = parts[1]
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, f"Bearer {INGEST_TOKEN}"):
            return self._send(401, b"unauthorized\n", True)
        suffixes = PROVIDERS[name].get("suffixes")
        length = int(self.headers.get("Content-Length") or 0)
        if not suffixes or not 0 < length <= MAX_INGEST_BYTES:
            return self._send(400, b"bad request\n", True)
        pairs = []
        for line in self.rfile.read(length).decode("utf-8", "replace").splitlines():
            fields = line.split()
            if len(fields) != 2:
                continue
            ip, host = fields[0], fields[1].rstrip(".").lower()
            if any(host == s or host.endswith("." + s) for s in suffixes):
                pairs.append((ip, host))
        new, expired = record(name, pairs, OUT_DIR)
        if new or expired:
            build(name, OUT_DIR)
        log.info("%s: ingest %d lines, %d new IPs", name, len(pairs), new)
        self._send(200, f"added {new}\n".encode(), True)

    def _serve(self, send_body):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, b"ok\n", send_body)
        prefix = f"/{PATH_PREFIX}/" if PATH_PREFIX else "/"
        if not path.startswith(prefix):
            return self._send(404, b"not found\n", send_body)
        parts = path[len(prefix):].split("/")
        if len(parts) != 2 or parts[0] not in self.providers or parts[1] not in FILES:
            return self._send(404, b"not found\n", send_body)
        try:
            data = (OUT_DIR / parts[0] / parts[1]).read_bytes()
        except OSError:
            return self._send(503, b"not ready\n", send_body)
        self._send(200, data, send_body)

    def _send(self, code, data, send_body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if send_body:
            self.wfile.write(data)


def run_once(args):
    out = Path(args.out) if args.out else OUT_DIR
    names = [args.provider] if args.provider else enabled_providers()
    if args.from_file and len(names) != 1:
        sys.exit("--from-file needs --provider")
    failed = False
    for name in names:
        if args.from_file:
            BASE[name] = parse(Path(args.from_file).read_text(), PROVIDERS[name]["fmt"])
            v4n, v6n = build(name, out)
            print(f"{name}: wrote {v4n} IPv4 / {v6n} IPv6 ranges to {out}")
        elif not refresh(name, out):
            failed = True
        elif hosts(name) and resolve(name, out):
            build(name, out)
    return 1 if failed else 0


def run_server():
    names = enabled_providers()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in names:
        if not (OUT_DIR / name / "v4.txt").exists() and PROVIDERS[name]["fallback"]:
            v4, v6 = parse(PROVIDERS[name]["fallback"])
            BASE[name] = (v4, v6)
            build(name, OUT_DIR)
            log.warning("%s: no existing files; wrote built-in fallback until first fetch succeeds", name)
        if source_url(name) or PROVIDERS[name].get("asns"):
            threading.Thread(target=refresher, args=(name,), daemon=True).start()
        if hosts(name):
            threading.Thread(target=resolver, args=(name,), daemon=True).start()
    Handler.providers = tuple(names)
    log.info("serving %s on :%d (prefix=%r), refresh every %sh", ",".join(names), PORT, PATH_PREFIX, REFRESH_HOURS)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="fetch/parse/write once and exit")
    ap.add_argument("--provider", choices=list(PROVIDERS), help="with --once: only this provider")
    ap.add_argument("--from-file", help="with --once --provider: parse this local file instead of fetching")
    ap.add_argument("--out", help="with --once: output directory (default: OUT_DIR)")
    args = ap.parse_args()
    if args.once:
        sys.exit(run_once(args))
    run_server()


if __name__ == "__main__":
    main()
