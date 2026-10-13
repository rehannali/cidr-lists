#!/usr/bin/env python3
"""Mirror Telegram's official CIDR list as separate IPv4 / IPv6 files and serve them.

Fetches https://core.telegram.org/resources/cidr.txt on a schedule, validates and
splits it, and serves the result so pfSense (URL Table alias) can pull it from
your own domain.

Endpoints (optionally under /<PATH_PREFIX>/):
    telegram-v4.txt   IPv4 ranges, one per line
    telegram-v6.txt   IPv6 ranges, one per line
    telegram-all.txt  both
    /healthz          liveness check (never behind the prefix)

Environment variables:
    SOURCE_URL     upstream list            (default: official Telegram URL)
    OUT_DIR        where files are written  (default: /data)
    REFRESH_HOURS  refresh interval         (default: 24)
    PORT           listen port              (default: 8080)
    PATH_PREFIX    optional secret path segment, e.g. "k3x9q2" -> /k3x9q2/telegram-v4.txt

CLI (no server):
    python app.py --once                        fetch, write files, exit
    python app.py --once --from-file cidr.txt   parse a local copy instead
    python app.py --once --out ./out            write somewhere else
"""
import argparse
import ipaddress
import logging
import os
import sys
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SOURCE_URL = os.getenv("SOURCE_URL", "https://core.telegram.org/resources/cidr.txt")
OUT_DIR = Path(os.getenv("OUT_DIR", "/data"))
REFRESH_HOURS = float(os.getenv("REFRESH_HOURS", "24"))
PORT = int(os.getenv("PORT", "8080"))
PATH_PREFIX = os.getenv("PATH_PREFIX", "").strip("/")

RETRY_SECONDS = 600
MIN_V4, MIN_V6 = 5, 2  # sanity floor: reject an upstream file that looks truncated
FILES = ("telegram-v4.txt", "telegram-v6.txt", "telegram-all.txt")

# Used only so the URL works before the first successful fetch.
# Replaced as soon as a fetch succeeds.
FALLBACK = """
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
"""

log = logging.getLogger("tg-cidr")


def parse(text):
    """Return (sorted_v4, sorted_v6) networks from raw cidr.txt content."""
    v4, v6 = set(), set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            log.warning("skipping invalid line: %r", line)
            continue
        (v4 if net.version == 4 else v6).add(net)
    return sorted(v4), sorted(v6)


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


def save(v4, v6, out):
    if len(v4) < MIN_V4 or len(v6) < MIN_V6:
        raise ValueError(f"suspicious list: {len(v4)} IPv4 / {len(v6)} IPv6 ranges")
    l4 = [str(n) for n in v4]
    l6 = [str(n) for n in v6]
    write_atomic(out / "telegram-v4.txt", "\n".join(l4) + "\n")
    write_atomic(out / "telegram-v6.txt", "\n".join(l6) + "\n")
    write_atomic(out / "telegram-all.txt", "\n".join(l4 + l6) + "\n")


def fetch():
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "tg-cidr-mirror/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read(1_000_000).decode("utf-8")


def refresh(out):
    """Fetch + parse + save. On any failure the previous files are left untouched."""
    try:
        v4, v6 = parse(fetch())
        save(v4, v6, out)
    except Exception as exc:  # noqa: BLE001
        log.error("refresh failed, keeping previous files: %s", exc)
        return False
    log.info("refreshed: %d IPv4, %d IPv6 ranges", len(v4), len(v6))
    return True


def refresher():
    stop = threading.Event()
    while True:
        ok = refresh(OUT_DIR)
        stop.wait(REFRESH_HOURS * 3600 if ok else RETRY_SECONDS)


class Handler(BaseHTTPRequestHandler):
    server_version = "tg-cidr"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)

    def _serve(self, send_body):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, b"ok\n", send_body)
        prefix = f"/{PATH_PREFIX}/" if PATH_PREFIX else "/"
        if not path.startswith(prefix):
            return self._send(404, b"not found\n", send_body)
        name = path[len(prefix):]
        if name not in FILES:
            return self._send(404, b"not found\n", send_body)
        try:
            data = (OUT_DIR / name).read_bytes()
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
    if args.from_file:
        text = Path(args.from_file).read_text()
        v4, v6 = parse(text)
        save(v4, v6, out)
        print(f"wrote {len(v4)} IPv4 / {len(v6)} IPv6 ranges to {out}")
        return 0
    ok = refresh(out)
    return 0 if ok else 1


def run_server():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not (OUT_DIR / FILES[0]).exists():
        v4, v6 = parse(FALLBACK)
        save(v4, v6, OUT_DIR)
        log.warning("no existing files; wrote built-in fallback list until first fetch succeeds")
    threading.Thread(target=refresher, daemon=True).start()
    log.info("serving on :%d (prefix=%r), refresh every %sh", PORT, PATH_PREFIX, REFRESH_HOURS)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="fetch/parse/write once and exit")
    ap.add_argument("--from-file", help="with --once: parse this local file instead of fetching")
    ap.add_argument("--out", help="with --once: output directory (default: OUT_DIR)")
    args = ap.parse_args()
    if args.once:
        sys.exit(run_once(args))
    run_server()


if __name__ == "__main__":
    main()
