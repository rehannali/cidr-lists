# cidr-lists
Mirrors vendor CIDR lists (Telegram, Google, Apple) for pfSense URL Table aliases, served from your own domain.

    https://<your-domain>/telegram/v4.txt   (also v6.txt, all.txt)
    https://<your-domain>/google/v4.txt
    https://<your-domain>/apple/v4.txt

Sources: Telegram `cidr.txt`, Google `goog.txt`, Apple's static allocation (17.0.0.0/8, 2620:149::/32).
Override any source with `<NAME>_URL`, limit providers with `PROVIDERS`, and hide the whole tree
behind a secret path with `PATH_PREFIX`. See the docstring in `app.py`.

## Apple
`/apple/*` is the union of:
- `17.0.0.0/8` and `2620:149::/32` (Apple's own allocation)
- prefixes announced by AS714 and AS6185 (RIPEstat, refreshed daily)
- every IP the Apple hostnames resolve to (developer, App Store Connect, Apple ID, iTunes, mzstatic, ...),
  re-resolved every `RESOLVE_MINUTES`; override the list with `APPLE_HOSTS`

Resolved and reported IPs are stored in `seen.db` (SQLite, in the `/data` volume) and expire after
`EXPIRE_DAYS` without being seen again. New IPs show up in the list immediately.

To learn from real client traffic, set `INGEST_TOKEN` and run `scripts/pfsense-ingest.sh` from cron on
pfSense. It posts the A/AAAA answers for `*.apple.com` etc. from Unbound's cache to `POST /ingest/apple`.
Only hostnames under Apple's domains and public IPs are accepted.

### Learning from NextDNS
Set `NEXTDNS_API_KEY` and `NEXTDNS_PROFILES` (comma separated profile ids) and enable logging on the
profile. The server reads the last day of logs, then follows the live log stream (resuming after any
disconnect) and re-reads recent logs every `NEXTDNS_POLL_MINUTES` in case the stream stalls. Every queried domain under Apple's domains is remembered and resolved immediately, and
its IPs are added to the list; remembered domains are re-resolved every `RESOLVE_MINUTES`.

NextDNS logs contain the queried domain but not the answer IPs, so the IPs come from this server's own
DNS lookups and can differ from what a client was given by a CDN.
