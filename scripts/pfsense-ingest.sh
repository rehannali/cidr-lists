#!/bin/sh
# Run from cron on pfSense (Cron package, e.g. every 15 min). Reports the Apple IPs your
# own network actually resolved to the mirror, so the list learns what clients really hit.
# Needs: Services > DNS Resolver (Unbound) with remote control enabled (default on pfSense).
# Untested on a live pfSense; check `unbound-control dump_cache | head` output matches.
URL="https://cidr.example.com/ingest/apple"   # include your PATH_PREFIX if you set one
TOKEN="change-me"                              # same value as INGEST_TOKEN on the server

unbound-control dump_cache 2>/dev/null |
  awk '$3 == "IN" && ($4 == "A" || $4 == "AAAA") && $1 ~ /(apple\.com|mzstatic\.com|icloud\.com|cdn-apple\.com|aaplimg\.com|apple-dns\.net)\.$/ { print $5, $1 }' |
  sort -u |
  curl -fsS -X POST -H "Authorization: Bearer $TOKEN" --data-binary @- "$URL"
