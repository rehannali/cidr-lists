#!/bin/sh
# Run from cron on pfSense (Cron package, e.g. every 15 min). Reports the Apple IPs your
# own network actually resolved to the mirror, so the list learns what clients really hit.
#
# Reads Unbound's cache. CDN-fronted names (developer.apple.com -> ...akamaiedge.net) only
# have their A records under the CDN name, so the CNAME chain is followed back to the Apple
# name. Entries only exist for names your clients looked up recently.
URL="https://cidr.example.com/ingest/apple"   # include your PATH_PREFIX if you set one
TOKEN="change-me"                              # same value as INGEST_TOKEN on the server
DUMP_CMD="${DUMP_CMD:-unbound-control -c /var/unbound/unbound.conf dump_cache}"

eval "$DUMP_CMD" 2>/dev/null |
  awk '
    $3 == "IN" && $4 == "CNAME" { back[tolower($5)] = tolower($1) }
    $3 == "IN" && ($4 == "A" || $4 == "AAAA") { n++; owner[n] = tolower($1); ip[n] = $5 }
    END {
      re = "(^|\\.)(apple\\.com|mzstatic\\.com|icloud\\.com|cdn-apple\\.com|aaplimg\\.com|apple-dns\\.net)\\.$"
      for (i = 1; i <= n; i++) {
        name = owner[i]
        for (hops = 0; name != "" && hops < 10; hops++) {
          if (name ~ re) { print ip[i], name; break }
          name = back[name]
        }
      }
    }' |
  sort -u |
  curl -fsS -X POST -H "Authorization: Bearer $TOKEN" --data-binary @- "$URL"
