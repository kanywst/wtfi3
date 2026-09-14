#!/usr/bin/env bash
#
# update-oui.sh regenerates web/oui.tsv, the embedded MAC-vendor database.
#
# Source: nmap's nmap-mac-prefixes, which is itself derived from the IEEE OUI
# registry. Output format is one "aa:bb:cc<TAB>Vendor" line per prefix.
#
# Usage: hack/update-oui.sh
set -euo pipefail

SRC="https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes"
DEST="$(cd "$(dirname "$0")/.." && pwd)/web/oui.tsv"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "fetching $SRC"
curl -fsSL "$SRC" -o "$TMP"

echo "converting to $DEST"
grep '^[0-9A-Fa-f]' "$TMP" \
  | awk '{
      oui = tolower(substr($1,1,2)":"substr($1,3,2)":"substr($1,5,2));
      $1="";
      sub(/^ /,"");
      print oui"\t"$0
    }' > "$DEST"

echo "wrote $(wc -l < "$DEST" | tr -d ' ') entries to $DEST"
