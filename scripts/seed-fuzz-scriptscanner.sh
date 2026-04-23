#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATES="$REPO_ROOT/testdata/vulnerable-payment-service/templates"
DST="$REPO_ROOT/testdata/fuzz/FuzzScriptScannerHTML"

if [ ! -d "$TEMPLATES" ]; then
  echo "templates dir missing: $TEMPLATES" >&2
  exit 1
fi

mkdir -p "$DST"

count=0
for src in "$TEMPLATES"/*.html; do
  [ -f "$src" ] || continue
  hash=$(shasum -a 256 "$src" | awk '{print $1}' | cut -c1-16)
  out="$DST/seed-${hash}"
  if [ ! -f "$out" ]; then
    {
      printf 'go test fuzz v1\n'
      printf '[]byte('
      awk 'BEGIN{printf "\""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r"); printf "%s\\n", $0} END{printf "\")"}' "$src"
      printf '\n'
    } > "$out"
    count=$((count + 1))
  fi
done

echo "seeded $count html templates into $DST"
