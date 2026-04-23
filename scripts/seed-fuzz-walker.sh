#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$REPO_ROOT/testdata/vulnerable-payment-service"
DST="$REPO_ROOT/testdata/fuzz/FuzzWalker"

MAX_SEEDS=60

if [ ! -d "$FIXTURE" ]; then
  echo "fixture dir missing: $FIXTURE" >&2
  exit 1
fi

mkdir -p "$DST"

count=0
while IFS= read -r -d '' src; do
  if [ "$count" -ge "$MAX_SEEDS" ]; then
    break
  fi
  size=$(wc -c <"$src" | tr -d ' ')
  if [ "$size" -gt 65536 ]; then
    continue
  fi
  hash=$(shasum -a 256 "$src" | awk '{print $1}' | cut -c1-16)
  out="$DST/seed-${hash}"
  if [ -f "$out" ]; then
    count=$((count + 1))
    continue
  fi
  {
    printf 'go test fuzz v1\n'
    printf '[]byte('
    awk 'BEGIN{printf "\""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r"); printf "%s\\n", $0} END{printf "\")"}' "$src"
    printf '\n'
  } > "$out"
  count=$((count + 1))
done < <(find "$FIXTURE" -type f -name '*.go' -print0 | sort -z)

echo "seeded $count files into $DST"
