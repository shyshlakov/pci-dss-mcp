#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-${1:-pci-dss-mcp:local}}"
FIXTURE_HOST="${FIXTURE_HOST:-$(pwd)/testdata/vulnerable-payment-service}"

EXPECTED_CRITICAL=49
EXPECTED_HIGH=89
EXPECTED_MEDIUM=27
EXPECTED_LOW=0
EXPECTED_INFO=59

if ! command -v docker >/dev/null 2>&1; then
  echo "docker CLI not found on PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found on PATH" >&2
  exit 1
fi

if [ ! -d "$FIXTURE_HOST" ]; then
  echo "fixture directory not found: $FIXTURE_HOST" >&2
  exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "image not present locally: $IMAGE" >&2
  echo "hint: run 'make docker-build-local' first, or pass IMAGE=<tag>" >&2
  exit 1
fi

REQUEST=$(cat <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"docker-smoke","version":"1"},"capabilities":{}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_compliance_report","arguments":{"path":"/projects/fixture","limit":-1}}}
EOF
)

RESPONSE=$(printf '%s\n' "$REQUEST" | docker run -i --rm \
  --mount "type=bind,src=${FIXTURE_HOST},dst=/projects/fixture,readonly" \
  "$IMAGE")

SUMMARY=$(printf '%s\n' "$RESPONSE" \
  | grep -E '^\{.*"id":2' \
  | tail -n 1 \
  | jq -r '.result.structuredContent.summary')

if [ -z "$SUMMARY" ] || [ "$SUMMARY" = "null" ]; then
  echo "smoke failed: tools/call response missing .result.structuredContent.summary" >&2
  echo "---RAW RESPONSE---" >&2
  printf '%s\n' "$RESPONSE" >&2
  exit 1
fi

check() {
  local key=$1
  local expected=$2
  local got
  got=$(printf '%s\n' "$SUMMARY" | jq -r ".$key")
  if [ "$got" != "$expected" ]; then
    echo "FAIL: severity parity drift on $key: expected=$expected got=$got" >&2
    exit 1
  fi
}

check critical "$EXPECTED_CRITICAL"
check high     "$EXPECTED_HIGH"
check medium   "$EXPECTED_MEDIUM"
check low      "$EXPECTED_LOW"
check info     "$EXPECTED_INFO"

echo "OK: Docker severity parity ($EXPECTED_CRITICAL/$EXPECTED_HIGH/$EXPECTED_MEDIUM/$EXPECTED_LOW/$EXPECTED_INFO) on $IMAGE"
