#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-${1:-pci-dss-mcp:local}}"
FIXTURE_HOST="${FIXTURE_HOST:-$(pwd)/testdata/vulnerable-payment-service}"

EXPECTED_CRITICAL=51
EXPECTED_HIGH=95
EXPECTED_MEDIUM=53
EXPECTED_LOW=0
EXPECTED_INFO=69

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
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_compliance_report","arguments":{"path":"/projects/fixture"}}}
EOF
)

TMP_DIR=$(mktemp -d)
CONTAINER_NAME="pci-dss-mcp-smoke-$$"
FEEDER_PID=""
DOCKER_PID=""
cleanup() {
  if [ -n "$DOCKER_PID" ]; then
    kill -9 "$DOCKER_PID" 2>/dev/null || true
  fi
  if [ -n "$FEEDER_PID" ]; then
    kill -9 "$FEEDER_PID" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
FIFO_IN="$TMP_DIR/in"
RESP_FILE="$TMP_DIR/resp.jsonl"
mkfifo "$FIFO_IN"
: >"$RESP_FILE"

{ printf '%s\n' "$REQUEST"; exec tail -f /dev/null; } >"$FIFO_IN" &
FEEDER_PID=$!

docker run -i --rm --name "$CONTAINER_NAME" \
  --mount "type=bind,src=${FIXTURE_HOST},dst=/projects/fixture,readonly" \
  "$IMAGE" <"$FIFO_IN" >"$RESP_FILE" 2>/dev/null &
DOCKER_PID=$!

deadline=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if grep -qE '^\{.*"id":2' "$RESP_FILE" 2>/dev/null; then
    break
  fi
  sleep 1
done

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
kill -9 "$FEEDER_PID" 2>/dev/null || true
wait "$DOCKER_PID" 2>/dev/null || true
FEEDER_PID=""
DOCKER_PID=""

RESPONSE=$(cat "$RESP_FILE")

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

check critical_findings "$EXPECTED_CRITICAL"
check high_findings     "$EXPECTED_HIGH"
check medium_findings   "$EXPECTED_MEDIUM"
check low_findings      "$EXPECTED_LOW"
check info_findings     "$EXPECTED_INFO"

echo "OK: Docker severity parity ($EXPECTED_CRITICAL/$EXPECTED_HIGH/$EXPECTED_MEDIUM/$EXPECTED_LOW/$EXPECTED_INFO) on $IMAGE"
