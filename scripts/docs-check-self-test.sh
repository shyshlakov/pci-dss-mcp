#!/usr/bin/env bash
# Self-test variant of docs-check.sh. Hardcodes the fixture mapping so the
# production gate (scripts/docs-check.sh) does not need a TOOL_MAP_FILE override.
# Extraction helpers are duplicated rather than sourced to keep the production
# script untouched and side-effect-free.

set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$REPO_ROOT"

FIXTURE_DIR="scripts/testdata/docs-check-fixture"
DOCS_DIR="$FIXTURE_DIR/docs"
SRC_PKG="$FIXTURE_DIR/scanner/dummytool"

# Single fixture mapping; matches dummy_tool.md + dummytool/tool.go.
TOOL_TO_PKG=(
  "dummy_tool=$SRC_PKG"
)

extract_doc_params() {
  local doc="$1"
  grep -oE '`[a-z][a-z0-9_]*`' "$doc" 2>/dev/null \
    | tr -d '`' \
    | grep -E '^[a-z][a-z0-9]*(_[a-z0-9]+)+$' \
    | sort -u
}

extract_doc_errors() {
  local doc="$1"
  grep -oE '`[A-Z][A-Z0-9_]+`' "$doc" 2>/dev/null \
    | tr -d '`' \
    | grep -E '^[A-Z][A-Z0-9_]{2,}$' \
    | sort -u
}

extract_src_params() {
  local src="$1"
  grep -oE 'json:"[a-z_][a-z0-9_,]*"' "$src" 2>/dev/null \
    | sed 's/json:"//;s/,.*$//;s/"$//' \
    | sort -u
}

extract_src_errors() {
  local src="$1"
  grep -oE '"[A-Z][A-Z0-9_]{2,}"' "$src" 2>/dev/null \
    | tr -d '"' \
    | sort -u
}

warn_count=0
exit_code=0

emit_warn() {
  warn_count=$((warn_count + 1))
  echo "$1"
}

for entry in "${TOOL_TO_PKG[@]}"; do
  tool="${entry%%=*}"
  src_pkg="${entry#*=}"
  doc="${DOCS_DIR}/${tool}.md"
  src="${src_pkg}/tool.go"

  if [[ ! -f "$doc" ]]; then
    emit_warn "WARN: missing doc $doc"
    exit_code=1
    continue
  fi
  if [[ ! -f "$src" ]]; then
    emit_warn "WARN: missing src $src"
    exit_code=1
    continue
  fi

  doc_params=$(extract_doc_params "$doc")
  src_params=$(extract_src_params "$src")
  if [[ -n "$doc_params" ]]; then
    drift=$(comm -23 <(echo "$doc_params") <(echo "$src_params") 2>/dev/null || true)
    if [[ -n "$drift" ]]; then
      while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        emit_warn "WARN: $doc mentions param '$p' not found in $src OutputSchema"
      done <<< "$drift"
    fi
  fi

  doc_errs=$(extract_doc_errors "$doc")
  src_errs=$(extract_src_errors "$src")
  if [[ -n "$doc_errs" ]]; then
    drift=$(comm -23 <(echo "$doc_errs") <(echo "$src_errs") 2>/dev/null || true)
    if [[ -n "$drift" ]]; then
      while IFS= read -r e; do
        [[ -z "$e" ]] && continue
        emit_warn "WARN: $doc mentions error token '$e' not found in $src"
      done <<< "$drift"
    fi
  fi
done

exit "$exit_code"
