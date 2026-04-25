#!/usr/bin/env bash
# Advisory drift gate: docs/<tool>.md vs scanner/<scanner>/tool.go OutputSchema
# and error tokens. Per Phase 20.3 D-10 / D-11 / D-13. Advisory tier: prints
# WARN lines, exits non-zero only if a doc or source file is missing.

set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$REPO_ROOT"

# tool=pkg pairs. Avoids `declare -A` because macOS ships bash 3.2 which has
# no associative arrays (CI runs ubuntu bash 5+ where it would work, but the
# gate must run for every local dev too).
#
# update_vulnerability_db shares scanner/depscanner/tool.go with check_dependencies
# and is documented inside docs/check_dependencies.md (Plan 04 D-15 / Claude's
# Discretion). The gate therefore does NOT include a standalone update_vulnerability_db
# entry; its tokens are implicitly covered by the check_dependencies entry.
TOOL_TO_PKG=(
  "scan_pan_data=scanner/panscanner"
  "check_encryption=scanner/cryptoscanner"
  "check_tls_config=scanner/tlsscanner"
  "check_secrets_in_configs=scanner/secretscanner"
  "check_error_handling=scanner/errorscanner"
  "check_auth_strength=scanner/authscanner"
  "audit_log_coverage=scanner/auditscanner"
  "check_data_retention=scanner/retentionscanner"
  "check_payment_page_scripts=scanner/scriptscanner"
  "check_dependencies=scanner/depscanner"
  "generate_compliance_report=scanner/reportscanner"
  "triage_findings=scanner/triagescanner"
  "explain_requirement=pcidb"
  "generate_sbom=scanner/sbomscanner"
)

DOCS_DIR="${DOCS_DIR:-docs}"
exit_code=0
warn_count=0

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

if [[ "$warn_count" -gt 0 ]]; then
  echo
  echo "docs-check: $warn_count WARN line(s); advisory tier (exit 0 unless missing files)."
fi

exit "$exit_code"
