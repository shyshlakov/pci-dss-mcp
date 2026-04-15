// Package panscanner taint_bridge.go
//
// This file owns the integration between PAN-KEYWORD / PAN-TYPE findings and
// the type-aware data-flow engine in internal/taint. It applies the
// severity rule table:
//
//	┌──────────────────────────┬─────────────────────┬─────────────────────┐
//	│ Flow                     │ PAN-KEYWORD (3.3.1) │ PAN-TYPE (3.5.1)    │
//	├──────────────────────────┼─────────────────────┼─────────────────────┤
//	│ Flows to DB (stored)     │ keep + annotate     │ keep                │
//	│ Transit only (no DB)     │ downgrade to INFO   │ SUPPRESS entirely   │
//	│ Inconclusive             │ keep                │ keep                │
//	└──────────────────────────┴─────────────────────┴─────────────────────┘
//
// "Inconclusive" covers two cases: (a) the taint engine is unavailable
// (graceful degradation — nil engine, no go binary, typecheck errors)
// and (b) FlowsTo returned false AND the struct tag heuristic returned
// inconclusive AND the negative evidence heuristic did not fire AND the file
// path does not match any transit-shape marker.
//
// A struct tag heuristic is the PRIMARY guard:
//   - json tags without gorm/db/bun/sql → transit API model → downgrade
//   - gorm/db/bun/sql tags present → storage model → keep severity
//   - no tags → inconclusive → negative evidence → path markers
//
// A "negative evidence" step sits between the
// struct tag heuristic and the isTransitShape fallback. When the struct tag
// heuristic returns inconclusive AND the taint engine reports no DB flow AND
// the field name is a known SAD keyword (CVV/CVC/CVC2/CVV2/SecurityCode),
// the bridge treats the field as high-confidence transit and applies the
// same downgrade/suppress rules as tagClassTransit. PAN-like field names
// (Number, PrimaryAccountNumber, AccountNumber, CardNumber) are deliberately
// excluded because PAN CAN be legitimately stored under PCI DSS 3.5.1.
//
// This replaces the path-based isTransitShape as the first check. isTransitShape
// is preserved as a fallback for structs without any tags AND without a
// SAD-matching field name.
//
// PAN-TYPE suppression for transit fields rests on the PCI SSC FAQ on
// non-persistent memory: "If account data is present in non-persistent
// memory (e.g. RAM), encryption of account data is not required." A Go
// `string` in a short-lived HTTP request handler is non-persistent memory,
// so PCI DSS 3.5.1 does not apply.
//
// ERR-LEAK / PAN-LOGGER taint upgrades are deferred. The bridge ships
// SinkHTTPResponse / SinkLoggerCall / SinkCryptoCall as empty libraries;
// FlowsTo against those kinds returns false. The deferred contract is locked
// by TestDeferredSinks_PANScanner in taint_bridge_test.go.
package panscanner

import (
	"context"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// suppressedSentinel is a synthetic RuleID written by adjustSeverityByTaint
// when a PAN-TYPE finding is suppressed. removeSuppressed strips
// every entry with this RuleID before the bridge returns. Sentinel approach
// keeps the index→source map consistent during the rewrite loop and avoids
// the gymnastics of mutating the slice in place.
const suppressedSentinel = "__SUPPRESSED__"

// taintAnnotationDB is appended to PAN-KEYWORD descriptions when the engine
// confirms a flow to a SinkDBStore target. Used by tests to verify the
// stored-CHD branch fired.
const taintAnnotationDB = " (taint: field flows to DB storage sink)"

// taintAnnotationTransit is appended to PAN-KEYWORD descriptions when a
// finding is downgraded to INFO under row 2. References the PCI SSC
// FAQ verbatim so the audit trail explains the downgrade.
const taintAnnotationTransit = " (taint: transit-only, non-persistent memory per PCI SSC FAQ)"

// sadFieldNames enumerates struct field names that represent Sensitive
// Authentication Data (CVV/CVC/CVC2/CVV2/SecurityCode). Per PCI DSS 3.3.1, SAD
// MUST be deleted after authorization — it is never legitimately persisted by
// a compliant payment service. When the taint engine confirms no DB flow AND
// the enclosing struct has no DB tags (tagClassInconclusive), a SAD field name
// provides strong negative evidence that this is a transit-only model, and the
// finding can be safely downgraded.
//
// IMPORTANT: PAN field names (Number, PrimaryAccountNumber, AccountNumber,
// CardNumber) are deliberately EXCLUDED from this set. PAN CAN be legitimately
// stored under PCI DSS 3.5.1 (with encryption/tokenisation), so "no DB flow
// found" is substantially weaker evidence for PAN than for SAD. Keeping PAN
// out of the set prevents false negatives where a stored PAN field with no
// visible ORM tags (interface dispatch, reflection, dynamic SQL) is
// incorrectly downgraded.
//
// Both PascalCase and camelCase variants are included — Go code conventions
// normally give PascalCase exported fields, but lowercase unexported fields
// (e.g. `cvv string`) occur in internal helper structs that still carry SAD.
var sadFieldNames = map[string]bool{
	"CVV":          true,
	"CVC":          true,
	"CVC2":         true,
	"CVV2":         true,
	"SecurityCode": true,
	"Cvv":          true,
	"Cvc":          true,
	"Cvc2":         true,
	"Cvv2":         true,
	"cvv":          true,
	"cvc":          true,
	"cvc2":         true,
	"cvv2":         true,
	"securityCode": true,
}

// negativeEvidenceTransit returns true when there is strong negative evidence
// that a field is transit-only, even though structTagClassification returned
// inconclusive. This fires ONLY for SAD field names (CVV/CVC/CVC2/SecurityCode)
// in structs that have no DB tags — i.e. pure domain models where the taint
// engine's FlowsTo(SinkDBStore) already returned false.
//
// Rationale (Option B): SAD is explicitly prohibited from
// post-authorization storage by PCI DSS 3.3.1. A struct field named "CVV" that
// doesn't flow to any DB sink is, with very high probability, a transit field
// used to pass the value to an external payment API. The heuristic is narrow
// by design — only SAD gets the downgrade, PAN stays at its current severity
// for conservative false-negative avoidance.
//
// Callers MUST only invoke this after structTagClassification has returned
// tagClassInconclusive. Using it on a tagClassStorage result would be incorrect
// — the HasDBTag check below is a belt-and-braces guard for that misuse.
func negativeEvidenceTransit(src taint.Source) bool {
	if src.HasDBTag {
		// Storage model — the struct has DB tags, so this code path should
		// not have been reached via tagClassInconclusive. Refuse to downgrade.
		return false
	}
	if src.Field == "" {
		return false
	}
	return sadFieldNames[src.Field]
}

// tagClass represents the result of the struct tag heuristic.
// It classifies a struct as transit (API model), storage (DB model), or
// inconclusive (no tags / unknown).
type tagClass int

const (
	// tagClassTransit: struct has json tags but no gorm/db/bun/sql tags.
	// High confidence API/transit model — downgrade regardless of file path.
	tagClassTransit tagClass = iota
	// tagClassStorage: struct has at least one gorm/db/bun/sql tag.
	// DB model — keep severity even when FlowsTo returns false.
	tagClassStorage
	// tagClassInconclusive: struct has no tags or unknown tag combination.
	// Falls back to isTransitShape path-based detection.
	tagClassInconclusive
)

// structTagClassification inspects the HasJSONTag and HasDBTag metadata on a
// taint.Source to classify the enclosing struct as transit, storage, or
// inconclusive. This is the primary guard in the decision tree
// replacing path-based isTransitShape as the first check.
//
// Classification rules:
// - HasDBTag=true -> storage (DB tags take precedence, even if json tags present)
// - HasJSONTag=true && HasDBTag=false -> transit (API/DTO model)
// - Neither tag present -> inconclusive (fall through to path markers)
func structTagClassification(src taint.Source) tagClass {
	if src.HasDBTag {
		return tagClassStorage
	}
	if src.HasJSONTag {
		return tagClassTransit
	}
	return tagClassInconclusive
}

// adjustSeverityByTaint applies severity rules to PAN-KEYWORD and
// PAN-TYPE findings using the type-aware taint engine. Called from
// ScanFullWithTaint only when includeTaint=true and at least one resolvable
// field source was collected during the AST walk.
//
// Behavior summary:
// - engine nil → return findings unchanged
// - finding RuleID not in {PAN-KEYWORD, PAN-TYPE} → pass through
// - no Source in fieldSources for this index → pass through (literal /
// logger / parameter findings)
// - Source.Package or.TypeName or.Field empty → pass through (cannot
// query the engine without a fully resolved source)
// - FlowsTo(SinkDBStore) = true → keep severity, set Confidence=high,
// append taintAnnotationDB to Description (row 1)
// - FlowsTo(SinkDBStore) = false → apply two-level guard:
// 1. structTagClassification(src) = tagClassTransit (json tags, no DB tags) →
// PAN-KEYWORD: downgrade to INFO + Confidence=high + transit annotation;
// PAN-TYPE: rewrite RuleID to suppressedSentinel (row 2)
// 2. structTagClassification(src) = tagClassStorage (gorm/db/bun/sql tags) →
// keep severity (DB model, err on side of caution)
// 3. structTagClassification(src) = tagClassInconclusive (no tags) →
// fall back to isTransitShape(finding) path-based guard (behavior)
//
// After the rewrite loop, removeSuppressed filters out the sentinel entries
// and returns the cleaned slice. The bridge never mutates FilePath, Line,
// Column, RequirementID, Suggestion, or RelatedRequirements — only Severity,
// Confidence, Description, and (in the suppression path) RuleID.
func adjustSeverityByTaint(ctx context.Context, projectRoot string, findings []scanner.Finding, fieldSources map[int]taint.Source) []scanner.Finding {
	engine := taint.GetOrInit(ctx, projectRoot)
	if engine == nil {
		// graceful degradation: pass through unchanged.
		return findings
	}

	for i := range findings {
		ruleID := findings[i].RuleID
		if ruleID != "PAN-KEYWORD" && ruleID != "PAN-TYPE" {
			continue
		}
		src, ok := fieldSources[i]
		if !ok {
			// Literal-match, logger, parameter findings have no Source.
			continue
		}
		if src.Package == "" || src.TypeName == "" || src.Field == "" {
			// Incomplete source — typically the file lives outside any
			// resolvable Go module. Cannot query the engine, so row 3.
			continue
		}

		flowsToDB := engine.FlowsTo(src, taint.SinkPattern{Kind: taint.SinkDBStore})
		if flowsToDB {
			// row 1: stored CHD. Keep current severity and annotate.
			findings[i].Confidence = "high"
			findings[i].Description += taintAnnotationDB
			continue
		}

		// FlowsTo returned false. Apply the two-level guard:
		// 1. Struct tag heuristic (primary) — json-only = transit, gorm/db = storage
		// 2. isTransitShape path markers (fallback) — only when tags inconclusive
		cls := structTagClassification(src)
		switch cls {
		case tagClassTransit:
			// struct has json tags, no DB tags → API model. High confidence
			// transit — downgrade regardless of file path. This covers structs in
			// /pkg/visa/, /pkg/mastercard/, /internal/service/.../model/ that the
			// old 13-marker isTransitShape would miss.
			switch ruleID {
			case "PAN-KEYWORD":
				findings[i].Severity = scanner.SeverityInfo
				findings[i].Confidence = "high"
				findings[i].Description += taintAnnotationTransit
			case "PAN-TYPE":
				findings[i].RuleID = suppressedSentinel
			}
		case tagClassStorage:
			// Struct is a DB model (has gorm/db/bun/sql tags) — keep severity
			// even when FlowsTo=false. The taint engine may have missed the DB
			// sink (interface dispatch, incomplete sink library), so we err on
			// the side of caution and treat it as potentially stored CHD.
			continue
		case tagClassInconclusive:
			// No tag metadata available. Two-step decision:
			// 1. Option B — negative evidence heuristic:
			// if the field name is a known SAD keyword (CVV/CVC/etc.)
			// and the struct has no DB tags, treat it as high-confidence
			// transit regardless of file path.
			// 2. belt-and-braces — fall back to isTransitShape
			// path markers for all other inconclusive fields.
			if negativeEvidenceTransit(src) {
				// SAD field (CVV/CVC/SecurityCode) in a tagless domain
				// model with no confirmed DB flow → virtually certainly
				// transit. Apply the same downgrade/suppress as tagClassTransit.
				switch ruleID {
				case "PAN-KEYWORD":
					findings[i].Severity = scanner.SeverityInfo
					findings[i].Confidence = "high"
					findings[i].Description += taintAnnotationTransit
				case "PAN-TYPE":
					findings[i].RuleID = suppressedSentinel
				}
				continue
			}
			if !isTransitShape(findings[i]) {
				// row 3: inconclusive. Keep severity, no annotation.
				continue
			}
			switch ruleID {
			case "PAN-KEYWORD":
				// row 2 PAN-KEYWORD column: transit-only → INFO.
				findings[i].Severity = scanner.SeverityInfo
				findings[i].Confidence = "high"
				findings[i].Description += taintAnnotationTransit
			case "PAN-TYPE":
				// row 2 PAN-TYPE column: transit-only → suppress
				// entirely. PCI SSC FAQ: non-persistent memory does not require
				// 3.5.1 string-vs-[]byte enforcement.
				findings[i].RuleID = suppressedSentinel
			}
		}
	}

	return removeSuppressed(findings)
}

// isTransitShape returns true when the finding's file path indicates a
// transit-only context — request/response DTOs, API client models, HTTP
// handler payloads. The match is case-insensitive substring against a list
// of well-known directory markers used in Go payment-service codebases.
//
// this function is now the FALLBACK guard, used only when the
// struct tag heuristic returns tagClassInconclusive (no json/gorm/db/bun/sql
// tags on the struct). The struct tag heuristic (structTagClassification) is
// the primary guard. A new directory marker is the cheapest way to opt
// codebases with tagless structs into the downgrade rule.
func isTransitShape(f scanner.Finding) bool {
	path := strings.ToLower(filepathToSlash(f.FilePath))
	markers := []string{
		"/requests/",
		"/request/",
		"/responses/",
		"/response/",
		"/dto/",
		"/dtos/",
		"/api/",
		"/client/",
		"/clients/",
		"/models/requests/",
		"/models/responses/",
		"/handler/",
		"/handlers/",
	}
	for _, m := range markers {
		if strings.Contains(path, m) {
			return true
		}
	}
	return false
}

// removeSuppressed filters out findings whose RuleID is the suppressed
// sentinel written by adjustSeverityByTaint. Allocates a fresh
// slice rather than reusing the backing array because the input may still be
// referenced by ScanFullWithTaint's metadata bookkeeping.
func removeSuppressed(findings []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == suppressedSentinel {
			continue
		}
		out = append(out, f)
	}
	return out
}

// filepathToSlash normalises Windows-style backslashes to forward slashes
// before substring matching. Matches Go's filepath.ToSlash behavior without
// pulling another import into the bridge.
func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
