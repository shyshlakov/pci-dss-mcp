package triagescanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// contextRadius is the number of lines before and after a finding hinted at
// in ResourceLink.StartLine / EndLine. The MCP client uses these as a
// targeted Read window rather than the full file.
const contextRadius = 10

// TriageEngine collects contextual evidence for scanner findings to enable
// AI-assisted triage. It caches parsed files to avoid re-parsing when multiple
// findings reference the same file.
type TriageEngine struct {
	cache           fileCache
	middlewareCache []MiddlewareEvidence // cached middleware discovery results
	routeCache      []MiddlewareEvidence // cached route registration results
	projectScanned  bool                 // true after first discoverMiddleware call
}

// NewTriageEngine creates a TriageEngine with an empty file cache.
func NewTriageEngine() *TriageEngine {
	return &TriageEngine{
		cache: make(fileCache),
	}
}

// Triage processes a set of findings and returns enriched findings with
// contextual evidence for AI-assisted classification.
func (e *TriageEngine) Triage(ctx context.Context, projectPath string, findings []scanner.Finding) (*TriageResult, error) {
	start := time.Now()

	// Fresh cache per triage call.
	e.cache = make(fileCache)
	e.middlewareCache = nil
	e.routeCache = nil
	e.projectScanned = false

	enriched := make([]EnrichedFinding, 0, len(findings))
	triaged := 0

	for _, f := range findings {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// skip verified-OK markers before enrichment. They carry no
		// actionable signal for AI-assisted triage and consume ~4 KB each
		// measured 22 × ~4 KB = 88 KB = 72% of triage wire). Metadata
		// FindingsTotal still reflects the original input count so the
		// client can see the delta. generate_compliance_report output is
		// unchanged — auditors still see the markers per the project conventions
		// "INFO for verified-OK" convention.
		if isVerifiedOKRule(f.RuleID) {
			continue
		}

		absPath := resolveFilePath(projectPath, f.FilePath)
		fctx := e.collectContext(projectPath, f, absPath)
		hint := e.generateHint(f)
		relativizeEvidenceFiles(&fctx, projectPath)

		// strip the legacy inline CodeSnippet and
		// rewrite Finding.FilePath to a project-relative form. The triage
		// response now carries a single ResourceLink in Context.Sources
		// instead, and absolute /var/folders/... paths blow up the payload
		// without adding signal — the MCP client knows the project root.
		stripped := f
		stripped.CodeSnippet = nil
		stripped.FilePath = relativizeProjectPath(stripped.FilePath, projectPath)
		ef := EnrichedFinding{
			Finding: stripped,
			Context: fctx,
			Hint:    hint,
		}
		enriched = append(enriched, ef)

		// Count as triaged if we got any context at all.
		if len(fctx.Sources) > 0 || len(fctx.Imports) > 0 {
			triaged++
		}
	}

	result := &TriageResult{
		Findings: enriched,
		Metadata: TriageMetadata{
			FindingsTotal:   len(findings),
			FindingsTriaged: triaged,
			DurationMS:      time.Since(start).Milliseconds(),
			FilesAnalyzed:   len(e.cache),
		},
	}

	return result, nil
}

// resolveFilePath resolves a finding's file path relative to the project root.
// If the joined path doesn't exist, tries the path as-is (absolute path support).
func resolveFilePath(projectPath, filePath string) string {
	joined := filepath.Join(projectPath, filePath)
	if _, err := os.Stat(joined); err == nil {
		return joined
	}

	// Try as absolute path.
	if filepath.IsAbs(filePath) {
		if _, err := os.Stat(filePath); err == nil {
			return filePath
		}
	}

	// Return joined path even if it doesn't exist — errors handled downstream.
	return joined
}

// collectContext gathers generic context for a finding (source link, imports,
// package declarations, file location) and then dispatches to rule-specific
// collectors based on the finding's RuleID prefix.
//
// instead of embedding 20-30 lines of source per finding inline, we
// now emit a single ResourceLink with a file:// URI and a hinted line
// window. The MCP client reads source on demand via its Read tool. We
// still parse the Go file when needed (for Imports / PackageDecls) but we
// never embed source bytes in the response.
func (e *TriageEngine) collectContext(projectPath string, f scanner.Finding, absPath string) FindingContext {
	ctx := FindingContext{}
	ctx.FileLocation = classifyFileLocation(absPath)
	ctx.Sources = append(ctx.Sources, buildPrimarySourceLink(f, projectPath, absPath))

	// Generic context for all findings.
	ext := strings.ToLower(filepath.Ext(absPath))
	if ext == ".go" {
		pf, err := getParsedGoFile(e.cache, absPath)
		if err != nil {
			slog.Warn("triagescanner: failed to parse file", "path", absPath, "err", err)
		} else {
			ctx.Imports = extractImports(pf.astFile)
			ctx.PackageDecls = extractPackageDecls(pf.astFile, pf.fset)
		}
	}

	// Rule-specific context.
	switch {
	case strings.HasPrefix(f.RuleID, "AUDIT-"):
		collectAuditContext(e, projectPath, f, absPath, &ctx)
	case strings.HasPrefix(f.RuleID, "CSP-") || strings.HasPrefix(f.RuleID, "SRI-") || strings.HasPrefix(f.RuleID, "NONCE-"):
		collectCSPContext(e, projectPath, f, absPath, &ctx)
	case strings.HasPrefix(f.RuleID, "AUTH-MISSING-MFA"):
		collectMFAContext(e, projectPath, f, absPath, &ctx)
	case strings.HasPrefix(f.RuleID, "SECRET-") || strings.HasPrefix(f.RuleID, "CRYPTO-HARDCODED"):
		collectSecretsContext(e, projectPath, f, absPath, &ctx)
	}

	return ctx
}

// generateHint returns a triage hint based on the finding's rule ID.
// Hints help the AI understand what additional context to look for.
func (e *TriageEngine) generateHint(f scanner.Finding) string {
	// Ordered by specificity — more specific prefixes first.
	hints := []struct {
		prefix string
		hint   string
	}{
		{"AUDIT-NO-LOG", "No logging found in handler body -- check if middleware chain includes logging"},
		{"AUDIT-UNSTRUCTURED", "Unstructured logging -- check if structured logger used via middleware"},
		{"CSP-MISSING", "No CSP header set in handler -- check if middleware or reverse proxy sets CSP"},
		{"CSP-UNSAFE-INLINE", "CSP allows unsafe-inline -- check if nonce/hash-based CSP applied via middleware"},
		{"CSP-UNSAFE-EVAL", "CSP allows unsafe-eval -- verify if required by application framework"},
		{"AUTH-MISSING-MFA", "No MFA middleware on route -- check if MFA enforced at infrastructure level"},
		{"CRYPTO-HARDCODED", "Hardcoded crypto key detected -- check if this is a test/example value"},
		{"SECRET-", "Possible secret in config -- check if value comes from environment variable at runtime"},
	}

	for _, h := range hints {
		if strings.HasPrefix(f.RuleID, h.prefix) {
			return h.hint
		}
	}

	return "Review surrounding code and imports for context"
}

// buildPrimarySourceLink returns a ResourceLink pointing at the finding's
// primary source file. The MCP client reads the file on demand via its own
// Read tool; we do NOT embed code in the response. (.)
//
// StartLine/EndLine hint the client at the relevant region (finding.Line ±
// contextRadius) so a targeted Read can pull just the surrounding window
// instead of the full file.
//
// URI is built from the project-root-relative path when possible (keeps the
// payload small and avoids leaking the full host filesystem layout); it
// falls back to the absolute path when the finding lives outside the
// project root. The MCP client resolves relative file:// URIs against the
// project root passed in the tool input.
func buildPrimarySourceLink(f scanner.Finding, projectRoot, absPath string) ResourceLink {
	uriPath := f.FilePath
	if filepath.IsAbs(uriPath) && projectRoot != "" {
		if rel, err := filepath.Rel(projectRoot, uriPath); err == nil && !strings.HasPrefix(rel, "..") {
			uriPath = rel
		}
	}
	start := f.Line - contextRadius
	if start < 1 {
		start = 1
	}
	end := f.Line + contextRadius
	if end < start {
		end = start
	}
	return ResourceLink{
		URI:         "file://" + uriPath,
		Name:        filepath.Base(f.FilePath),
		Description: fmt.Sprintf("%s at line %d", f.RuleID, f.Line),
		MimeType:    mimeTypeForPath(f.FilePath),
		StartLine:   start,
		EndLine:     end,
	}
}

// relativizeProjectPath rewrites an absolute path to a project-root-relative
// form when possible. Falls back to the input string when the path lives
// outside the project root or projectRoot is empty.
func relativizeProjectPath(path, projectRoot string) string {
	if path == "" || projectRoot == "" || !filepath.IsAbs(path) {
		return path
	}
	rel, err := filepath.Rel(projectRoot, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return rel
}

// relativizeEvidenceFiles normalizes EvidenceFiles entries from absolute
// "/abs/path:line" form to "rel/path:line" using the project root. Tmp-dir
// scan paths bloat the payload by ~150 bytes per entry without adding
// signal — the client knows the project root.
func relativizeEvidenceFiles(ctx *FindingContext, projectRoot string) {
	if ctx == nil || projectRoot == "" {
		return
	}
	for i, entry := range ctx.EvidenceFiles {
		path, suffix := splitFileLineSuffix(entry)
		rel := relativizeProjectPath(path, projectRoot)
		if rel == path {
			continue
		}
		ctx.EvidenceFiles[i] = rel + suffix
	}
}

// splitFileLineSuffix splits "/abs/path.go:42" into ("/abs/path.go", ":42").
// If the entry has no trailing:line suffix, returns the whole string and "".
func splitFileLineSuffix(entry string) (string, string) {
	idx := strings.LastIndex(entry, ":")
	if idx == -1 {
		return entry, ""
	}
	tail := entry[idx+1:]
	for _, c := range tail {
		if c < '0' || c > '9' {
			return entry, ""
		}
	}
	if tail == "" {
		return entry, ""
	}
	return entry[:idx], entry[idx:]
}

// isVerifiedOKRule returns true for scanner RuleIDs that are "verified-OK"
// markers — findings the scanner emits to show QSA auditors that a check
// ran and passed, not actual violations. Per the scanner design convention
// these are emitted at INFO severity to preserve audit visibility in
// generate_compliance_report. They carry no actionable signal for
// AI-assisted triage, so the triage engine skips them before context
// enrichment to keep the MCP response small.
//
// Current verified-OK rules: AUDIT-LOG-OK, CSP-OK. Future scanners that
// follow the same "-OK" suffix convention will automatically inherit
// this skip without requiring this function to change.
func isVerifiedOKRule(ruleID string) bool {
	return ruleID != "" && strings.HasSuffix(ruleID, "-OK")
}

// mimeTypeForPath maps common extensions to MIME types. Falls back to
// text/plain for unknown extensions. Kept tiny and local — no new dep.
func mimeTypeForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "text/x-go"
	case ".html", ".htm":
		return "text/html"
	case ".yaml", ".yml":
		return "text/yaml"
	case ".toml":
		return "text/toml"
	case ".json":
		return "application/json"
	case ".env":
		return "text/plain"
	default:
		return "text/plain"
	}
}
