package reportscanner

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const (
	autoCapThreshold = 500
	flatPageSize     = 24
	topPerSeverity   = 10
)

const (
	hintSummaryFollowUp = "Call again with cursor to page through full findings, or use min_severity/rule_filter to narrow"
	hintFlatNextPage    = "Call again with next_cursor to page, or use min_severity/rule_filter to narrow"
	hintFlatEndOfList   = "End of results"
	hintAutoCap         = "Response auto-capped at 500 findings. Pass limit=<N> for explicit size or use cursor pagination."
	hintCursorMalformed = "Cursor token is corrupted. Re-run without cursor to start a fresh scan."
	hintCursorExpired   = "Session cache expired or server restarted. Re-run without cursor to start a fresh scan."
)

func newCursorMalformed() *CursorExpiredError {
	return &CursorExpiredError{
		ResponseShape: "error",
		Error:         "cursor_malformed",
		Code:          "CURSOR_MALFORMED",
		Hint:          hintCursorMalformed,
	}
}

func newCursorExpired() *CursorExpiredError {
	return &CursorExpiredError{
		ResponseShape: "error",
		Error:         "cursor_expired",
		Code:          "CURSOR_EXPIRED",
		Hint:          hintCursorExpired,
	}
}

func SelectAndExecute(ctx context.Context, gen *ReportGenerator, input ReportInput, toolName string) (*SummaryResponse, *FlatResponse, *CursorExpiredError, error) {
	if input.Cursor != "" {
		payload, err := decodeCursor(input.Cursor)
		if err != nil {
			return nil, nil, newCursorMalformed(), nil
		}
		if payload.Tool != "" && payload.Tool != toolName {
			return nil, nil, newCursorMalformed(), nil
		}
		entry, ok := getSession(payload.SID)
		if !ok {
			return nil, nil, newCursorExpired(), nil
		}
		flat := buildFlatPage(entry, payload.Off, flatPageSize, payload.SID, toolName)
		return nil, flat, nil, nil
	}

	path := input.Path
	if path == "" {
		path = "."
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		absPath = path
	}
	scanTS := time.Now().UTC().Format(time.RFC3339)
	includeTaint := true
	if input.IncludeTaint != nil {
		includeTaint = *input.IncludeTaint
	}

	report, err := gen.GenerateWithOptions(ctx, path, input.DepScanMode, input.IncludeTests, includeTaint)
	if err != nil {
		return nil, nil, nil, err
	}

	if input.Limit == -1 {
		return nil, buildAutoCapFlat(report), nil, nil
	}

	if input.Limit > 0 || input.MinSeverity != "" || input.RuleFilter != "" {
		raw := make([]scanner.Finding, 0, len(report.Findings))
		for _, rf := range report.Findings {
			raw = append(raw, rf.Finding)
		}
		filtered, ferr := FilterFindings(raw, input.MinSeverity, input.RuleFilter, 0)
		if ferr != nil {
			return nil, nil, nil, ferr
		}
		kept := make(map[string]bool, len(filtered))
		for _, f := range filtered {
			kept[f.RuleID+"#"+f.FilePath+"#"+strconv.Itoa(f.Line)] = true
		}
		projected := make([]ReportFinding, 0, len(filtered))
		for _, rf := range report.Findings {
			key := rf.RuleID + "#" + rf.FilePath + "#" + strconv.Itoa(rf.Line)
			if kept[key] {
				projected = append(projected, rf)
			}
		}

		filteredSummary := recomputeSeveritySummary(report.Summary, projected)
		fh := filterHash(input.MinSeverity, input.RuleFilter, input.IncludeTests)
		sid := sessionKey(absPath, scanTS, fh, includeTaint)
		cached := make([]ReportFinding, len(projected))
		copy(cached, projected)
		entry := &cacheEntry{
			findings:   cached,
			scanMeta:   report.Metadata,
			summary:    filteredSummary,
			reqStatus:  report.RequirementStatus,
			filterHash: fh,
		}
		putSession(sid, entry)

		pageSize := flatPageSize
		if input.Limit > 0 {
			pageSize = input.Limit
		}
		flat := buildFlatPage(entry, 0, pageSize, sid, toolName)
		return nil, flat, nil, nil
	}

	fh := filterHash("", "", input.IncludeTests)
	sid := sessionKey(absPath, scanTS, fh, includeTaint)
	cached := make([]ReportFinding, len(report.Findings))
	copy(cached, report.Findings)
	entry := &cacheEntry{
		findings:   cached,
		scanMeta:   report.Metadata,
		summary:    report.Summary,
		reqStatus:  report.RequirementStatus,
		filterHash: fh,
	}
	putSession(sid, entry)
	return buildSummary(report, sid, toolName), nil, nil, nil
}

func recomputeSeveritySummary(base ReportSummary, findings []ReportFinding) ReportSummary {
	out := base
	out.Critical = 0
	out.High = 0
	out.Medium = 0
	out.Low = 0
	out.Info = 0
	for _, rf := range findings {
		switch rf.Severity {
		case scanner.SeverityCritical:
			out.Critical++
		case scanner.SeverityHigh:
			out.High++
		case scanner.SeverityMedium:
			out.Medium++
		case scanner.SeverityLow:
			out.Low++
		case scanner.SeverityInfo:
			out.Info++
		}
	}
	return out
}

func buildSummary(report *ComplianceReport, sid, toolName string) *SummaryResponse {
	top := map[string][]ReportFinding{
		"critical": stripSummaryFindings(pickTopN(report.Findings, scanner.SeverityCritical, topPerSeverity)),
		"high":     stripSummaryFindings(pickTopN(report.Findings, scanner.SeverityHigh, topPerSeverity)),
		"medium":   stripSummaryFindings(pickTopN(report.Findings, scanner.SeverityMedium, topPerSeverity)),
	}
	remain := map[string]int{
		"critical": max0(report.Summary.Critical - len(top["critical"])),
		"high":     max0(report.Summary.High - len(top["high"])),
		"medium":   max0(report.Summary.Medium - len(top["medium"])),
	}
	// Layer B budget: strip NOT_CHECKED entries from requirement_statuses —
	// those are static PCI DSS spec and blow the 25 KB wire budget on the
	// default unfiltered summary. Auditors still see PASS/FAIL/SUPPRESSED
	// for every checked requirement. NOT_CHECKED items live in the flat
	// view or the full fixture test and remain discoverable.
	checkedStatuses := make(map[string]RequirementStatus, len(report.RequirementStatus))
	for id, rs := range report.RequirementStatus {
		if rs.Status != "NOT_CHECKED" {
			checkedStatuses[id] = rs
		}
	}
	next, err := encodeCursor(cursorPayload{SID: sid, Off: 0, Tool: toolName})
	if err != nil {
		slog.Warn("encodeCursor failed", "err", err, "sid", sid, "off", 0, "tool", toolName)
	}
	return &SummaryResponse{
		ResponseShape:       "summary",
		Metadata:            report.Metadata,
		Summary:             report.Summary,
		RequirementStatuses: checkedStatuses,
		TopFindings:         top,
		Pagination: PaginationInfo{
			TotalFindings:        len(report.Findings),
			Returned:             len(top["critical"]) + len(top["high"]) + len(top["medium"]),
			RemainingPerSeverity: remain,
			NextCursor:           next,
			Hint:                 hintSummaryFollowUp,
			AutoCapped:           false,
		},
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func buildFlatPage(entry *cacheEntry, off, pageSize int, sid, toolName string) *FlatResponse {
	total := len(entry.findings)
	if off >= total {
		return &FlatResponse{
			ResponseShape: "flat",
			Metadata:      entry.scanMeta,
			Summary:       entry.summary,
			Findings:      []ReportFinding{},
			Pagination: PaginationInfo{
				TotalFindings: total,
				Returned:      0,
				Hint:          hintFlatEndOfList,
				AutoCapped:    false,
			},
		}
	}
	end := off + pageSize
	if end > total {
		end = total
	}
	page := entry.findings[off:end]
	var next string
	hint := hintFlatEndOfList
	if end < total {
		encoded, err := encodeCursor(cursorPayload{SID: sid, Off: end, Tool: toolName})
		if err != nil {
			slog.Warn("encodeCursor failed", "err", err, "sid", sid, "off", end, "tool", toolName)
		} else {
			next = encoded
		}
		hint = hintFlatNextPage
	}
	return &FlatResponse{
		ResponseShape: "flat",
		Metadata:      entry.scanMeta,
		Summary:       entry.summary,
		Findings:      page,
		Pagination: PaginationInfo{
			TotalFindings: total,
			Returned:      len(page),
			NextCursor:    next,
			Hint:          hint,
			AutoCapped:    false,
		},
	}
}

func buildAutoCapFlat(report *ComplianceReport) *FlatResponse {
	total := len(report.Findings)
	if total <= autoCapThreshold {
		return &FlatResponse{
			ResponseShape: "flat",
			Metadata:      report.Metadata,
			Summary:       report.Summary,
			Findings:      report.Findings,
			Pagination: PaginationInfo{
				TotalFindings: total,
				Returned:      total,
				AutoCapped:    false,
			},
		}
	}
	kept := report.Findings[:autoCapThreshold]
	return &FlatResponse{
		ResponseShape: "flat",
		Metadata:      report.Metadata,
		Summary:       report.Summary,
		Findings:      kept,
		Pagination: PaginationInfo{
			TotalFindings:  total,
			Returned:       len(kept),
			AutoCapped:     true,
			TotalBeforeCap: total,
			Kept:           len(kept),
			Hint:           hintAutoCap,
		},
	}
}

// stripSummaryFindings returns slimmer copies of the top findings for the
// Layer B wire budget. Summary clients drill down via cursor to get the full
// finding; the top panel only needs enough context for an AI to pick which
// severity to page through.
func stripSummaryFindings(findings []ReportFinding) []ReportFinding {
	out := make([]ReportFinding, len(findings))
	for i, rf := range findings {
		stripped := ReportFinding{
			Finding: scanner.Finding{
				RuleID:        rf.RuleID,
				Severity:      rf.Severity,
				RequirementID: rf.RequirementID,
				FilePath:      rf.FilePath,
				Line:          rf.Line,
				Description:   rf.Description,
			},
			RequirementTitle: rf.RequirementTitle,
			ScannerName:      rf.ScannerName,
		}
		out[i] = stripped
	}
	return out
}

func pickTopN(findings []ReportFinding, sev scanner.Severity, n int) []ReportFinding {
	out := make([]ReportFinding, 0, n)
	for _, f := range findings {
		if f.Severity != sev {
			continue
		}
		out = append(out, f)
		if len(out) >= n {
			break
		}
	}
	return out
}
