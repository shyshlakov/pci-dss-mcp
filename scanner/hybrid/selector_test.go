package hybrid

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

type fakeFinding struct {
	ID  string
	Sev string
}

type fakeSummary struct {
	Total  int
	Cursor string
}

type fakeFlat struct {
	Page        []fakeFinding
	Total       int
	AutoCapped  bool
	Off         int
	Cursor      string
	AllFindings []fakeFinding
	Histogram   *hybridcache.Histogram
}

type memCache struct {
	mu             sync.Mutex
	m              map[string]memEntry
	histogramCalls int
}

type memEntry struct {
	findings []fakeFinding
	meta     hybridcache.ScanMeta
	hist     *hybridcache.Histogram
}

func newMemCache() *memCache { return &memCache{m: map[string]memEntry{}} }

func (c *memCache) Put(sid string, findings []fakeFinding, meta hybridcache.ScanMeta) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]fakeFinding, len(findings))
	copy(cp, findings)
	c.m[sid] = memEntry{findings: cp, meta: meta}
}

func (c *memCache) Get(sid string) ([]fakeFinding, hybridcache.ScanMeta, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[sid]
	if !ok {
		return nil, hybridcache.ScanMeta{}, false
	}
	return e.findings, e.meta, true
}

func (c *memCache) PutWithHistogram(sid string, findings []fakeFinding, meta hybridcache.ScanMeta, hist *hybridcache.Histogram) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]fakeFinding, len(findings))
	copy(cp, findings)
	c.m[sid] = memEntry{findings: cp, meta: meta, hist: hist}
}

func (c *memCache) GetWithHistogram(sid string) ([]fakeFinding, hybridcache.ScanMeta, *hybridcache.Histogram, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[sid]
	if !ok {
		return nil, hybridcache.ScanMeta{}, nil, false
	}
	return e.findings, e.meta, e.hist, true
}

func (c *memCache) Histogram(findings []fakeFinding) *hybridcache.Histogram {
	c.mu.Lock()
	c.histogramCalls++
	c.mu.Unlock()
	bySev := scanner.SeverityStats{}
	ruleCounts := map[string]int{}
	for _, f := range findings {
		ruleCounts[f.ID]++
		switch f.Sev {
		case "CRITICAL":
			bySev.Critical++
		case "HIGH":
			bySev.High++
		case "MEDIUM":
			bySev.Medium++
		case "LOW":
			bySev.Low++
		case "INFO":
			bySev.Info++
		}
	}
	byRule := make([]scanner.RuleCount, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		byRule = append(byRule, scanner.RuleCount{RuleID: r, Count: c})
	}
	sortRuleCountsStable(byRule)
	h := hybridcache.Histogram{BySeverity: bySev, ByRule: byRule}
	return &h
}

func sortRuleCountsStable(rc []scanner.RuleCount) {
	sort.SliceStable(rc, func(i, j int) bool {
		if rc[i].Count != rc[j].Count {
			return rc[i].Count > rc[j].Count
		}
		return rc[i].RuleID < rc[j].RuleID
	})
}

func newFakeScan(findings []fakeFinding, err error) Scan[fakeFinding] {
	return func(ctx context.Context, in Input) ([]fakeFinding, hybridcache.ScanMeta, error) {
		if err != nil {
			return nil, hybridcache.ScanMeta{}, err
		}
		return findings, hybridcache.ScanMeta{TotalFiles: 1, TotalLines: len(findings)}, nil
	}
}

func noopFilter(findings []fakeFinding, minSev, ruleFilter string) ([]fakeFinding, error) {
	if minSev == "__bad__" {
		return nil, errors.New("filter boom")
	}
	out := make([]fakeFinding, 0, len(findings))
	for _, f := range findings {
		if minSev != "" && f.Sev != minSev {
			continue
		}
		if ruleFilter != "" && !strings.Contains(f.ID, ruleFilter) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func buildSummaryFake(findings []fakeFinding, meta hybridcache.ScanMeta, sid, nextCursor string) *fakeSummary {
	return &fakeSummary{Total: len(findings), Cursor: nextCursor}
}

func buildFlatFake(findings []fakeFinding, allFindings []fakeFinding, hist *hybridcache.Histogram, off, pageSize, total int, meta hybridcache.ScanMeta, sid, nextCursor string, autoCapped bool) *fakeFlat {
	return &fakeFlat{Page: findings, Total: total, AutoCapped: autoCapped, Off: off, Cursor: nextCursor, AllFindings: allFindings, Histogram: hist}
}

func mkFindings(n int) []fakeFinding {
	out := make([]fakeFinding, n)
	for i := range out {
		out[i] = fakeFinding{ID: "R-" + strconv.Itoa(i), Sev: severityRotation(i)}
	}
	return out
}

func severityRotation(i int) string {
	switch i % 5 {
	case 0:
		return "CRITICAL"
	case 1:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 3:
		return "LOW"
	default:
		return "INFO"
	}
}

func TestSelectAndExecute_Default(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(30)
	cache := newMemCache()
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{AbsPath: "/tmp/x", ToolName: "triage_findings", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Summary == nil {
		t.Fatalf("expected Summary, got %+v", res)
	}
	if res.Flat != nil || res.Err != nil {
		t.Fatalf("expected only Summary set; got Flat=%v Err=%v", res.Flat, res.Err)
	}
	if res.Summary.Total != 30 {
		t.Errorf("Total=%d want 30", res.Summary.Total)
	}
	if res.Summary.Cursor == "" {
		t.Errorf("expected non-empty cursor on Layer B")
	}
}

func TestSelectAndExecute_Cursor_Resume(t *testing.T) {
	ctx := context.Background()
	cache := newMemCache()
	findings := mkFindings(90)
	cache.Put("sid-abc", findings, hybridcache.ScanMeta{})
	cur, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: "sid-abc", Off: 60, Tool: "triage_findings"})
	if err != nil {
		t.Fatalf("EncodeCursor: %v", err)
	}
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Cursor: cur, ToolName: "triage_findings"},
		newFakeScan(nil, errors.New("scan must not be called")),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil || res.Summary != nil || res.Err != nil {
		t.Fatalf("expected only Flat set; got %+v", res)
	}
	if res.Flat.Total != 90 || res.Flat.Off != 60 || len(res.Flat.Page) != 30 {
		t.Errorf("Flat=%+v, want total=90 off=60 page=30", res.Flat)
	}
	if res.Flat.Cursor != "" {
		t.Errorf("expected empty next_cursor on last page, got %q", res.Flat.Cursor)
	}
}

func TestSelectAndExecute_Cursor_Malformed(t *testing.T) {
	ctx := context.Background()
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Cursor: "!!!not-base64!!!", ToolName: "triage_findings"},
		newFakeScan(nil, errors.New("scan must not be called")),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Err == nil || res.Err.Code != "CURSOR_MALFORMED" {
		t.Fatalf("expected CURSOR_MALFORMED, got %+v", res)
	}
}

func TestSelectAndExecute_Cursor_ToolMismatch(t *testing.T) {
	ctx := context.Background()
	cur, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: "sid-x", Off: 0, Tool: "other_tool"})
	if err != nil {
		t.Fatalf("EncodeCursor: %v", err)
	}
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Cursor: cur, ToolName: "triage_findings"},
		newFakeScan(nil, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Err == nil || res.Err.Code != "CURSOR_MALFORMED" {
		t.Fatalf("expected CURSOR_MALFORMED, got %+v", res)
	}
}

func TestSelectAndExecute_Cursor_Expired(t *testing.T) {
	ctx := context.Background()
	cur, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: "sid-gone", Off: 0, Tool: "triage_findings"})
	if err != nil {
		t.Fatalf("EncodeCursor: %v", err)
	}
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Cursor: cur, ToolName: "triage_findings"},
		newFakeScan(nil, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Err == nil || res.Err.Code != "CURSOR_EXPIRED" {
		t.Fatalf("expected CURSOR_EXPIRED, got %+v", res)
	}
}

func TestSelectAndExecute_FilterSet_MinSeverity(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(30)
	cache := newMemCache()
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{MinSeverity: "HIGH", AbsPath: "/tmp/x", ToolName: "scan_pan_data", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil || res.Summary != nil || res.Err != nil {
		t.Fatalf("expected only Flat set; got %+v", res)
	}
	for _, f := range res.Flat.Page {
		if f.Sev != "HIGH" {
			t.Errorf("unexpected severity %q passed through HIGH filter", f.Sev)
		}
	}
}

func TestSelectAndExecute_ScanError(t *testing.T) {
	ctx := context.Background()
	_, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{AbsPath: "/tmp/x", ToolName: "triage_findings"},
		newFakeScan(nil, errors.New("boom")),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSelectAndExecute_FilterError(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(5)
	_, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{MinSeverity: "__bad__", AbsPath: "/tmp/x", ToolName: "scan_pan_data"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err == nil {
		t.Fatal("expected filter error, got nil")
	}
}

func TestSelectAndExecute_PerToolPageSize(t *testing.T) {
	ctx := context.Background()
	findings := make([]fakeFinding, 40)
	for i := range findings {
		findings[i] = fakeFinding{ID: "R-" + strconv.Itoa(i), Sev: "HIGH"}
	}
	cache := newMemCache()

	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{FlatPageSize: 12, MinSeverity: "HIGH", AbsPath: "/tmp/x", ToolName: "triage_findings", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil {
		t.Fatalf("expected Flat, got %+v", res)
	}
	if len(res.Flat.Page) != 12 {
		t.Errorf("first page len=%d, want 12", len(res.Flat.Page))
	}
	if res.Flat.Cursor == "" {
		t.Fatalf("expected non-empty cursor; 40 findings at page=12 leaves more pages")
	}

	payload, err := hybridcache.DecodeCursor(res.Flat.Cursor)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if payload.Off != 12 {
		t.Errorf("cursor Off=%d, want 12 (per-tool page size)", payload.Off)
	}

	res2, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{FlatPageSize: 12, Cursor: res.Flat.Cursor, ToolName: "triage_findings"},
		newFakeScan(nil, errors.New("scan must not be called on cursor resume")),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("cursor resume err: %v", err)
	}
	if res2.Flat == nil {
		t.Fatalf("expected Flat on cursor resume, got %+v", res2)
	}
	if len(res2.Flat.Page) != 12 {
		t.Errorf("second page len=%d, want 12", len(res2.Flat.Page))
	}
	if res2.Flat.Cursor == "" {
		t.Fatalf("expected non-empty cursor; 40-24=16 findings remain")
	}
	payload2, err := hybridcache.DecodeCursor(res2.Flat.Cursor)
	if err != nil {
		t.Fatalf("DecodeCursor p2: %v", err)
	}
	if payload2.Off != 24 {
		t.Errorf("cursor Off=%d, want 24 (12+12 per-tool page size)", payload2.Off)
	}

	resDefault, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{FlatPageSize: 0, MinSeverity: "HIGH", AbsPath: "/tmp/y", ToolName: "scan_pan_data", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("default-size err: %v", err)
	}
	if resDefault.Flat == nil {
		t.Fatalf("expected Flat on default-size call, got %+v", resDefault)
	}
	if len(resDefault.Flat.Page) != 40 {
		t.Errorf("default page len=%d, want 40 (legacy FlatPageSize=60 covers all 40)", len(resDefault.Flat.Page))
	}
	if resDefault.Flat.Cursor != "" {
		t.Errorf("expected empty cursor on legacy default; got %q", resDefault.Flat.Cursor)
	}
}

func TestSelectAndExecute_LimitExceedsPageSize(t *testing.T) {
	ctx := context.Background()
	tt := []struct {
		name        string
		flatPage    int
		limit       int
		wantReject  bool
		wantMaxHint int
	}{
		{name: "triage_limit_within_page", flatPage: 12, limit: 12, wantReject: false},
		{name: "triage_limit_just_over", flatPage: 12, limit: 13, wantReject: true, wantMaxHint: 12},
		{name: "triage_high_positive_attack", flatPage: 12, limit: 200, wantReject: true, wantMaxHint: 12},
		{name: "default_page_within", flatPage: 0, limit: 60, wantReject: false},
		{name: "default_page_over", flatPage: 0, limit: 61, wantReject: true, wantMaxHint: 60},
		{name: "depscanner_limit_just_over", flatPage: 15, limit: 16, wantReject: true, wantMaxHint: 15},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
				ctx,
				Input{
					FlatPageSize:  tc.flatPage,
					Limit:         tc.limit,
					AbsPath:       "/tmp/x",
					ToolName:      "triage_findings",
					ScanTimestamp: "2026-04-18T00:00:00Z",
				},
				newFakeScan(mkFindings(5), nil),
				noopFilter,
				buildSummaryFake,
				buildFlatFake,
				newMemCache(),
			)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantReject {
				if res.Err == nil {
					t.Fatalf("expected reject Err, got nil (Flat=%+v Summary=%+v)", res.Flat, res.Summary)
				}
				if res.Err.Code != "LIMIT_EXCEEDS_PAGE_SIZE" {
					t.Errorf("Code=%q, want LIMIT_EXCEEDS_PAGE_SIZE", res.Err.Code)
				}
				if !strings.Contains(res.Err.Hint, "max="+strconv.Itoa(tc.wantMaxHint)) {
					t.Errorf("Hint=%q, want substring max=%d", res.Err.Hint, tc.wantMaxHint)
				}
				if !strings.Contains(res.Err.Hint, "cursor pagination") {
					t.Errorf("Hint=%q, want substring 'cursor pagination'", res.Err.Hint)
				}
			} else if res.Err != nil {
				t.Errorf("expected no reject, got Err=%+v", res.Err)
			}
		})
	}
}

func TestSelectAndExecute_BuildSummaryNil(t *testing.T) {
	ctx := context.Background()
	buildNilSummary := func(_ []fakeFinding, _ hybridcache.ScanMeta, _, _ string) *fakeSummary {
		return nil
	}
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{AbsPath: "/tmp/x", ToolName: "triage_findings", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(mkFindings(5), nil),
		noopFilter,
		buildNilSummary,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Summary != nil {
		t.Errorf("expected nil summary from nil buildSummary, got non-nil")
	}
}

func TestSelectAndExecute_FreshFilterHistogramFullScan(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(30)
	cache := newMemCache()
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{MinSeverity: "CRITICAL", AbsPath: "/tmp/fresh", ToolName: "triage_findings", ScanTimestamp: "2026-04-20T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil {
		t.Fatalf("expected Flat, got %+v", res)
	}
	if res.Flat.Histogram == nil {
		t.Fatalf("expected non-nil histogram on fresh filter call")
	}
	if res.Flat.Histogram.BySeverity.Info <= 0 {
		t.Errorf("BySeverity.Info=%d want >0 (filter=CRITICAL must not truncate histogram)", res.Flat.Histogram.BySeverity.Info)
	}
	if res.Flat.Histogram.BySeverity.Critical <= 0 {
		t.Errorf("BySeverity.Critical=%d want >0", res.Flat.Histogram.BySeverity.Critical)
	}
	if cache.histogramCalls != 1 {
		t.Errorf("cache.Histogram called %d times on fresh filter, want 1", cache.histogramCalls)
	}
	for _, f := range res.Flat.Page {
		if f.Sev != "CRITICAL" {
			t.Errorf("filtered page contains non-CRITICAL severity %q", f.Sev)
		}
	}
}

func TestSelectAndExecute_CursorResumeHistogramStable(t *testing.T) {
	ctx := context.Background()
	findings := make([]fakeFinding, 100)
	for i := range findings {
		findings[i] = fakeFinding{ID: "R-" + strconv.Itoa(i%7), Sev: "HIGH"}
	}
	for i := 0; i < 20; i++ {
		findings = append(findings, fakeFinding{ID: "R-INFO", Sev: "INFO"})
	}
	cache := newMemCache()

	res1, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{FlatPageSize: 12, MinSeverity: "HIGH", AbsPath: "/tmp/resume", ToolName: "triage_findings", ScanTimestamp: "2026-04-20T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("fresh call err: %v", err)
	}
	if res1.Flat == nil || res1.Flat.Histogram == nil {
		t.Fatalf("fresh call missing Flat or Histogram: %+v", res1)
	}
	if res1.Flat.Cursor == "" {
		t.Fatalf("fresh call must yield cursor (HIGH filter yields 100, page=12 leaves more pages)")
	}

	firstHist, err := json.Marshal(res1.Flat.Histogram)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}

	res2, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{FlatPageSize: 12, Cursor: res1.Flat.Cursor, ToolName: "triage_findings"},
		newFakeScan(nil, errors.New("scan must not be called on resume")),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		cache,
	)
	if err != nil {
		t.Fatalf("resume call err: %v", err)
	}
	if res2.Flat == nil || res2.Flat.Histogram == nil {
		t.Fatalf("resume call missing Flat or Histogram: %+v", res2)
	}

	secondHist, err := json.Marshal(res2.Flat.Histogram)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if string(firstHist) != string(secondHist) {
		t.Errorf("cursor-resume histogram drifted:\nfresh  = %s\nresume = %s", firstHist, secondHist)
	}
	if cache.histogramCalls != 1 {
		t.Errorf("cache.Histogram called %d times across fresh+resume, want 1 (resume replays cached snapshot)", cache.histogramCalls)
	}
}
