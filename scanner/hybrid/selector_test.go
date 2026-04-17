package hybrid

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

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
	Page       []fakeFinding
	Total      int
	AutoCapped bool
	Off        int
	Cursor     string
}

type memCache struct {
	mu sync.Mutex
	m  map[string]memEntry
}

type memEntry struct {
	findings []fakeFinding
	meta     hybridcache.ScanMeta
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

func buildFlatFake(findings []fakeFinding, off, pageSize, total int, meta hybridcache.ScanMeta, sid, nextCursor string, autoCapped bool) *fakeFlat {
	return &fakeFlat{Page: findings, Total: total, AutoCapped: autoCapped, Off: off, Cursor: nextCursor}
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

func TestSelectAndExecute_LimitNegOne_UnderCap(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(100)
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Limit: -1, AbsPath: "/tmp/x", ToolName: "triage_findings", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil || res.Flat.AutoCapped {
		t.Fatalf("expected Flat auto_capped=false; got %+v", res)
	}
	if res.Flat.Total != 100 || len(res.Flat.Page) != 100 {
		t.Errorf("Flat=%+v, want total=100 page=100", res.Flat)
	}
}

func TestSelectAndExecute_LimitNegOne_OverCap(t *testing.T) {
	ctx := context.Background()
	findings := mkFindings(700)
	res, err := SelectAndExecute[fakeFinding, fakeSummary, fakeFlat](
		ctx,
		Input{Limit: -1, AbsPath: "/tmp/x", ToolName: "scan_pan_data", ScanTimestamp: "2026-04-17T00:00:00Z"},
		newFakeScan(findings, nil),
		noopFilter,
		buildSummaryFake,
		buildFlatFake,
		newMemCache(),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Flat == nil || !res.Flat.AutoCapped {
		t.Fatalf("expected Flat auto_capped=true; got %+v", res)
	}
	if res.Flat.Total != 700 || len(res.Flat.Page) != AutoCapThreshold {
		t.Errorf("Flat=%+v, want total=700 page=%d", res.Flat, AutoCapThreshold)
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
