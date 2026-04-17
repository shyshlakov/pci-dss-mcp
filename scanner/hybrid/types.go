package hybrid

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

type Input struct {
	AbsPath       string
	Cursor        string
	MinSeverity   string
	RuleFilter    string
	Limit         int
	IncludeTests  bool
	IncludeTaint  bool
	ScanTimestamp string
	ToolName      string
	FlatPageSize  int `json:"flat_page_size,omitempty"`
}

type Result[TSummary, TFlat any] struct {
	Summary *TSummary
	Flat    *TFlat
	Err     *CursorError
}

type CursorError struct {
	Code string
	Hint string
}

type Scan[TFinding any] func(ctx context.Context, in Input) ([]TFinding, hybridcache.ScanMeta, error)

type Filter[TFinding any] func(findings []TFinding, minSeverity, ruleFilter string) ([]TFinding, error)

type BuildSummary[TFinding, TSummary any] func(
	findings []TFinding,
	meta hybridcache.ScanMeta,
	sid string,
	nextCursor string,
) *TSummary

type BuildFlat[TFinding, TFlat any] func(
	findings []TFinding,
	off int,
	pageSize int,
	total int,
	meta hybridcache.ScanMeta,
	sid string,
	nextCursor string,
	autoCapped bool,
) *TFlat

type Cacher[TFinding any] interface {
	Put(sid string, findings []TFinding, meta hybridcache.ScanMeta)
	Get(sid string) ([]TFinding, hybridcache.ScanMeta, bool)
}

const (
	AutoCapThreshold = 500
	FlatPageSize     = 60
)

const (
	hintCursorMalformed = "Cursor token is corrupted. Re-run without cursor to start a fresh scan."
	hintCursorExpired   = "Session cache expired or server restarted. Re-run without cursor to start a fresh scan."
)
