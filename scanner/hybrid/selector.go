package hybrid

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

func effectivePageSize(in Input) int {
	if in.FlatPageSize > 0 {
		return in.FlatPageSize
	}
	return FlatPageSize
}

func SelectAndExecute[TFinding, TSummary, TFlat any](
	ctx context.Context,
	in Input,
	scan Scan[TFinding],
	filter Filter[TFinding],
	buildSummary BuildSummary[TFinding, TSummary],
	buildFlat BuildFlat[TFinding, TFlat],
	cache Cacher[TFinding],
) (*Result[TSummary, TFlat], error) {
	if in.Limit > 0 {
		cap := effectivePageSize(in)
		if in.Limit > cap {
			return &Result[TSummary, TFlat]{Err: &CursorError{
				Code: "LIMIT_EXCEEDS_PAGE_SIZE",
				Hint: fmt.Sprintf("limit=%d exceeds max=%d for %s. Use cursor pagination: call without limit (or with limit<=%d), then follow next_cursor for additional pages.", in.Limit, cap, in.ToolName, cap),
			}}, nil
		}
	}
	if in.Cursor != "" {
		payload, err := hybridcache.DecodeCursor(in.Cursor)
		if err != nil {
			return &Result[TSummary, TFlat]{Err: &CursorError{Code: "CURSOR_MALFORMED", Hint: hintCursorMalformed}}, nil
		}
		if payload.Tool != "" && payload.Tool != in.ToolName {
			return &Result[TSummary, TFlat]{Err: &CursorError{Code: "CURSOR_MALFORMED", Hint: hintCursorMalformed}}, nil
		}
		cached, meta, ok := cache.Get(payload.SID)
		if !ok {
			return &Result[TSummary, TFlat]{Err: &CursorError{Code: "CURSOR_EXPIRED", Hint: hintCursorExpired}}, nil
		}
		total := len(cached)
		off := payload.Off
		if off < 0 {
			off = 0
		}
		pageSize := effectivePageSize(in)
		end := off + pageSize
		if end > total {
			end = total
		}
		var page []TFinding
		if off < total {
			page = cached[off:end]
		}
		next := ""
		if end < total {
			encoded, encErr := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: payload.SID, Off: end, Tool: in.ToolName})
			if encErr != nil {
				slog.Warn("hybrid.SelectAndExecute encodeCursor failed", "err", encErr, "tool", in.ToolName, "off", end)
			} else {
				next = encoded
			}
		}
		flat := buildFlat(page, off, pageSize, total, meta, payload.SID, next, false)
		return &Result[TSummary, TFlat]{Flat: flat}, nil
	}

	findings, meta, err := scan(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("hybrid scan: %w", err)
	}

	if in.Limit > 0 || in.MinSeverity != "" || in.RuleFilter != "" {
		filtered, ferr := filter(findings, in.MinSeverity, in.RuleFilter)
		if ferr != nil {
			return nil, fmt.Errorf("hybrid filter: %w", ferr)
		}
		fh := hybridcache.FilterHash(in.MinSeverity, in.RuleFilter, in.IncludeTests)
		sid := hybridcache.SessionKey(in.AbsPath+"|"+in.ToolName, in.ScanTimestamp, fh, in.IncludeTaint)
		cache.Put(sid, filtered, meta)
		pageSize := effectivePageSize(in)
		if in.Limit > 0 {
			pageSize = in.Limit
		}
		total := len(filtered)
		end := pageSize
		if end > total {
			end = total
		}
		page := filtered[:end]
		next := ""
		if end < total {
			encoded, encErr := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: sid, Off: end, Tool: in.ToolName})
			if encErr != nil {
				slog.Warn("hybrid.SelectAndExecute encodeCursor failed", "err", encErr, "tool", in.ToolName, "sid", sid, "off", end)
			} else {
				next = encoded
			}
		}
		flat := buildFlat(page, 0, pageSize, total, meta, sid, next, false)
		return &Result[TSummary, TFlat]{Flat: flat}, nil
	}

	fh := hybridcache.FilterHash("", "", in.IncludeTests)
	sid := hybridcache.SessionKey(in.AbsPath+"|"+in.ToolName, in.ScanTimestamp, fh, in.IncludeTaint)
	cache.Put(sid, findings, meta)
	next, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: sid, Off: 0, Tool: in.ToolName})
	if err != nil {
		slog.Warn("hybrid.SelectAndExecute encodeCursor failed", "err", err, "tool", in.ToolName, "sid", sid)
		next = ""
	}
	summary := buildSummary(findings, meta, sid, next)
	return &Result[TSummary, TFlat]{Summary: summary}, nil
}
