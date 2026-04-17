package hybrid

import (
	"context"
	"errors"
)

func SelectAndExecute[TFinding, TSummary, TFlat any](
	ctx context.Context,
	in Input,
	scan Scan[TFinding],
	filter Filter[TFinding],
	buildSummary BuildSummary[TFinding, TSummary],
	buildFlat BuildFlat[TFinding, TFlat],
	cache Cacher[TFinding],
) (*Result[TSummary, TFlat], error) {
	_ = ctx
	_ = in
	_ = scan
	_ = filter
	_ = buildSummary
	_ = buildFlat
	_ = cache
	return nil, errors.New("unimplemented")
}
