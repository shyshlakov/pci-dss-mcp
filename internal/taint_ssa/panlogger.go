package taint_ssa

import (
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// taintWalkBudget bounds the per-source forward dataflow traversal so a
// pathological SSA graph cannot stall the PoC. Plan 04 calls for a 50-step
// cap; we allow 64 to absorb harmless graph branching while staying linear.
const taintWalkBudget = 64

// panFieldKeywords mirrors the AST engine's PAN keyword set
// (scanner/panscanner/keywords.go). Copied verbatim to keep the SSA
// package isolated and avoid import cycles. Keywords are matched
// case-insensitively after stripping underscores and hyphens.
var panFieldKeywords = map[string]bool{
	"pan":                  true,
	"cvv":                  true,
	"cvc":                  true,
	"cardnumber":           true,
	"cardnum":              true,
	"creditcard":           true,
	"debitcard":            true,
	"accountnumber":        true,
	"primaryaccountnumber": true,
	"securitycode":         true,
	"verificationcode":     true,
	"cardholder":           true,
	"trackdata":            true,
	"track1":               true,
	"track2":               true,
	"magneticstripe":       true,
	"pinblock":             true,
}

// panAmbiguousKeywords are field names that match PAN only when the
// enclosing struct has at least one sibling field whose name also matches a
// strong PAN keyword. "Number" alone is too generic to flag in isolation.
var panAmbiguousKeywords = map[string]bool{
	"number":  true,
	"holder":  true,
	"expiry":  true,
	"expires": true,
	"iban":    true,
}

// loggerPackagePaths enumerates the Tier 1 logging library paths the SSA
// PoC recognizes. Mirrors the AST engine's logger sink coverage so recall
// numbers compare directly.
var loggerPackagePaths = map[string]bool{
	"log":                           true,
	"log/slog":                      true,
	"github.com/sirupsen/logrus":    true,
	"go.uber.org/zap":               true,
	"github.com/rs/zerolog":         true,
	"github.com/go-logr/logr":       true,
	"k8s.io/klog/v2":                true,
	"github.com/hashicorp/go-hclog": true,
}

var loggerTypeNames = map[string]bool{
	"Logger":  true,
	"Entry":   true,
	"Event":   true,
	"Context": true,
	"Sugar":   true,
}

func init() {
	panSourceImpl = panSourceConcrete
	loggerSinkImpl = loggerSinkConcrete
}

func normalizeFieldName(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		if r == '_' || r == '-' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func isPANFieldName(name string) bool {
	return panFieldKeywords[normalizeFieldName(name)]
}

func isAmbiguousPANFieldName(name string) bool {
	return panAmbiguousKeywords[normalizeFieldName(name)]
}

func structSiblingsContainPAN(st *types.Struct, excludeIdx int) bool {
	if st == nil {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if i == excludeIdx {
			continue
		}
		if isPANFieldName(st.Field(i).Name()) {
			return true
		}
	}
	return false
}

// panSourceConcrete recognizes PAN field reads:
//
//   - *ssa.FieldAddr: address-of struct field (the common case for
//     non-pointer struct values accessed via &x.Field).
//   - *ssa.Field: direct struct field selection on a struct value.
//   - *ssa.UnOp on a *ssa.FieldAddr: dereference (the typical x.Field read).
func panSourceConcrete(v ssa.Value) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case *ssa.FieldAddr:
		return panFieldFromAddr(x)
	case *ssa.Field:
		return panFieldFromField(x)
	case *ssa.UnOp:
		if inner, ok := x.X.(*ssa.FieldAddr); ok {
			return panFieldFromAddr(inner)
		}
	}
	return false
}

func panFieldFromAddr(fa *ssa.FieldAddr) bool {
	if fa == nil || fa.X == nil {
		return false
	}
	t := fa.X.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || fa.Field >= st.NumFields() {
		return false
	}
	name := st.Field(fa.Field).Name()
	if isPANFieldName(name) {
		return true
	}
	if isAmbiguousPANFieldName(name) && structSiblingsContainPAN(st, fa.Field) {
		return true
	}
	return false
}

func panFieldFromField(f *ssa.Field) bool {
	if f == nil || f.X == nil {
		return false
	}
	st, ok := f.X.Type().Underlying().(*types.Struct)
	if !ok || f.Field >= st.NumFields() {
		return false
	}
	name := st.Field(f.Field).Name()
	if isPANFieldName(name) {
		return true
	}
	if isAmbiguousPANFieldName(name) && structSiblingsContainPAN(st, f.Field) {
		return true
	}
	return false
}

func calleePackageAndName(call *ssa.Call) (pkg string, name string) {
	if call == nil {
		return "", ""
	}
	common := call.Common()
	if common == nil {
		return "", ""
	}
	if fn := common.StaticCallee(); fn != nil {
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			pkg = fn.Pkg.Pkg.Path()
		}
		name = fn.Name()
		return pkg, name
	}
	if common.Method != nil {
		name = common.Method.Name()
		if common.Method.Pkg() != nil {
			pkg = common.Method.Pkg().Path()
		}
		return pkg, name
	}
	return "", ""
}

func receiverTypeName(call *ssa.Call) (pkgPath string, typeName string) {
	if call == nil {
		return "", ""
	}
	common := call.Common()
	if common == nil || common.Method == nil {
		return "", ""
	}
	sig, ok := common.Method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", ""
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if named.Obj() != nil && named.Obj().Pkg() != nil {
			pkgPath = named.Obj().Pkg().Path()
			typeName = named.Obj().Name()
		}
	}
	return pkgPath, typeName
}

// loggerSinkConcrete checks free-function logger calls (slog.Info,
// log.Printf, ...) and method calls on logger receivers
// ((*slog.Logger).Info, (*logrus.Entry).Error, ...).
func loggerSinkConcrete(call *ssa.Call) bool {
	if call == nil {
		return false
	}
	pkg, name := calleePackageAndName(call)
	if pkg != "" && loggerPackagePaths[pkg] && isLoggerEmittingName(name) {
		return true
	}
	rPkg, rType := receiverTypeName(call)
	if rPkg != "" && loggerPackagePaths[rPkg] && loggerTypeNames[rType] {
		if isLoggerEmittingName(name) || isLoggerChainingName(name) {
			return true
		}
	}
	return false
}

func isLoggerEmittingName(name string) bool {
	switch name {
	case
		"Print", "Printf", "Println",
		"Debug", "Debugf", "Debugln", "DebugContext", "DebugContextf",
		"Info", "Infof", "Infoln", "InfoContext", "InfoContextf",
		"Warn", "Warnf", "Warnln", "WarnContext", "WarnContextf", "Warning", "Warningf",
		"Error", "Errorf", "Errorln", "ErrorContext", "ErrorContextf",
		"Fatal", "Fatalf", "Fatalln",
		"Panic", "Panicf", "Panicln",
		"Log", "Logf",
		"Msg", "Msgf",
		"V":
		return true
	}
	return false
}

func isLoggerChainingName(name string) bool {
	if strings.HasPrefix(name, "With") {
		return true
	}
	switch name {
	case "Str", "Int", "Bool", "Any", "Field", "Fields":
		return true
	}
	return false
}

// Finding is a minimal local result type emitted by the rule ports. A
// production scanner would use scanner.Finding from the parent package; the
// PoC keeps the dependency local to preserve the package isolation contract.
type Finding struct {
	RuleID      string
	File        string
	Line        int
	Description string
}

// RunPANLogger walks every SSA function in p, identifies PAN sources via
// IsPANSource, and traces forward dataflow through the SSA value graph
// (UnOp, Phi, Call, Store, MakeInterface, ChangeType, ChangeInterface,
// Convert, Slice, Index) until a value reaches a logger sink call. Each
// match emits a Finding with the position of the originating source.
//
// Findings are deduplicated by (file, line). One source location can
// surface as both a FieldAddr and a deref UnOp in SSA; we collapse them
// so the recall measurement compares to the AST engine's per-line counts.
func RunPANLogger(p *Program) []Finding {
	if p == nil {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, fn := range p.Functions() {
		if fn == nil {
			continue
		}
		for _, f := range scanPANLoggerInFunction(p, fn) {
			key := f.File + ":" + strconv.Itoa(f.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func scanPANLoggerInFunction(p *Program, fn *ssa.Function) []Finding {
	var out []Finding
	for _, block := range fn.Blocks {
		if block == nil {
			continue
		}
		for _, instr := range block.Instrs {
			val, ok := instr.(ssa.Value)
			if !ok || !panSourceConcrete(val) {
				continue
			}
			if reachesLoggerSink(val, taintWalkBudget) {
				pos := p.Prog.Fset.Position(val.Pos())
				out = append(out, Finding{
					RuleID:      "PAN-LOGGER",
					File:        pos.Filename,
					Line:        pos.Line,
					Description: "PAN field flows to logger sink",
				})
			}
		}
	}
	return out
}

func reachesLoggerSink(start ssa.Value, budget int) bool {
	return reachesSink(start, budget, loggerSinkConcrete)
}

// reachesSink runs a forward dataflow walk from start. It chases v's
// Referrers, propagates through call args, follows Store->aggregate
// taint (Store *addr = val -> mark the aggregate addr points into),
// and stops when isSink returns true on a *ssa.Call.
func reachesSink(start ssa.Value, budget int, isSink func(*ssa.Call) bool) bool {
	visited := map[ssa.Value]bool{}
	var visit func(v ssa.Value, remaining int) bool
	visit = func(v ssa.Value, remaining int) bool {
		if v == nil || remaining <= 0 || visited[v] {
			return false
		}
		visited[v] = true
		referrers := v.Referrers()
		if referrers == nil {
			return false
		}
		for _, ref := range *referrers {
			switch r := ref.(type) {
			case *ssa.Call:
				if isSink(r) {
					return true
				}
				if propagated := propagateThroughCall(r, v); propagated != nil {
					if visit(propagated, remaining-1) {
						return true
					}
				}
			case *ssa.Store:
				if r.Val == v {
					if root := aggregateBase(r.Addr); root != nil {
						if visit(root, remaining-1) {
							return true
						}
					}
					if next := storeAddrAsValue(r); next != nil {
						if visit(next, remaining-1) {
							return true
						}
					}
				}
			default:
				if next, ok := ref.(ssa.Value); ok {
					if visit(next, remaining-1) {
						return true
					}
				}
			}
		}
		return false
	}
	return visit(start, budget)
}

// aggregateBase walks backwards through IndexAddr and FieldAddr chains to
// the underlying aggregate (typically an *ssa.Alloc). Used so storing a
// tainted value into one slot of an array or struct taints the whole
// aggregate, letting forward walks find readers of the aggregate.
func aggregateBase(addr ssa.Value) ssa.Value {
	for {
		switch a := addr.(type) {
		case *ssa.IndexAddr:
			addr = a.X
		case *ssa.FieldAddr:
			addr = a.X
		default:
			return addr
		}
	}
}

// propagateThroughCall returns the call's result when v is one of the call
// operands and the call is not itself a sink. This models the simple
// "tainted-in -> tainted-out" pass-through that helper functions exhibit
// without doing a full interprocedural taint analysis.
func propagateThroughCall(call *ssa.Call, v ssa.Value) ssa.Value {
	if call == nil || v == nil {
		return nil
	}
	common := call.Common()
	if common == nil {
		return nil
	}
	for _, arg := range common.Args {
		if arg == v {
			return call
		}
	}
	if common.Value == v {
		return call
	}
	return nil
}

func storeAddrAsValue(s *ssa.Store) ssa.Value {
	if s == nil || s.Addr == nil {
		return nil
	}
	return s.Addr
}
