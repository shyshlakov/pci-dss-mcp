package httpinputscanner

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// logSinkSpec describes one positive-list log sink: package + receiver type +
// method name. A blank TypeName marks a free-function sink. The kvStartIndex
// is the variadic position where positional key/value pairs begin (msg arg is
// at [0..kvStartIndex)).
type logSinkSpec struct {
	PkgPath      string
	TypeName     string
	Method       string
	KvStartIndex int
	// AnyArgTainted skips the kv-shape walk and instead emits whenever ANY
	// arg of the call is tainted (used for builders like slog.Group, attr
	// helpers like slog.String / slog.Any, logrus WithFields, etc.).
	AnyArgTainted bool
}

// logSinkLibrary covers Tier 1 loggers (slog / zap / logrus / zerolog / logr /
// klog / hclog) plus stdlib log per D-16.1. Recognition is via *types.Func
// pointer identity so a fake "slog" package in the analyzed module cannot
// spoof recognition (mitigation T-21.02-04).
var logSinkLibrary = []logSinkSpec{
	{PkgPath: "log/slog", Method: "Info", KvStartIndex: 1},
	{PkgPath: "log/slog", Method: "Warn", KvStartIndex: 1},
	{PkgPath: "log/slog", Method: "Error", KvStartIndex: 1},
	{PkgPath: "log/slog", Method: "Debug", KvStartIndex: 1},
	{PkgPath: "log/slog", Method: "InfoContext", KvStartIndex: 2},
	{PkgPath: "log/slog", Method: "WarnContext", KvStartIndex: 2},
	{PkgPath: "log/slog", Method: "ErrorContext", KvStartIndex: 2},
	{PkgPath: "log/slog", Method: "DebugContext", KvStartIndex: 2},
	{PkgPath: "log/slog", Method: "Log", KvStartIndex: 3},
	{PkgPath: "log/slog", Method: "LogAttrs", KvStartIndex: 3},

	{PkgPath: "log/slog", Method: "With", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "String", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Any", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Int", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Int64", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Uint64", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Bool", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Float64", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Duration", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Time", AnyArgTainted: true},
	{PkgPath: "log/slog", Method: "Group", AnyArgTainted: true},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "With", AnyArgTainted: true},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "WithGroup", AnyArgTainted: true},

	{PkgPath: "log/slog", TypeName: "Logger", Method: "Info", KvStartIndex: 1},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "Warn", KvStartIndex: 1},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "Error", KvStartIndex: 1},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "Debug", KvStartIndex: 1},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "InfoContext", KvStartIndex: 2},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "WarnContext", KvStartIndex: 2},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "ErrorContext", KvStartIndex: 2},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "DebugContext", KvStartIndex: 2},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "Log", KvStartIndex: 3},
	{PkgPath: "log/slog", TypeName: "Logger", Method: "LogAttrs", KvStartIndex: 3},

	{PkgPath: "log", Method: "Print", AnyArgTainted: true},
	{PkgPath: "log", Method: "Printf", KvStartIndex: 1},
	{PkgPath: "log", Method: "Println", AnyArgTainted: true},
	{PkgPath: "log", Method: "Fatal", AnyArgTainted: true},
	{PkgPath: "log", Method: "Fatalf", KvStartIndex: 1},
	{PkgPath: "log", Method: "Fatalln", AnyArgTainted: true},
	{PkgPath: "log", TypeName: "Logger", Method: "Print", AnyArgTainted: true},
	{PkgPath: "log", TypeName: "Logger", Method: "Printf", KvStartIndex: 1},
	{PkgPath: "log", TypeName: "Logger", Method: "Println", AnyArgTainted: true},

	{PkgPath: "github.com/sirupsen/logrus", Method: "Info", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Warn", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Error", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Debug", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Print", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Infof", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Warnf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Errorf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Debugf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Printf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Infoln", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Warnln", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Errorln", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "Println", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "WithField", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "WithFields", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", Method: "WithError", AnyArgTainted: true},

	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Info", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Warn", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Error", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Debug", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Print", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Infof", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Warnf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Errorf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Debugf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "Printf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "WithField", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "WithFields", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Logger", Method: "WithError", AnyArgTainted: true},

	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Info", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Warn", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Error", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Debug", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Print", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Infof", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Warnf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Errorf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Debugf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "Printf", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "WithField", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "WithFields", AnyArgTainted: true},
	{PkgPath: "github.com/sirupsen/logrus", TypeName: "Entry", Method: "WithError", AnyArgTainted: true},

	{PkgPath: "go.uber.org/zap", TypeName: "Logger", Method: "Info", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "Logger", Method: "Warn", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "Logger", Method: "Error", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "Logger", Method: "Debug", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "Logger", Method: "Fatal", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "SugaredLogger", Method: "Infow", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "SugaredLogger", Method: "Warnw", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "SugaredLogger", Method: "Errorw", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", TypeName: "SugaredLogger", Method: "Debugw", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", Method: "String", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", Method: "Any", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", Method: "Int", AnyArgTainted: true},
	{PkgPath: "go.uber.org/zap", Method: "Bool", AnyArgTainted: true},

	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Msg", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Msgf", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Send", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Str", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Stringer", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Int", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Bool", AnyArgTainted: true},
	// Event.Err is intentionally NOT a LOG sink - it carries the error chain
	// finalizer Send/Msg into the HTTP-INPUT-ERROR rule via zerologErrArgs.
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Any", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Interface", AnyArgTainted: true},
	{PkgPath: "github.com/rs/zerolog", TypeName: "Event", Method: "Bytes", AnyArgTainted: true},

	{PkgPath: "github.com/go-logr/logr", TypeName: "Logger", Method: "Info", KvStartIndex: 1},
	{PkgPath: "github.com/go-logr/logr", TypeName: "Logger", Method: "Error", KvStartIndex: 2},
	{PkgPath: "github.com/go-logr/logr", TypeName: "Logger", Method: "WithValues", AnyArgTainted: true},

	{PkgPath: "k8s.io/klog/v2", Method: "Info", AnyArgTainted: true},
	{PkgPath: "k8s.io/klog/v2", Method: "Warning", AnyArgTainted: true},
	{PkgPath: "k8s.io/klog/v2", Method: "Error", AnyArgTainted: true},
	{PkgPath: "k8s.io/klog/v2", Method: "Infof", AnyArgTainted: true},
	{PkgPath: "k8s.io/klog/v2", Method: "InfoS", KvStartIndex: 1},
	{PkgPath: "k8s.io/klog/v2", Method: "ErrorS", KvStartIndex: 2},

	{PkgPath: "github.com/hashicorp/go-hclog", TypeName: "Logger", Method: "Info", KvStartIndex: 1},
	{PkgPath: "github.com/hashicorp/go-hclog", TypeName: "Logger", Method: "Warn", KvStartIndex: 1},
	{PkgPath: "github.com/hashicorp/go-hclog", TypeName: "Logger", Method: "Error", KvStartIndex: 1},
	{PkgPath: "github.com/hashicorp/go-hclog", TypeName: "Logger", Method: "Debug", KvStartIndex: 1},
	{PkgPath: "github.com/hashicorp/go-hclog", TypeName: "Logger", Method: "Trace", KvStartIndex: 1},
}

// logSinkInfo describes a recognized log sink; ArgsToCheck is the slice of
// argument expressions that should be inspected for taint.
type logSinkInfo struct {
	Name        string
	ArgsToCheck []ast.Expr
}

// isLogSink reports whether call resolves to a known log sink and returns the
// arg expressions that need taint inspection.
func isLogSink(call *ast.CallExpr, info *types.Info) (logSinkInfo, bool) {
	if call == nil || info == nil {
		return logSinkInfo{}, false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return logSinkInfo{}, false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recvName := taint.ReceiverTypeName(fn)

	for _, spec := range logSinkLibrary {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recvName {
			continue
		}
		if spec.TypeName == "" && recvName != "" {
			continue
		}
		args := call.Args
		if !spec.AnyArgTainted && spec.KvStartIndex < len(args) {
			args = args[spec.KvStartIndex:]
		}
		return logSinkInfo{
			Name:        sinkDisplayName(pkgPath, recvName, method),
			ArgsToCheck: args,
		}, true
	}

	if recvName != "" {
		if isFieldResolvedLoggerMethod(call, info) {
			return logSinkInfo{
				Name:        sinkDisplayName(pkgPath, recvName, method),
				ArgsToCheck: call.Args,
			}, true
		}
	}

	return logSinkInfo{}, false
}

// isFieldResolvedLoggerMethod reports whether call is a method on a value
// whose type resolves to one of the recognized logger types. Catches the
// `h.log.Error(...)` shape where h.log is a *slog.Logger field.
func isFieldResolvedLoggerMethod(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	tv, ok := info.Types[sel.X]
	if !ok {
		return false
	}
	t := tv.Type
	if t == nil {
		return false
	}
	switch sel.Sel.Name {
	case "Info", "Warn", "Error", "Debug", "InfoContext", "WarnContext", "ErrorContext", "DebugContext",
		"Infof", "Warnf", "Errorf", "Debugf", "Print", "Printf", "Println":
		return isSlogLoggerType(t) || isLogrusLoggerType(t) || isLogrusEntryType(t) || isZapLoggerType(t) || isZerologLoggerType(t)
	case "WithField", "WithFields", "WithError", "WithValues", "With":
		return isLogrusLoggerType(t) || isLogrusEntryType(t) || isSlogLoggerType(t)
	}
	return false
}

// sinkDisplayName renders a stable human-readable sink name for descriptions.
func sinkDisplayName(pkgPath, recv, method string) string {
	switch pkgPath {
	case "log/slog":
		return "slog." + method
	case "log":
		return "log." + method
	case "github.com/sirupsen/logrus":
		return "logrus." + method
	case "go.uber.org/zap":
		return "zap." + method
	case "github.com/rs/zerolog":
		return "zerolog." + method
	case "github.com/go-logr/logr":
		return "logr." + method
	case "k8s.io/klog/v2":
		return "klog." + method
	case "github.com/hashicorp/go-hclog":
		return "hclog." + method
	}
	return strings.TrimPrefix(pkgPath, "github.com/") + "." + method
}
