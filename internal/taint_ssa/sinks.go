package taint_ssa

import (
	"golang.org/x/tools/go/ssa"
)

// IsLoggerSink reports whether call invokes a known logger function or method.
// Concrete implementation lands with the PAN-LOGGER rule port.
func IsLoggerSink(call *ssa.Call) bool {
	return loggerSinkImpl(call)
}

// IsCryptoSink reports whether call invokes a crypto API that consumes a
// key or IV. Concrete implementation lands with the CRYPTO-HARDCODED-KEY
// rule port.
func IsCryptoSink(call *ssa.Call) bool {
	return cryptoSinkImpl(call)
}

// IsDBStoreSink and IsHTTPClientSink are reserved for future parity with the
// AST engine's SinkDBStore and SinkHTTPClient kinds. The PoC does not port
// those rules; the no-op forms keep the API surface symmetric.
func IsDBStoreSink(call *ssa.Call) bool {
	return false
}

func IsHTTPClientSink(call *ssa.Call) bool {
	return false
}

var loggerSinkImpl = func(call *ssa.Call) bool { return false }
var cryptoSinkImpl = func(call *ssa.Call) bool { return false }
