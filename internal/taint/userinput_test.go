package taint

import (
	"context"
	"testing"
)

func TestUserInputTaintKind(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "TaintUserInput is distinct from existing SinkKind values",
			run: func(t *testing.T) {
				existing := []SinkKind{SinkDBStore, SinkHTTPClient, SinkHTTPResponse, SinkLoggerCall, SinkCryptoCall}
				for _, k := range existing {
					if k == TaintUserInput {
						t.Fatalf("TaintUserInput collides with existing SinkKind %v", k)
					}
				}
			},
		},
		{
			name: "FlowsToUserInput on nil engine returns false without panic",
			run: func(t *testing.T) {
				var engine *TaintEngine
				if engine.FlowsToUserInput(UserInputSource{Package: "example.com/x", TypeName: "Y", Method: "Z"}, SinkPattern{Kind: SinkLoggerCall}) {
					t.Fatalf("expected false on nil engine")
				}
			},
		},
		{
			name: "FlowsToUserInput on engine with no loaded packages returns false",
			run: func(t *testing.T) {
				engine := &TaintEngine{}
				if engine.FlowsToUserInput(UserInputSource{Package: "example.com/x", TypeName: "Y", Method: "Z"}, SinkPattern{Kind: SinkLoggerCall}) {
					t.Fatalf("expected false when loadOK is false")
				}
			},
		},
		{
			name: "FlowsToUserInput returns false when source resolution fails",
			run: func(t *testing.T) {
				resetAround(t)
				root := absFixture(t, "stored_model")
				engine := GetOrInit(context.Background(), root)
				if engine == nil {
					t.Skip("taint engine unavailable")
				}
				src := UserInputSource{
					Package:  "example.com/no/such/package",
					TypeName: "Ghost",
					Method:   "Missing",
				}
				if engine.FlowsToUserInput(src, SinkPattern{Kind: SinkDBStore}) {
					t.Fatalf("expected false for unresolved source")
				}
			},
		},
		{
			name: "UserInputSource zero value is comparable and safe",
			run: func(t *testing.T) {
				var a, b UserInputSource
				if a != b {
					t.Fatalf("zero-value UserInputSource should be equal")
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}
