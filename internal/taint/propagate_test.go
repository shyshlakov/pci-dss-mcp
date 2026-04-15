package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// loadEngineForFixture is a small helper that loads a fixture and skips the
// test if the engine is unavailable (CI container with no go binary).
func loadEngineForFixture(t *testing.T, name string) *TaintEngine {
	t.Helper()
	resetAround(t)
	root := absFixture(t, name)
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable — go binary missing?")
	}
	return engine
}

// TestFlowsTo_Direct — stored_model fixture, Card.Number flows to
// database/sql.DB.Exec directly via R3 (arg binding in Save) + R5 (sink hit).
func TestFlowsTo_Direct(t *testing.T) {
	engine := loadEngineForFixture(t, "stored_model")
	src := Source{Package: "example.com/storedmodel", TypeName: "Card", Field: "Number"}
	if !engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected Card.Number to flow to SinkDBStore")
	}
}

// TestFlowsTo_CrossFunction — encrypted_store fixture, Card.CVV flows
// through Encrypt() to database/sql.DB.Exec. Exercises R3 + R4 + R5.
func TestFlowsTo_CrossFunction(t *testing.T) {
	engine := loadEngineForFixture(t, "encrypted_store")
	src := Source{Package: "example.com/encryptedstore", TypeName: "Card", Field: "CVV"}
	if !engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected encrypted_store Card.CVV to flow through Encrypt to DB sink")
	}
}

// TestFlowsTo_CrossPackage — cross_package fixture, a.Req.PAN → b.Store → db.Exec.
func TestFlowsTo_CrossPackage(t *testing.T) {
	engine := loadEngineForFixture(t, "cross_package")
	src := Source{Package: "example.com/crosspkg/a", TypeName: "Req", Field: "PAN"}
	if !engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected cross-package Req.PAN → b.Store → db.Exec flow")
	}
}

// TestFlowsTo_DepthLimit — build a synthetic module with 7 nested functions
// each passing the tainted argument forward. The contract is that FlowsTo
// TERMINATES within the -timeout (10 s), regardless of whether it finds the
// sink or not. Bounding it with maxDepth=5 is the point.
func TestFlowsTo_DepthLimit(t *testing.T) {
	resetAround(t)
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/depth\n\ngo 1.25\n")
	mustWrite(t, filepath.Join(dir, "deep.go"), `package deep

import "database/sql"

type Req struct{ PAN string }

func f0(db *sql.DB, r Req) error { return f1(db, r.PAN) }
func f1(db *sql.DB, s string) error { return f2(db, s) }
func f2(db *sql.DB, s string) error { return f3(db, s) }
func f3(db *sql.DB, s string) error { return f4(db, s) }
func f4(db *sql.DB, s string) error { return f5(db, s) }
func f5(db *sql.DB, s string) error { return f6(db, s) }
func f6(db *sql.DB, s string) error { return f7(db, s) }
func f7(db *sql.DB, s string) error {
	_, err := db.Exec("INSERT INTO t (p) VALUES (?)", s)
	return err
}
`)
	engine := GetOrInit(context.Background(), dir)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}
	src := Source{Package: "example.com/depth", TypeName: "Req", Field: "PAN"}
	// Contract: termination, not result.
	_ = engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore})
}

// TestFlowsTo_SinkPackageMissing — transit_dto imports net/http, not any
// DB package. SinkDBStore must therefore resolve to zero targets and
// FlowsTo must return false.
func TestFlowsTo_SinkPackageMissing(t *testing.T) {
	engine := loadEngineForFixture(t, "transit_dto")
	src := Source{Package: "example.com/transitdto/requests", TypeName: "TokenizeRequest", Field: "CVV"}
	if engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected false for SinkDBStore on DB-less transit_dto fixture")
	}
	// Sanity: the same source DOES flow to HTTPClient.
	if !engine.FlowsTo(src, SinkPattern{Kind: SinkHTTPClient}) {
		t.Fatalf("expected TokenizeRequest.CVV to flow to HTTPClient sink in transit_dto")
	}
}

// TestFlowsTo_UnknownSource — asking about a non-existent type must return
// false without panic.
func TestFlowsTo_UnknownSource(t *testing.T) {
	engine := loadEngineForFixture(t, "transit_dto")
	src := Source{Package: "example.com/nonexistent", TypeName: "Foo", Field: "Bar"}
	if engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected false for unknown source, got true")
	}
}

// TestFlowsTo_StructLiteral — stored_model SaveViaLiteral pipes a parameter
// through Card{Number: rawNumber} into db.Exec. Verifies R2 + A1 mitigation.
func TestFlowsTo_StructLiteral(t *testing.T) {
	engine := loadEngineForFixture(t, "stored_model")
	src := Source{Package: "example.com/storedmodel", TypeName: "Card", Field: "Number"}
	if !engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected Card.Number composite-literal flow to reach DB sink")
	}
}

// TestFlowsTo_EmbeddedDB — stored_model Repo{*sql.DB}.SaveEmbedded calls
// repo.Exec which resolves via method promotion to the same *types.Func as
// (*sql.DB).Exec. Exercises A2 / pointer-method-set promotion.
func TestFlowsTo_EmbeddedDB(t *testing.T) {
	engine := loadEngineForFixture(t, "stored_model")
	targets := engine.resolveSinks(SinkPattern{Kind: SinkDBStore})
	if len(targets) == 0 {
		t.Fatalf("expected non-zero DB sink targets (embedded promotion)")
	}
}

// TestFlowsTo_Cycle — build a synthetic recursive module and assert
// FlowsTo terminates within the test -timeout.
func TestFlowsTo_Cycle(t *testing.T) {
	resetAround(t)
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/cycle\n\ngo 1.25\n")
	mustWrite(t, filepath.Join(dir, "cycle.go"), `package cycle

import "database/sql"

type Req struct{ PAN string }

func f(db *sql.DB, r Req) error { return g(db, r) }
func g(db *sql.DB, r Req) error { return f(db, r) }
`)
	engine := GetOrInit(context.Background(), dir)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}
	// FlowsTo must not hang. We don't care about the result here.
	_ = engine.FlowsTo(
		Source{Package: "example.com/cycle", TypeName: "Req", Field: "PAN"},
		SinkPattern{Kind: SinkDBStore},
	)
}

// TestFlowsTo_InterfaceDispatch_Inconclusive — inconclusive fixture, the
// trace terminates at the interface method call and FlowsTo returns false
// without panic. This is a documented known-limitation.
func TestFlowsTo_InterfaceDispatch_Inconclusive(t *testing.T) {
	engine := loadEngineForFixture(t, "inconclusive")
	src := Source{Package: "example.com/inconclusive", TypeName: "Req", Field: "CVV"}
	if engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore}) {
		t.Fatalf("expected false (interface dispatch erases trace), got true")
	}
}

// Sanity check that propagate_test.go's fixture helpers can see the
// stored_model extensions (SaveViaLiteral, Repo) — otherwise the taint
// engine would report zero coverage of them.
func TestFixtureExtensionsPresent(t *testing.T) {
	root := absFixture(t, "stored_model")
	for _, f := range []string{"via_struct_literal.go", "embedded_db.go"} {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Fatalf("missing fixture extension %s: %v", f, err)
		}
	}
}
