package taint

import (
	"context"
	"go/types"
	"testing"
)

func TestLookupField_TransitDTO(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "transit_dto")
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}
	obj := engine.lookupField(Source{
		Package:  "example.com/transitdto/requests",
		TypeName: "TokenizeRequest",
		Field:    "CVV",
	})
	if obj == nil {
		t.Fatalf("expected non-nil field object for TokenizeRequest.CVV")
	}
	if _, ok := obj.(*types.Var); !ok {
		t.Fatalf("expected *types.Var, got %T", obj)
	}
	if obj.Name() != "CVV" {
		t.Fatalf("expected field name CVV, got %q", obj.Name())
	}
}

func TestLookupField_UnknownSource(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "transit_dto")
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}
	obj := engine.lookupField(Source{
		Package:  "example.com/nope",
		TypeName: "Ghost",
		Field:    "Missing",
	})
	if obj != nil {
		t.Fatalf("expected nil for missing source, got %v", obj)
	}
}
