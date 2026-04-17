package reportscanner

import (
	"encoding/json"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
)

func buildOutputSchemaUnion() (json.RawMessage, error) {
	sumS, err := jsonschema.ForType(reflect.TypeOf(SummaryResponse{}), nil)
	if err != nil {
		return nil, err
	}
	flatS, err := jsonschema.ForType(reflect.TypeOf(FlatResponse{}), nil)
	if err != nil {
		return nil, err
	}
	errS, err := jsonschema.ForType(reflect.TypeOf(CursorExpiredError{}), nil)
	if err != nil {
		return nil, err
	}
	pinResponseShape(sumS, "summary")
	pinResponseShape(flatS, "flat")
	pinResponseShape(errS, "error")
	union := &jsonschema.Schema{
		Type:     "object",
		OneOf:    []*jsonschema.Schema{sumS, flatS, errS},
		Required: []string{"response_shape"},
	}
	return json.Marshal(union)
}

func pinResponseShape(s *jsonschema.Schema, discriminator string) {
	if s == nil || s.Properties == nil {
		return
	}
	rs, ok := s.Properties["response_shape"]
	if !ok {
		return
	}
	var v any = discriminator
	rs.Const = &v
}
