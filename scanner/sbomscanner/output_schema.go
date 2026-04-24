package sbomscanner

import (
	"encoding/json"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
)

func buildSBOMOutputSchema() (json.RawMessage, error) {
	s, err := jsonschema.ForType(reflect.TypeOf(GenSBOMOutput{}), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}
