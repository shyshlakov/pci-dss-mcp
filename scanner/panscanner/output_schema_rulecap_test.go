package panscanner

import (
	"encoding/json"
	"testing"
)

func TestBuildPANOutputSchemaUnion_IncludesMoreRules(t *testing.T) {
	t.Parallel()
	raw, err := buildPANOutputSchemaUnion()
	if err != nil {
		t.Fatalf("buildPANOutputSchemaUnion: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	oneOf, ok := schema["oneOf"].([]any)
	if !ok || len(oneOf) == 0 {
		t.Fatalf("oneOf missing or empty: %T", schema["oneOf"])
	}
	var summaryProps map[string]any
	for _, variant := range oneOf {
		vm, ok := variant.(map[string]any)
		if !ok {
			continue
		}
		props, _ := vm["properties"].(map[string]any)
		if props == nil {
			continue
		}
		if _, has := props["summary"]; has {
			if sm, ok := props["summary"].(map[string]any); ok {
				if inner, ok := sm["properties"].(map[string]any); ok {
					summaryProps = inner
					break
				}
			}
		}
	}
	if summaryProps == nil {
		t.Fatalf("summary.properties not found in any oneOf variant")
	}
	mrProp, ok := summaryProps["more_rules"]
	if !ok {
		t.Fatalf("summary.properties.more_rules missing from OutputSchema: %+v", summaryProps)
	}
	mr, ok := mrProp.(map[string]any)
	if !ok {
		t.Fatalf("more_rules property wrong shape: %T", mrProp)
	}
	if typ, _ := mr["type"].(string); typ != "integer" {
		t.Errorf("more_rules type=%q want integer", typ)
	}
}
