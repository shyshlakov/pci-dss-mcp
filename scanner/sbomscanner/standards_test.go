package sbomscanner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/google/licensecheck"
)

var spdxIDSet = func() map[string]struct{} {
	m := make(map[string]struct{}, 256)
	for _, l := range licensecheck.BuiltinLicenses() {
		m[l.ID] = struct{}{}
	}
	return m
}()

func TestSBOMStandardsConformance(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	sbom, err := GenerateSBOM(context.Background(), fixtureRoot)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	raw, _, err := serializeSBOM(sbom, "json")
	if err != nil {
		t.Fatalf("serializeSBOM: %v", err)
	}

	var probe map[string]any
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	if got, _ := probe["specVersion"].(string); got != "1.6" {
		t.Errorf("specVersion: got %q want \"1.6\"", got)
	}

	serialRe := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if got, _ := probe["serialNumber"].(string); !serialRe.MatchString(got) {
		t.Errorf("serialNumber: got %q want urn:uuid v4 form", got)
	}

	metadata, _ := probe["metadata"].(map[string]any)
	if metadata == nil {
		t.Fatal("metadata block missing")
	}
	if ts, _ := metadata["timestamp"].(string); ts == "" {
		t.Error("metadata.timestamp empty")
	} else if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("metadata.timestamp not RFC3339: %v", err)
	}

	mainComp, _ := metadata["component"].(map[string]any)
	if mainComp == nil {
		t.Fatal("metadata.component missing")
	}
	if mainComp["bom-ref"] != mainComp["purl"] {
		t.Errorf("metadata.component bom-ref (%v) != purl (%v)", mainComp["bom-ref"], mainComp["purl"])
	}
	mainPURL, _ := mainComp["purl"].(string)

	tools, _ := metadata["tools"].(map[string]any)
	toolComps, _ := tools["components"].([]any)
	if len(toolComps) == 0 {
		t.Fatal("metadata.tools.components empty")
	}
	first, _ := toolComps[0].(map[string]any)
	if name, _ := first["name"].(string); name != "pci-dss-mcp" {
		t.Errorf("tool name: got %v want pci-dss-mcp", first["name"])
	}
	if v, _ := first["version"].(string); v == "" {
		t.Error("tool version empty")
	}
	if er, _ := first["externalReferences"].([]any); len(er) < 1 {
		t.Error("tool externalReferences empty")
	}

	components, _ := probe["components"].([]any)
	for _, raw := range components {
		c, _ := raw.(map[string]any)
		if cp, _ := c["purl"].(string); cp != "" && cp == mainPURL {
			t.Errorf("main module purl %q must not appear in bom.Components", cp)
		}
		lics, _ := c["licenses"].([]any)
		for _, lraw := range lics {
			lc, _ := lraw.(map[string]any)
			lic, _ := lc["license"].(map[string]any)
			id, _ := lic["id"].(string)
			if id == "" {
				continue
			}
			if _, ok := spdxIDSet[id]; !ok {
				t.Errorf("component %v license.id %q is not a valid SPDX identifier", c["name"], id)
			}
		}
	}
}
