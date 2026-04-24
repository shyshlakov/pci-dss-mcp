package sbomscanner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGenerateSBOM_Fixture(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := GenerateSBOM(context.Background(), fixtureRoot)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	if sbom == nil {
		t.Fatal("GenerateSBOM returned nil SBOM without error")
	}
	if sbom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat: got %q want CycloneDX", sbom.BOMFormat)
	}
	if sbom.SpecVersion != "1.6" {
		t.Errorf("SpecVersion: got %q want 1.6", sbom.SpecVersion)
	}
	if got := len(sbom.Components); got < 40 {
		t.Errorf("component count: got %d want >=40", got)
	}
	for i, c := range sbom.Components {
		if c.Name == "" {
			t.Errorf("component[%d] missing Name", i)
		}
		if c.Version == "" {
			t.Errorf("component[%d] (%s) missing Version", i, c.Name)
		}
		if c.PURL == "" {
			t.Errorf("component[%d] (%s) missing PURL", i, c.Name)
		}
		if want := "pkg:golang/" + c.Name + "@" + c.Version; c.PURL != want {
			t.Errorf("component[%d] PURL: got %q want %q", i, c.PURL, want)
		}
		hasSHA256 := false
		for _, h := range c.Hashes {
			if h.Algorithm != "SHA-256" {
				continue
			}
			if len(h.Content) != 64 {
				t.Errorf("component[%d] (%s) SHA-256 hex len: got %d want 64", i, c.Name, len(h.Content))
			}
			hasSHA256 = true
		}
		if !hasSHA256 {
			t.Errorf("component[%d] (%s) missing SHA-256 hash", i, c.Name)
		}
	}
}

func TestGenerateSBOM_InvalidPath(t *testing.T) {
	t.Parallel()
	sbom, err := GenerateSBOM(context.Background(), "/does/not/exist")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if sbom != nil {
		t.Errorf("expected nil SBOM on error, got %+v", sbom)
	}
	if !strings.Contains(err.Error(), "sbom") {
		t.Errorf("error should wrap with sbom context: %v", err)
	}
}

func TestGenerateSBOM_UnknownLicense(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := GenerateSBOM(context.Background(), fixtureRoot)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	if sbom == nil {
		t.Fatal("nil SBOM")
	}
	unknown := 0
	for _, c := range sbom.Components {
		if len(c.Licenses) == 0 {
			unknown++
		}
	}
	if unknown == 0 {
		t.Error("expected at least one component without License entries when GOMODCACHE is empty (D-S4: cache-miss emits pci-dss-mcp:license-status=unknown property, no License object)")
	}
}

func TestHandleGenerateSBOM_UnknownLicensesCount(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, GenSBOMInput{
		Path:       fixtureRoot,
		OutputPath: filepath.Join(work, "sbom.json"),
	})
	if err != nil {
		t.Fatalf("HandleGenerateSBOM: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("unexpected error result: %+v", res)
	}
	out, ok := raw.(*GenSBOMOutput)
	if !ok || out == nil {
		payload := ""
		if res != nil && len(res.Content) > 0 {
			if tc, tok := res.Content[0].(*mcp.TextContent); tok {
				payload = tc.Text
			}
		}
		var parsed GenSBOMOutput
		if payload != "" {
			if jerr := json.Unmarshal([]byte(payload), &parsed); jerr == nil {
				out = &parsed
			}
		}
		if out == nil {
			t.Fatalf("expected *GenSBOMOutput, got %T (payload=%q)", raw, payload)
		}
	}
	if out.UnknownLicenses <= 0 {
		t.Errorf("UnknownLicenses: got %d want > 0 when GOMODCACHE is empty", out.UnknownLicenses)
	}
	if out.ComponentCount <= 0 {
		t.Errorf("ComponentCount: got %d want > 0", out.ComponentCount)
	}
}

func TestGenerateSBOM_CtxCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := GenerateSBOM(ctx, fixtureRoot)
	if err == nil {
		t.Fatal("expected ctx-canceled error, got nil")
	}
	if sbom != nil {
		t.Errorf("expected nil SBOM on ctx cancel, got %+v", sbom)
	}
}
