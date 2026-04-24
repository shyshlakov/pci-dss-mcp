package sbomscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleGenerateSBOM_HappyPaths(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		name       string
		input      GenSBOMInput
		wantFormat string
	}{
		{name: "json_default", input: GenSBOMInput{Path: fixtureRoot}, wantFormat: "json"},
		{name: "json_explicit", input: GenSBOMInput{Path: fixtureRoot, Format: "json"}, wantFormat: "json"},
		{name: "json_uppercase", input: GenSBOMInput{Path: fixtureRoot, Format: "JSON"}, wantFormat: "json"},
		{name: "xml", input: GenSBOMInput{Path: fixtureRoot, Format: "xml"}, wantFormat: "xml"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res, raw, err := handleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, tc.input)
			if err != nil {
				t.Fatalf("handler returned Go error: %v", err)
			}
			if res.IsError {
				text := extractText(res)
				t.Fatalf("handler returned IsError result: %s", text)
			}
			out, ok := raw.(*GenSBOMOutput)
			if !ok {
				t.Fatalf("raw return type: got %T want *GenSBOMOutput", raw)
			}
			if out.Format != tc.wantFormat {
				t.Errorf("Format: got %q want %q", out.Format, tc.wantFormat)
			}
			if out.BOMFormat != "CycloneDX" {
				t.Errorf("BOMFormat: got %q want CycloneDX", out.BOMFormat)
			}
			if out.SpecVersion != "1.5" {
				t.Errorf("SpecVersion: got %q want 1.5", out.SpecVersion)
			}
			if out.ComponentCount < 40 {
				t.Errorf("ComponentCount: got %d want >=40", out.ComponentCount)
			}
			if tc.wantFormat == "xml" {
				if !strings.Contains(out.SerializedBOM, "<") {
					preview := out.SerializedBOM
					if len(preview) > 80 {
						preview = preview[:80]
					}
					t.Errorf("xml output does not look like xml: %q", preview)
				}
			} else {
				var probe map[string]any
				if uerr := json.Unmarshal([]byte(out.SerializedBOM), &probe); uerr != nil {
					t.Errorf("json SerializedBOM does not parse: %v", uerr)
				}
			}
		})
	}
}

func TestHandleGenerateSBOM_Errors(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		name       string
		input      GenSBOMInput
		wantSubstr string
	}{
		{name: "empty_path", input: GenSBOMInput{}, wantSubstr: "invalid path: required"},
		{name: "bad_format", input: GenSBOMInput{Path: fixtureRoot, Format: "yaml"}, wantSubstr: `must be "json" or "xml"`},
		{name: "missing_project", input: GenSBOMInput{Path: "/definitely/does/not/exist/here/12345"}, wantSubstr: "sbom generation failed"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res, _, err := handleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, tc.input)
			if err != nil {
				t.Fatalf("handler returned Go error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected IsError=true, got success")
			}
			text := extractText(res)
			if !strings.Contains(text, tc.wantSubstr) {
				t.Errorf("error message: got %q, want substring %q", text, tc.wantSubstr)
			}
		})
	}
}

func TestHandleGenerateSBOM_OversizeGuard(t *testing.T) {
	t.Parallel()
	big := &SBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5"}
	for i := 0; i < 10000; i++ {
		big.Components = append(big.Components, Component{
			Name:    fmt.Sprintf("example.com/synthetic/mod-%d", i),
			Version: "v1.0.0",
			PURL:    fmt.Sprintf("pkg:golang/example.com/synthetic/mod-%d@v1.0.0", i),
			Hashes:  []Hash{{Algorithm: "SHA-256", Content: strings.Repeat("a", 64)}},
		})
	}
	s, _, err := serializeSBOM(big, "json")
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if len(s) <= maxInlineBytes {
		t.Fatalf("synthetic SBOM too small to trigger guard: %d bytes", len(s))
	}
}

func extractText(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}
