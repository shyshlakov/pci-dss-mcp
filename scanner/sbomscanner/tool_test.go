package sbomscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		{name: "json_default", input: GenSBOMInput{Path: fixtureRoot, Inline: true}, wantFormat: "json"},
		{name: "json_explicit", input: GenSBOMInput{Path: fixtureRoot, Format: "json", Inline: true}, wantFormat: "json"},
		{name: "json_uppercase", input: GenSBOMInput{Path: fixtureRoot, Format: "JSON", Inline: true}, wantFormat: "json"},
		{name: "xml", input: GenSBOMInput{Path: fixtureRoot, Format: "xml", Inline: true}, wantFormat: "xml"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, tc.input)
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
			if out.SpecVersion != "1.6" {
				t.Errorf("SpecVersion: got %q want 1.6", out.SpecVersion)
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
			res, _, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, tc.input)
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
	big := &SBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6"}
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

func TestHandleGenerateSBOM_FileOutput(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		name       string
		prep       func(t *testing.T) (workDir string, input GenSBOMInput, expectedExt string)
		wantFormat string
		wantPath   func(workDir string) string
	}{
		{
			name: "default_json",
			prep: func(tt *testing.T) (string, GenSBOMInput, string) {
				work := copyFixtureToTemp(tt, fixtureRoot)
				return work, GenSBOMInput{Path: work}, ".json"
			},
			wantFormat: "json",
			wantPath: func(workDir string) string {
				return filepath.Join(workDir, "sbom.json")
			},
		},
		{
			name: "default_xml",
			prep: func(tt *testing.T) (string, GenSBOMInput, string) {
				work := copyFixtureToTemp(tt, fixtureRoot)
				return work, GenSBOMInput{Path: work, Format: "xml"}, ".xml"
			},
			wantFormat: "xml",
			wantPath: func(workDir string) string {
				return filepath.Join(workDir, "sbom.xml")
			},
		},
		{
			name: "explicit_output_path",
			prep: func(tt *testing.T) (string, GenSBOMInput, string) {
				work := copyFixtureToTemp(tt, fixtureRoot)
				dest := filepath.Join(tt.TempDir(), "custom-sbom.json")
				return work, GenSBOMInput{Path: work, OutputPath: dest}, ".json"
			},
			wantFormat: "json",
			wantPath:   nil,
		},
		{
			name: "overwrite_existing",
			prep: func(tt *testing.T) (string, GenSBOMInput, string) {
				work := copyFixtureToTemp(tt, fixtureRoot)
				existing := filepath.Join(work, "sbom.json")
				if err := os.WriteFile(existing, []byte("OLD"), 0o644); err != nil {
					tt.Fatal(err)
				}
				return work, GenSBOMInput{Path: work}, ".json"
			},
			wantFormat: "json",
			wantPath: func(workDir string) string {
				return filepath.Join(workDir, "sbom.json")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(ttt *testing.T) {
			ttt.Parallel()
			work, input, expectedExt := tc.prep(ttt)
			res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, input)
			if err != nil {
				ttt.Fatalf("handler: %v", err)
			}
			if res.IsError {
				ttt.Fatalf("IsError: %s", extractText(res))
			}
			out, ok := raw.(*GenSBOMOutput)
			if !ok {
				ttt.Fatalf("raw type: %T", raw)
			}
			if out.Mode != "file" {
				ttt.Errorf("Mode: got %q want file", out.Mode)
			}
			if out.SerializedBOM != "" {
				ttt.Errorf("SerializedBOM: want empty in file mode, got %d bytes", len(out.SerializedBOM))
			}
			if out.OutputPath == "" {
				ttt.Fatal("OutputPath empty")
			}
			if !strings.HasSuffix(out.OutputPath, expectedExt) {
				ttt.Errorf("OutputPath suffix: got %q want suffix %q", out.OutputPath, expectedExt)
			}
			if tc.wantPath != nil {
				want := tc.wantPath(work)
				if out.OutputPath != want {
					ttt.Errorf("OutputPath: got %q want %q", out.OutputPath, want)
				}
			}
			if out.SizeBytes <= 0 {
				ttt.Errorf("SizeBytes: got %d want >0", out.SizeBytes)
			}
			body, rerr := os.ReadFile(out.OutputPath)
			if rerr != nil {
				ttt.Fatalf("read written file: %v", rerr)
			}
			if int64(len(body)) != out.SizeBytes {
				ttt.Errorf("disk size %d != reported SizeBytes %d", len(body), out.SizeBytes)
			}
			if tc.name == "overwrite_existing" && len(body) < 1000 {
				ttt.Errorf("overwrite: expected >1000 bytes after regeneration, got %d", len(body))
			}
			if tc.wantFormat == "xml" {
				if !strings.HasPrefix(strings.TrimSpace(string(body)), "<") {
					ttt.Errorf("xml body does not start with <")
				}
			} else {
				var probe map[string]any
				if jerr := json.Unmarshal(body, &probe); jerr != nil {
					ttt.Errorf("json body invalid: %v", jerr)
				}
			}
		})
	}
}

func TestHandleGenerateSBOM_InlineOptIn(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("inline_happy", func(tt *testing.T) {
		tt.Parallel()
		work := copyFixtureToTemp(tt, fixtureRoot)
		res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, GenSBOMInput{Path: work, Inline: true})
		if err != nil {
			tt.Fatalf("handler: %v", err)
		}
		if res.IsError {
			tt.Fatalf("IsError: %s", extractText(res))
		}
		out, ok := raw.(*GenSBOMOutput)
		if !ok {
			tt.Fatalf("raw type: %T", raw)
		}
		if out.Mode != "inline" {
			tt.Errorf("Mode: got %q want inline", out.Mode)
		}
		if out.SerializedBOM == "" {
			tt.Fatal("SerializedBOM empty")
		}
		if out.OutputPath != "" {
			tt.Errorf("OutputPath: want empty in inline mode, got %q", out.OutputPath)
		}
		if out.SizeBytes != 0 {
			tt.Errorf("SizeBytes: want 0 in inline mode, got %d", out.SizeBytes)
		}
		var probe map[string]any
		if jerr := json.Unmarshal([]byte(out.SerializedBOM), &probe); jerr != nil {
			tt.Fatalf("SerializedBOM not json: %v", jerr)
		}
		if _, sErr := os.Stat(filepath.Join(work, "sbom.json")); !os.IsNotExist(sErr) {
			tt.Errorf("expected no sbom.json in inline mode, stat err=%v", sErr)
		}
	})
}

func TestHandleGenerateSBOM_ErrorTokens(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		name       string
		prep       func(t *testing.T) GenSBOMInput
		wantSubstr string
	}{
		{
			name: "output_path_not_absolute",
			prep: func(tt *testing.T) GenSBOMInput {
				return GenSBOMInput{Path: fixtureRoot, OutputPath: "relative/sbom.json"}
			},
			wantSubstr: "OUTPUT_PATH_NOT_ABSOLUTE",
		},
		{
			name: "output_path_is_directory",
			prep: func(tt *testing.T) GenSBOMInput {
				dir := tt.TempDir()
				return GenSBOMInput{Path: fixtureRoot, OutputPath: dir}
			},
			wantSubstr: "OUTPUT_PATH_IS_DIRECTORY",
		},
		{
			name: "output_path_not_writable",
			prep: func(tt *testing.T) GenSBOMInput {
				return GenSBOMInput{Path: fixtureRoot, OutputPath: "/nonexistent-parent-dir-abc-12345-xyz/sbom.json"}
			},
			wantSubstr: "OUTPUT_PATH_NOT_WRITABLE",
		},
		{
			name: "default_path_not_writable",
			prep: func(tt *testing.T) GenSBOMInput {
				if os.Geteuid() == 0 {
					tt.Skip("cannot simulate read-only directory as root")
				}
				if runtime.GOOS == "windows" {
					tt.Skip("chmod 0o555 does not prevent writes on windows")
				}
				dir := copyFixtureToTemp(tt, fixtureRoot)
				if err := os.Chmod(dir, 0o555); err != nil {
					tt.Fatalf("chmod: %v", err)
				}
				tt.Cleanup(func() {
					if cerr := os.Chmod(dir, 0o755); cerr != nil {
						tt.Logf("restore chmod: %v", cerr)
					}
				})
				return GenSBOMInput{Path: dir}
			},
			wantSubstr: "DEFAULT_PATH_NOT_WRITABLE",
		},
		{
			name: "invalid_fixed_serial",
			prep: func(tt *testing.T) GenSBOMInput {
				return GenSBOMInput{Path: fixtureRoot, FixedSerial: "not-a-uuid"}
			},
			wantSubstr: "INVALID_FIXED_SERIAL",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(ttt *testing.T) {
			ttt.Parallel()
			input := tc.prep(ttt)
			res, _, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, input)
			if err != nil {
				ttt.Fatalf("handler: %v", err)
			}
			if !res.IsError {
				ttt.Fatalf("expected IsError=true")
			}
			text := extractText(res)
			if !strings.Contains(text, tc.wantSubstr) {
				ttt.Errorf("error text: got %q want substring %q", text, tc.wantSubstr)
			}
		})
	}
}

func copyFixtureToTemp(t *testing.T, fixtureRoot string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		src := filepath.Join(fixtureRoot, name)
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dst
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

func TestHandleGenerateSBOM_FixedSerial_Reproducibility(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	const fixedUUID = "550e8400-e29b-41d4-a716-446655440000"
	const wantSerial = "urn:uuid:550e8400-e29b-41d4-a716-446655440000"

	run := func(tt *testing.T) string {
		res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, GenSBOMInput{
			Path:        fixtureRoot,
			Inline:      true,
			FixedSerial: fixedUUID,
			NoTimestamp: true,
		})
		if err != nil {
			tt.Fatalf("handler: %v", err)
		}
		if res.IsError {
			tt.Fatalf("IsError: %s", extractText(res))
		}
		out, ok := raw.(*GenSBOMOutput)
		if !ok {
			tt.Fatalf("raw type: %T", raw)
		}
		var probe map[string]any
		if jerr := json.Unmarshal([]byte(out.SerializedBOM), &probe); jerr != nil {
			tt.Fatalf("re-parse: %v", jerr)
		}
		serial, _ := probe["serialNumber"].(string)
		if serial != wantSerial {
			tt.Errorf("serialNumber: got %q want %q", serial, wantSerial)
		}
		if md, ok := probe["metadata"].(map[string]any); ok {
			if ts, present := md["timestamp"]; present && ts != "" {
				tt.Errorf("metadata.timestamp: want absent/empty under no_timestamp=true, got %v", ts)
			}
		}
		return out.SerializedBOM
	}

	a := run(t)
	b := run(t)
	var pa, pb map[string]any
	if err := json.Unmarshal([]byte(a), &pa); err != nil {
		t.Fatalf("parse a: %v", err)
	}
	if err := json.Unmarshal([]byte(b), &pb); err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if pa["serialNumber"] != pb["serialNumber"] {
		t.Errorf("two runs with same fixed_serial diverge on serialNumber: %v vs %v", pa["serialNumber"], pb["serialNumber"])
	}
}

func TestHandleGenerateSBOM_FixedSerial_URN(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	res, raw, err := HandleGenerateSBOM(context.Background(), &mcp.CallToolRequest{}, GenSBOMInput{
		Path:        fixtureRoot,
		Inline:      true,
		FixedSerial: "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError: %s", extractText(res))
	}
	out, ok := raw.(*GenSBOMOutput)
	if !ok {
		t.Fatalf("raw type: %T", raw)
	}
	var probe map[string]any
	if jerr := json.Unmarshal([]byte(out.SerializedBOM), &probe); jerr != nil {
		t.Fatalf("re-parse: %v", jerr)
	}
	if got, _ := probe["serialNumber"].(string); got != "urn:uuid:550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("serialNumber: got %q want urn:uuid:550e8400-...", got)
	}
}
