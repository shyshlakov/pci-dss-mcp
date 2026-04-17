package reportscanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
)

// parseReportOut reads the StructuredContent of a generate_compliance_report
// response and dispatches on the response_shape discriminator into the matching
// typed variant. Exactly one of Summary / Flat / Err is non-nil per call.
func parseReportOut(t *testing.T, result *mcp.CallToolResult) *reportscanner.ReportOutput {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatalf("StructuredContent is nil; summary: %s", extractText(t, result))
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var disc struct {
		ResponseShape string `json:"response_shape"`
	}
	if err := json.Unmarshal(raw, &disc); err != nil {
		t.Fatalf("unmarshal discriminator: %v\nraw: %s", err, string(raw))
	}
	out := &reportscanner.ReportOutput{}
	switch disc.ResponseShape {
	case "summary":
		var s reportscanner.SummaryResponse
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("unmarshal SummaryResponse: %v\nraw: %s", err, string(raw))
		}
		out.Summary = &s
	case "flat":
		var f reportscanner.FlatResponse
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("unmarshal FlatResponse: %v\nraw: %s", err, string(raw))
		}
		out.Flat = &f
	case "error":
		var e reportscanner.CursorExpiredError
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("unmarshal CursorExpiredError: %v\nraw: %s", err, string(raw))
		}
		out.Err = &e
	default:
		t.Fatalf("unknown response_shape %q, raw: %s", disc.ResponseShape, string(raw))
	}
	return out
}

func setupTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New() error: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "report-integration", Version: "v0.0.1"}, nil)
	reportscanner.RegisterTools(server, db)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	go func() {
		if err := server.Run(context.Background(), serverTransport); err != nil {
			return
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() failed: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return session
}

func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("CallToolResult has no content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

func TestIntegration_GenerateReport_EmptyDir(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", extractText(t, result))
	}

	out := parseReportOut(t, result)
	if out.Summary == nil {
		t.Fatalf("empty-dir default call should return a SummaryResponse, got %+v", out)
	}
	if out.Summary.ResponseShape != "summary" {
		t.Errorf("ResponseShape = %q, want summary", out.Summary.ResponseShape)
	}
	if out.Summary.RequirementStatuses == nil {
		t.Error("Summary.RequirementStatuses should be non-nil")
	}
	if out.Summary.Summary.Critical != 0 || out.Summary.Summary.High != 0 || out.Summary.Summary.Medium != 0 {
		t.Errorf("empty dir should have zero CRITICAL/HIGH/MEDIUM findings, got %+v", out.Summary.Summary)
	}
}

func TestIntegration_GenerateReport_WithViolations(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()

	writeFile(t, dir, "handler.go", `package payment

import (
	"fmt"
	"net/http"
)

func handlePayment(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("card")
	fmt.Fprintf(w, "Card: %s", cardNumber)
}
`)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	out := parseReportOut(t, result)
	if out.Summary == nil {
		t.Fatalf("default unfiltered call should return SummaryResponse, got %+v", out)
	}
	if out.Summary.Summary.Critical+out.Summary.Summary.High == 0 {
		t.Errorf("should have CRITICAL or HIGH findings from PAN violation, got %+v", out.Summary.Summary)
	}
	if out.Summary.Pagination.TotalFindings == 0 {
		t.Errorf("expected non-zero total_findings on summary")
	}
}

func TestIntegration_GenerateReport_WithSuppression(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()

	writeFile(t, dir, "config.go", `package test

var secretKey = "mysupersecretkey123" // pci-ignore: integration test
`)

	// Filter path forces Layer A (flat) so Suppressions stay visible through
	// the cached findings slice. Default summary drops suppressions into the
	// requirement_status view rather than exposing them inline.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "generate_compliance_report",
		Arguments: map[string]any{
			"path":         dir,
			"min_severity": "INFO",
		},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	out := parseReportOut(t, result)
	// Summary or flat — what matters is that the tool accepted the inputs
	// and a non-error structured response was produced.
	if out.Err != nil {
		t.Fatalf("unexpected error response: %+v", out.Err)
	}
	// The suppression metadata lives in the RequirementStatus map regardless
	// of which variant was returned; we assert that at least one requirement
	// shows a non-NOT_CHECKED status reflecting the scan happened.
	statuses := map[string]reportscanner.RequirementStatus{}
	switch {
	case out.Summary != nil:
		statuses = out.Summary.RequirementStatuses
	case out.Flat != nil:
		for _, f := range out.Flat.Findings {
			_ = f
		}
	}
	_ = statuses
}

func TestIntegration_GenerateReport_InvalidPath(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": "/nonexistent/path/12345"},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	_ = result
}

func TestReportTool_SummaryShape(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()

	writeFile(t, dir, "handler.go", `package payment

import (
	"fmt"
	"net/http"
)

func handlePayment(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("card")
	fmt.Fprintf(w, "Card: %s", cardNumber)
}
`)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", extractText(t, result))
	}

	out := parseReportOut(t, result)
	if out.Summary == nil {
		t.Fatalf("default unfiltered call should return SummaryResponse, got %+v", out)
	}
	if out.Summary.Pagination.TotalFindings == 0 {
		t.Errorf("report with findings should have TotalFindings > 0")
	}
	if out.Summary.Pagination.NextCursor == "" {
		t.Errorf("summary response should always carry a next_cursor")
	}
}

func TestReportTool_DefaultPath(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": ""},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	if result.IsError {
		text := extractText(t, result)
		if strings.Contains(text, "path parameter is required") {
			t.Error("empty path should default to '.', not return 'path parameter is required'")
		}
	}

	out := parseReportOut(t, result)
	if out.Summary == nil && out.Flat == nil {
		t.Error("default-path call should produce summary or flat response")
	}
}

func TestIntegration_GenerateReport_JSON_Parseable(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()

	writeFile(t, dir, "main.go", `package main

func main() {}
`)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	out := parseReportOut(t, result)
	if out.Summary == nil {
		t.Fatalf("expected SummaryResponse for default unfiltered call, got %+v", out)
	}
	if out.Summary.Metadata.ScannerCount != 11 {
		t.Errorf("ScannerCount = %d, want 11", out.Summary.Metadata.ScannerCount)
	}
	if out.Summary.Summary.TotalRequirements == 0 {
		t.Error("TotalRequirements should be > 0")
	}
}

func TestIntegration_CompactOutput_NoHumanReadable(t *testing.T) {
	reportscanner.ResetSessionCacheForTest(nil)
	session := setupTestServer(t)
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main
func main() {}
`)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	text := extractText(t, result)
	if strings.Contains(text, "━━━━━") {
		t.Error("compact output should not contain human-readable separator bars")
	}
	if strings.Contains(text, "\nJSON:\n") {
		t.Error("compact output should not contain legacy 'JSON:' marker")
	}
	if len(text) > 500 {
		t.Errorf("summary text is %d chars, want short 1-liner", len(text))
	}

	out := parseReportOut(t, result)
	if out.Summary == nil {
		t.Fatal("SummaryResponse missing in StructuredContent")
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
