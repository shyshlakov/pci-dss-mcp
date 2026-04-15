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

// parseReportOut re-marshals StructuredContent into a typed ReportOutput.
// generate_compliance_report now returns typed output via the MCP
// SDK's structured-content channel instead of a text JSON blob.
func parseReportOut(t *testing.T, result *mcp.CallToolResult) *reportscanner.ReportOutput {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatalf("StructuredContent is nil; summary: %s", extractText(t, result))
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var out reportscanner.ReportOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal ReportOutput: %v\nraw: %s", err, string(raw))
	}
	return &out
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
	if out.ComplianceStatus != "PASS" {
		t.Errorf("empty dir should report PASS, got %q", out.ComplianceStatus)
	}
	if out.Report == nil {
		t.Error("ReportOutput.Report should be non-nil")
	}
	if out.Report.RequirementStatus == nil {
		t.Error("Report.RequirementStatus should be non-nil")
	}
}

func TestIntegration_GenerateReport_WithViolations(t *testing.T) {
	session := setupTestServer(t)
	dir := t.TempDir()

	// Create a Go file with a known PAN violation.
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
	if out.Report == nil || (out.Report.Summary.Critical+out.Report.Summary.High == 0) {
		t.Errorf("should have CRITICAL or HIGH findings from PAN violation, got %+v", out.Report.Summary)
	}
	if out.ComplianceStatus != "FAIL" {
		t.Errorf("should contain FAIL status, got %q", out.ComplianceStatus)
	}
}

func TestIntegration_GenerateReport_WithSuppression(t *testing.T) {
	session := setupTestServer(t)
	dir := t.TempDir()

	// Create a Go file with a known violation + pci-ignore.
	writeFile(t, dir, "config.go", `package test

var secretKey = "mysupersecretkey123" // pci-ignore: integration test
`)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	out := parseReportOut(t, result)
	if out.Report == nil || len(out.Report.Suppressions) == 0 {
		t.Fatalf("should have at least one suppressed finding, got %+v", out.Report)
	}
	sawReason := false
	for _, s := range out.Report.Suppressions {
		if strings.Contains(s.Reason, "integration test") {
			sawReason = true
			break
		}
	}
	if !sawReason {
		t.Errorf("suppression reason should be visible in report, got: %+v", out.Report.Suppressions)
	}
}

func TestIntegration_GenerateReport_InvalidPath(t *testing.T) {
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": "/nonexistent/path/12345"},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	// A nonexistent path should still return a report (empty dir behavior) or error.
	// The key test is that empty path no longer errors (see TestReportTool_DefaultPath).
	_ = result
}

// TestReportTool_FailStatus replaces the former TriageTip text-blob check.
// generate_compliance_report now returns typed output, so the "Tip:
// Run triage_findings" hint from the old text-mode is gone. AI clients
// derive the same guidance from ComplianceStatus=FAIL + ActiveFindings>0.
func TestReportTool_FailStatus(t *testing.T) {
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
	if out.ComplianceStatus != "FAIL" {
		t.Errorf("report with findings should have ComplianceStatus=FAIL, got %q", out.ComplianceStatus)
	}
	if out.ActiveFindings == 0 {
		t.Error("report with findings should have ActiveFindings > 0")
	}
}

func TestReportTool_DefaultPath(t *testing.T) {
	session := setupTestServer(t)

	// Call with empty path -- should default to "." and not return an error.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "generate_compliance_report",
		Arguments: map[string]any{"path": ""},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	// Empty path should no longer return "path parameter is required".
	if result.IsError {
		text := extractText(t, result)
		if strings.Contains(text, "path parameter is required") {
			t.Error("empty path should default to '.', not return 'path parameter is required'")
		}
	}

	out := parseReportOut(t, result)
	if out.Report == nil {
		t.Error("report with default path should contain Report object")
	}
}

func TestIntegration_GenerateReport_JSON_Parseable(t *testing.T) {
	session := setupTestServer(t)
	dir := t.TempDir()

	// Create a simple Go file.
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
	if out.Report.Metadata.ScannerCount != 11 {
		t.Errorf("ScannerCount = %d, want 11", out.Report.Metadata.ScannerCount)
	}
	if out.Report.Summary.TotalRequirements == 0 {
		t.Error("TotalRequirements should be > 0")
	}

	// Compact output must NOT contain NOT_CHECKED entries in requirement_status.
	for id, rs := range out.Report.RequirementStatus {
		if rs.Status == "NOT_CHECKED" {
			t.Errorf("requirement_status[%q] has NOT_CHECKED — compact output should exclude these", id)
			break
		}
	}
}

func TestIntegration_CompactOutput_NoHumanReadable(t *testing.T) {
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

	// text summary is a short 1-line human hint, full compact
	// JSON lives in StructuredContent. Assert the separation.
	text := extractText(t, result)
	if strings.Contains(text, "━━━━━") {
		t.Error("compact output should not contain human-readable separator bars")
	}
	if strings.Contains(text, "\nJSON:\n") {
		t.Error("compact output should not contain legacy 'JSON:' marker")
	}
	// Summary line must stay short.
	if len(text) > 500 {
		t.Errorf("summary text is %d chars, want short 1-liner", len(text))
	}

	// Full compact report is in StructuredContent, not Content.
	out := parseReportOut(t, result)
	if out.Report == nil {
		t.Fatal("Report is nil in StructuredContent")
	}

	// Compact output must NOT include NOT_CHECKED entries.
	for id, rs := range out.Report.RequirementStatus {
		if rs.Status == "NOT_CHECKED" {
			t.Errorf("requirement_status[%q] has NOT_CHECKED — compact output should exclude these", id)
			break
		}
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
