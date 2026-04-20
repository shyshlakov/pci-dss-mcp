package panscanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// TestPANScannerInterface verifies PANScanner implements scanner.Scanner.
func TestPANScannerInterface(t *testing.T) {
	var _ scanner.Scanner = (*PANScanner)(nil)
}

func TestPANScannerName(t *testing.T) {
	s := New()
	if s.Name() != "pan_data" {
		t.Errorf("Name() = %q, want %q", s.Name(), "pan_data")
	}
}

func TestPANScannerDescription(t *testing.T) {
	s := New()
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPANScannerRequirements(t *testing.T) {
	s := New()
	reqs := s.Requirements()
	want := map[string]bool{"3.3.1": true, "3.4.1": true, "3.5.1": true}
	if len(reqs) != len(want) {
		t.Fatalf("Requirements() returned %d items, want %d", len(reqs), len(want))
	}
	for _, r := range reqs {
		if !want[r] {
			t.Errorf("unexpected requirement %q", r)
		}
	}
}

// writeGoTemp writes a Go source file to a temp directory and returns the dir path.
func writeGoTemp(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --- PAN-KEYWORD: Struct field with payment context siblings -> CRITICAL ---
func TestStructFieldWithPaymentContext(t *testing.T) {
	src := `package test

type PaymentRequest struct {
	CVV      string
	Amount   float64
	Currency string
}
`
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	// Should find PAN-KEYWORD finding for CVV with CRITICAL severity (HIGH confidence, >= 2 payment indicators)
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" && f.Severity == scanner.SeverityCritical &&
			strings.Contains(strings.ToLower(f.Description), "cvv") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CRITICAL PAN-KEYWORD finding for CVV in payment context, got findings: %+v", result.Findings)
	}
}

// --- PAN-KEYWORD: Struct field without payment context -> HIGH ---
func TestStructFieldWithoutPaymentContext(t *testing.T) {
	src := `package test

type Config struct {
	CVV    string
	Name   string
	Active bool
}
`
	dir := writeGoTemp(t, "config.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	// Should find PAN-KEYWORD finding for CVV with HIGH severity (LOW confidence)
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" && f.Severity == scanner.SeverityHigh &&
			strings.Contains(strings.ToLower(f.Description), "manual review") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected HIGH PAN-KEYWORD finding with 'manual review' for CVV without payment context, got findings: %+v", result.Findings)
	}
}

// --- PAN-KEYWORD removed from function params per ---
// Function params like `cvv string` should NOT produce PAN-KEYWORD findings.
// Only PAN-TYPE (string vs []byte) should still be emitted.
func TestFuncParamNoPANKeyword(t *testing.T) {
	src := `package test

func ProcessPayment(cvv string, amount float64, currency string) {}
`
	dir := writeGoTemp(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	// PAN-KEYWORD should NOT be emitted for function params.
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			t.Errorf("expected no PAN-KEYWORD finding for function param, got: %+v", f)
		}
	}
	// PAN-TYPE should still be emitted with MEDIUM severity for string-typed sensitive params.
	var foundType bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" && f.Severity == scanner.SeverityMedium {
			foundType = true
			break
		}
	}
	if !foundType {
		t.Errorf("expected MEDIUM PAN-TYPE finding for cvv string param, got findings: %+v", result.Findings)
	}
}

// --- PAN-TYPE: string type for sensitive field -> MEDIUM ---
func TestStringTypeForSensitiveField(t *testing.T) {
	src := `package test

type Card struct {
	CVV    string
	Amount float64
}
`
	dir := writeGoTemp(t, "card.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" && f.Severity == scanner.SeverityMedium &&
			strings.Contains(f.Description, "immutable strings cannot be zeroed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MEDIUM PAN-TYPE finding for CVV as string, got findings: %+v", result.Findings)
	}
}

// --- PAN-TYPE: []byte type for sensitive field -> no PAN-TYPE finding ---
func TestByteSliceTypeNoFinding(t *testing.T) {
	src := `package test

type Card struct {
	CVV    []byte
	Amount float64
}
`
	dir := writeGoTemp(t, "card.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" {
			t.Errorf("expected no PAN-TYPE finding for CVV as []byte, but got: %+v", f)
		}
	}
}

// --- PAN-KEYWORD: local variable should NOT produce PAN-KEYWORD ---
func TestLocalVarNoPANKeyword(t *testing.T) {
	src := `package test

func process() {
	cardNumber := getCard()
	_ = cardNumber
}

func getCard() string { return "" }
`
	dir := writeGoTemp(t, "local.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			t.Errorf("expected no PAN-KEYWORD finding for local variable, got: %+v", f)
		}
	}
}

// --- PAN-KEYWORD: struct field still produces PAN-KEYWORD (preserves struct fields) ---
func TestStructFieldStillProducesPANKeyword(t *testing.T) {
	src := `package test

type Payment struct {
	CardNumber string
	Amount     float64
}
`
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" && strings.Contains(strings.ToLower(f.Description), "cardnumber") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PAN-KEYWORD finding for struct field CardNumber, got findings: %+v", result.Findings)
	}
}

// --- PAN-ZEROING: []byte field without zeroing -> MEDIUM ---
func TestMissingZeroingLoop(t *testing.T) {
	src := `package test

func process() {
	cvv := []byte("123")
	_ = cvv
}
`
	dir := writeGoTemp(t, "process.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-ZEROING" && f.Severity == scanner.SeverityMedium {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MEDIUM PAN-ZEROING finding for missing zeroing loop, got findings: %+v", result.Findings)
	}
}

// --- PAN-ZEROING: []byte field WITH zeroing loop -> no finding ---
func TestZeroingLoopPresent(t *testing.T) {
	src := `package test

func process() {
	cvv := []byte("123")
	// Use the data...
	for i := range cvv {
		cvv[i] = 0
	}
}
`
	dir := writeGoTemp(t, "process.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "PAN-ZEROING" {
			t.Errorf("expected no PAN-ZEROING finding when zeroing loop present, but got: %+v", f)
		}
	}
}

// --- PAN-ZEROING: []byte field WITH clear() -> no finding ---
func TestClearCallPresent(t *testing.T) {
	src := `package test

func process() {
	cvv := []byte("123")
	// Use the data...
	clear(cvv)
}
`
	dir := writeGoTemp(t, "process.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "PAN-ZEROING" {
			t.Errorf("expected no PAN-ZEROING finding when clear() present, but got: %+v", f)
		}
	}
}

// --- PAN-LITERAL: Luhn+IIN string literal -> MEDIUM ---
func TestStringLiteralPAN(t *testing.T) {
	src := `package test

var data = "4111111111111111"
`
	dir := writeGoTemp(t, "data.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LITERAL" && f.Severity == scanner.SeverityMedium &&
			strings.Contains(f.Description, "manual review") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MEDIUM PAN-LITERAL finding for Luhn-valid string literal, got findings: %+v", result.Findings)
	}
}

// --- PAN-LITERAL: string literal assigned to keyword-named variable -> CRITICAL ---
func TestStringLiteralNearKeyword(t *testing.T) {
	src := `package test

var cardNumber = "4111111111111111"
`
	dir := writeGoTemp(t, "data.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LITERAL" && f.Severity == scanner.SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CRITICAL PAN-LITERAL finding for PAN assigned to keyword-named variable, got findings: %+v", result.Findings)
	}
}

// --- PAN-LOGGER: fmt.Printf with sensitive arg -> CRITICAL ---
func TestLoggerWithSensitiveArg(t *testing.T) {
	src := `package test

import "fmt"

func logCard(cardNumber string) {
	fmt.Printf("card: %s", cardNumber)
}
`
	dir := writeGoTemp(t, "logger.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LOGGER" && f.Severity == scanner.SeverityCritical &&
			f.RequirementID == "3.3.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CRITICAL PAN-LOGGER finding for sensitive arg in fmt.Printf, got findings: %+v", result.Findings)
	}
}

// --- PAN-LOGGER: slog.Info with sensitive arg -> CRITICAL ---
func TestSlogLoggerWithSensitiveArg(t *testing.T) {
	src := `package test

import "log/slog"

func logCard(cvv string) {
	slog.Info("processing", "cvv", cvv)
}
`
	dir := writeGoTemp(t, "slogger.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LOGGER" && f.Severity == scanner.SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CRITICAL PAN-LOGGER finding for sensitive arg in slog.Info, got findings: %+v", result.Findings)
	}
}

// --- Test auto-suppression: testCardNumber top-level var no longer produces PAN-KEYWORD ---
// After, PAN-KEYWORD only fires on struct fields. Top-level vars are excluded.
// The PAN-LITERAL finding for the Luhn-valid string literal should still be present.
func TestAutoSuppression(t *testing.T) {
	src := `package test

var testCardNumber = "4111111111111111"
`
	dir := writeGoTemp(t, "test_data.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	// PAN-KEYWORD should NOT be emitted for top-level vars after.
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			t.Errorf("expected no PAN-KEYWORD for top-level var after, got: %+v", f)
		}
	}
	// PAN-LITERAL should still detect the Luhn-valid string.
	var foundLiteral bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LITERAL" {
			foundLiteral = true
			break
		}
	}
	if !foundLiteral {
		t.Errorf("expected PAN-LITERAL finding for Luhn-valid string, got findings: %+v", result.Findings)
	}
}

// --- Generated file -> 0 findings ---
func TestGeneratedFileSkipped(t *testing.T) {
	src := `// Code generated by foo; DO NOT EDIT.

package test

var cardNumber = "4111111111111111"
`
	dir := writeGoTemp(t, "generated.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for generated file, got %d: %+v", len(result.Findings), result.Findings)
	}
}

// --- JSON tag with sensitive name -> detected ---
func TestJSONTagSensitiveName(t *testing.T) {
	src := "package test\n\ntype Response struct {\n\tData string `json:\"card_number\"`\n}\n"
	dir := writeGoTemp(t, "response.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" && strings.Contains(f.Description, "json tag") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PAN-KEYWORD finding for json tag with sensitive name, got findings: %+v", result.Findings)
	}
}

// --- Scan metadata is populated ---
func TestScanMetadata(t *testing.T) {
	src := `package test

var x = 1
`
	dir := writeGoTemp(t, "simple.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.ScannedFiles == 0 {
		t.Error("expected ScannedFiles > 0")
	}
	if result.Metadata.DurationMS < 0 {
		t.Error("expected non-negative DurationMS")
	}
}

// --- Context cancellation ---
func TestScanCancellation(t *testing.T) {
	src := `package test

var cardNumber = "4111111111111111"
`
	dir := writeGoTemp(t, "data.go", src)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	s := New()
	_, err := s.Scan(ctx, dir)
	if err == nil {
		t.Error("expected error from canceled context")
	}
}

// --- FP5-02.: Struct field + json tag deduplication ---

func TestDeduplicateStructFindings_SameKeyword(t *testing.T) {
	// Struct field CVV with json tag "cvv" on same line -> 1 merged finding
	src := "package test\n\ntype Payment struct {\n\tCVV string `json:\"cvv\"`\n\tAmount float64\n}\n"
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	// Count PAN-KEYWORD findings — should be exactly 1 (merged)
	var panKeywordCount int
	var mergedDesc string
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			panKeywordCount++
			mergedDesc = f.Description
		}
	}
	if panKeywordCount != 1 {
		t.Errorf("expected 1 merged PAN-KEYWORD finding for CVV + json:cvv, got %d", panKeywordCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-KEYWORD" {
				t.Logf("  finding: %s", f.Description)
			}
		}
	}

	// Merged description should mention both field and json tag
	if !strings.Contains(mergedDesc, "json:") || !strings.Contains(mergedDesc, "CVV") {
		t.Errorf("merged description should mention field and json tag, got: %s", mergedDesc)
	}
}

func TestDeduplicateStructFindings_CardNumber(t *testing.T) {
	// Struct field CardNumber with json tag "card_number" -> 1 merged finding
	src := "package test\n\ntype Payment struct {\n\tCardNumber string `json:\"card_number\"`\n\tAmount float64\n}\n"
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	var panKeywordCount int
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			panKeywordCount++
		}
	}
	if panKeywordCount != 1 {
		t.Errorf("expected 1 merged PAN-KEYWORD for CardNumber + json:card_number, got %d", panKeywordCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-KEYWORD" {
				t.Logf("  finding: %s", f.Description)
			}
		}
	}
}

func TestDeduplicateStructFindings_DifferentKeywords(t *testing.T) {
	// field CVV with json tag "pan" -> different keywords -> keep 2 findings
	src := "package test\n\ntype Payment struct {\n\tCVV string `json:\"pan\"`\n\tAmount float64\n}\n"
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	var panKeywordCount int
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			panKeywordCount++
		}
	}
	if panKeywordCount != 2 {
		t.Errorf("expected 2 PAN-KEYWORD findings for CVV + json:pan (different keywords), got %d", panKeywordCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-KEYWORD" {
				t.Logf("  finding: %s", f.Description)
			}
		}
	}
}

func TestDeduplicateStructFindings_DifferentLines(t *testing.T) {
	// Fields on different lines -> keep both
	src := "package test\n\ntype Payment struct {\n\tCVV string\n\tPAN string\n\tAmount float64\n}\n"
	dir := writeGoTemp(t, "payment.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	var panKeywordCount int
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			panKeywordCount++
		}
	}
	if panKeywordCount != 2 {
		t.Errorf("expected 2 PAN-KEYWORD findings for CVV and PAN on different lines, got %d", panKeywordCount)
	}
}

// --- FP5-03.: Parameter grouping ---

func TestGroupParameterFindings_SameParam(t *testing.T) {
	// 4 functions with cardNumber string param -> 1 grouped PAN-TYPE finding
	src := `package test

func maskCard(cardNumber string) string { return "" }
func last4(cardNumber string) string { return "" }
func formatPAN(cardNumber string) string { return "" }
func validateCard(cardNumber string) bool { return false }
`
	dir := writeGoTemp(t, "util.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	var panTypeCount int
	var groupedDesc string
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" {
			panTypeCount++
			groupedDesc = f.Description
		}
	}
	if panTypeCount != 1 {
		t.Errorf("expected 1 grouped PAN-TYPE finding for 4x cardNumber param, got %d", panTypeCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-TYPE" {
				t.Logf("  finding: %s", f.Description)
			}
		}
	}

	// Grouped description should mention count
	if !strings.Contains(groupedDesc, "4 functions") {
		t.Errorf("grouped description should mention '4 functions', got: %s", groupedDesc)
	}
}

func TestGroupParameterFindings_DifferentParams(t *testing.T) {
	// 2 functions with cardNumber + 1 with cvv -> 2 grouped findings
	src := `package test

func maskCard(cardNumber string) string { return "" }
func last4(cardNumber string) string { return "" }
func verifyCVV(cvv string) bool { return false }
`
	dir := writeGoTemp(t, "util.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	var panTypeCount int
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" {
			panTypeCount++
		}
	}
	if panTypeCount != 2 {
		t.Errorf("expected 2 PAN-TYPE findings (one per param name), got %d", panTypeCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-TYPE" {
				t.Logf("  finding: %s", f.Description)
			}
		}
	}
}

func TestGroupParameterFindings_DifferentFiles(t *testing.T) {
	// Same param name across different files -> NOT grouped
	dir := t.TempDir()
	src1 := `package test

func maskCard(cardNumber string) string { return "" }
func last4(cardNumber string) string { return "" }
`
	src2 := `package test

func formatPAN(cardNumber string) string { return "" }
func validateCard(cardNumber string) bool { return false }
`
	if err := os.WriteFile(filepath.Join(dir, "util1.go"), []byte(src1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "util2.go"), []byte(src2), 0644); err != nil {
		t.Fatal(err)
	}

	s := New()
	result, err := s.ScanFull(context.Background(), dir, nil, false, true)
	if err != nil {
		t.Fatal(err)
	}

	var panTypeCount int
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" {
			panTypeCount++
		}
	}
	// Should be 2: one grouped per file
	if panTypeCount != 2 {
		t.Errorf("expected 2 PAN-TYPE findings (one per file), got %d", panTypeCount)
		for _, f := range result.Findings {
			if f.RuleID == "PAN-TYPE" {
				t.Logf("  finding: file=%s desc=%s", f.FilePath, f.Description)
			}
		}
	}
}

// --- Non-sensitive variable -> no PAN-KEYWORD finding ---
func TestNonSensitiveVariable(t *testing.T) {
	src := `package test

var userName = "john"
var amount = 42.0
`
	dir := writeGoTemp(t, "clean.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "PAN-KEYWORD" {
			t.Errorf("expected no PAN-KEYWORD findings for non-sensitive variables, got: %+v", f)
		}
	}
}

func TestRuleMatches_Regex(t *testing.T) {
	tt := []struct {
		name   string
		ruleID string
		filter string
		want   bool
	}{
		{"empty filter matches all", "PAN-KEYWORD", "", true},
		{"exact comma list match", "PAN-KEYWORD", "PAN-KEYWORD,PAN-TYPE", true},
		{"exact comma list no match", "PAN-LITERAL", "PAN-KEYWORD,PAN-TYPE", false},
		{"regex slash syntax matches", "PAN-KEYWORD", "/PAN-.*/", true},
		{"regex slash syntax no match", "CRYPTO-WEAK", "/PAN-.*/", false},
		{"regex dot-star", "PAN-TYPE", "/PAN-.*/", true},
		{"invalid regex returns false", "PAN-KEYWORD", "/[invalid/", false},
		{"literal substring does NOT match regex path", "PAN-KEYWORD", "/PAN-.*/", true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleMatches(tc.ruleID, tc.filter)
			if got != tc.want {
				t.Errorf("ruleMatches(%q, %q) = %v, want %v", tc.ruleID, tc.filter, got, tc.want)
			}
		})
	}
}
