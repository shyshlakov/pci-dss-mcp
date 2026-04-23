package auditscanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// parseTestFixture parses a testdata file and returns the named function's body,
// the file's import aliases, and the same-file function map.
func parseTestFixture(t *testing.T, filename, funcName string) (*ast.BlockStmt, map[string]string, map[string]*ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", filename, err)
	}

	// Build import alias map: alias -> import path.
	aliases := make(map[string]string)
	for _, imp := range f.Imports {
		importPath := imp.Path.Value[1 : len(imp.Path.Value)-1] // strip quotes
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			alias = filepath.Base(importPath)
		}
		aliases[alias] = importPath
	}

	// Build same-file function map.
	localFuncs := sameFileFuncs(f)

	// Find the target function.
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}
		if fn.Name.Name == funcName {
			return fn.Body, aliases, localFuncs
		}
	}

	t.Fatalf("function %q not found in %s", funcName, filename)
	return nil, nil, nil
}

func TestExtractFieldsFromBody_Logrus(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	fixture := filepath.Join(dir, "logfields_logrus.go")
	body, aliases, localFuncs := parseTestFixture(t, fixture, "EnrichLogger")

	// Build a constResolver that resolves local constants in the test fixture.
	constResolver := func(pkgAlias, constName string) string {
		// For local constants (no package alias), resolve in the fixture directory.
		if pkgAlias == "" {
			return resolveConstantInPackage(dir, constName)
		}
		return ""
	}

	fields := extractFieldsFromBody(body, aliases, localFuncs, constResolver, false)
	sort.Strings(fields)

	expected := []string{"elapsed", "http.status", "ip", "request_id", "url", "version"}
	sort.Strings(expected)

	if len(fields) != len(expected) {
		t.Fatalf("expected %d fields %v, got %d fields %v", len(expected), expected, len(fields), fields)
	}
	for i, f := range fields {
		if f != expected[i] {
			t.Errorf("field[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestExtractFieldsFromBody_Slog(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	fixture := filepath.Join(dir, "logfields_slog.go")

	// The function is inside an http.HandlerFunc literal, so we need to find it.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fixture, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	aliases := make(map[string]string)
	for _, imp := range f.Imports {
		importPath := imp.Path.Value[1 : len(imp.Path.Value)-1]
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			alias = filepath.Base(importPath)
		}
		aliases[alias] = importPath
	}

	// Find LogMiddleware function body.
	body, _, localFuncs := parseTestFixture(t, fixture, "LogMiddleware")

	noopResolver := func(pkgAlias, constName string) string { return "" }
	fields := extractFieldsFromBody(body, aliases, localFuncs, noopResolver, false)
	sort.Strings(fields)

	expected := []string{"event", "metadata", "status", "user_id"}
	sort.Strings(expected)

	if len(fields) != len(expected) {
		t.Fatalf("expected %d fields %v, got %d fields %v", len(expected), expected, len(fields), fields)
	}
	for i, f := range fields {
		if f != expected[i] {
			t.Errorf("field[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestExtractFieldsFromBody_Zap(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	fixture := filepath.Join(dir, "logfields_zap.go")
	body, aliases, localFuncs := parseTestFixture(t, fixture, "ZapMiddleware")

	noopResolver := func(pkgAlias, constName string) string { return "" }
	fields := extractFieldsFromBody(body, aliases, localFuncs, noopResolver, false)
	sort.Strings(fields)

	expected := []string{"error", "latency", "status_code", "user_id"}
	sort.Strings(expected)

	if len(fields) != len(expected) {
		t.Fatalf("expected %d fields %v, got %d fields %v", len(expected), expected, len(fields), fields)
	}
	for i, f := range fields {
		if f != expected[i] {
			t.Errorf("field[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestExtractFieldsFromBody_Zerolog(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	fixture := filepath.Join(dir, "logfields_zerolog.go")
	body, aliases, localFuncs := parseTestFixture(t, fixture, "ZerologMiddleware")

	noopResolver := func(pkgAlias, constName string) string { return "" }
	fields := extractFieldsFromBody(body, aliases, localFuncs, noopResolver, false)
	sort.Strings(fields)

	expected := []string{"elapsed", "error", "request_id", "status"}
	sort.Strings(expected)

	if len(fields) != len(expected) {
		t.Fatalf("expected %d fields %v, got %d fields %v", len(expected), expected, len(fields), fields)
	}
	for i, f := range fields {
		if f != expected[i] {
			t.Errorf("field[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestResolveConstantInPackage(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	constDir := filepath.Join(dir, "logfields_const")

	tests := []struct {
		name      string
		constName string
		want      string
	}{
		{"resolve request_id", "LogKeyRequestID", "request_id"},
		{"resolve ip", "LogKeyIP", "ip"},
		{"resolve url", "LogKeyURL", "url"},
		{"resolve http.method", "LogKeyHTTPMethod", "http.method"},
		{"resolve http.status", "LogKeyHTTPStatus", "http.status"},
		{"non-existent constant", "NonExistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveConstantInPackage(constDir, tt.constName)
			if got != tt.want {
				t.Errorf("resolveConstantInPackage(%q) = %q, want %q", tt.constName, got, tt.want)
			}
		})
	}
}

func TestExtractLogFields_LocalHelper(t *testing.T) {
	t.Parallel()
	dir := testdataDir()
	fixture := filepath.Join(dir, "logfields_logrus.go")

	// Parse the fixture to get imports for ExtractLogFields.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fixture, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	aliases := make(map[string]string)
	for _, imp := range f.Imports {
		importPath := imp.Path.Value[1 : len(imp.Path.Value)-1]
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			alias = filepath.Base(importPath)
		}
		aliases[alias] = importPath
	}

	fields := ExtractLogFields(dir, "EnrichLogger", aliases)

	// "version" comes from withExtraFields helper — must be present.
	found := false
	for _, f := range fields {
		if f == "version" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected field 'version' from local helper withExtraFields, got %v", fields)
	}
}

func TestExtractLogFields_GracefulDegradation(t *testing.T) {
	t.Parallel()
	fields := ExtractLogFields("/nonexistent/path/that/does/not/exist", "SomeFunc", nil)
	if fields != nil {
		t.Errorf("expected nil for non-existent directory, got %v", fields)
	}
}

// ----------: PCI DSS Field Matching, Scoring, Severity ----------

func TestNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"http.status", "httpstatus"},
		{"user_id", "userid"},
		{"user-agent", "useragent"},
		{"HTTP_STATUS", "httpstatus"},
		{"timestamp", "timestamp"},
		{"event.type", "eventtype"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalize(tt.input)
			if got != tt.want {
				t.Errorf("normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchPCIDSSFields_LogrusHTTPMiddleware(t *testing.T) {
	t.Parallel()
	// Fields: request_id, version, url, ip, user-agent, referer, elapsed, http.method, http.status
	// + logrus import -> auto-timestamp
	// Expected: 3/5 — timestamp(auto-logrus), event_type(url, http.method), outcome(http.status)
	// Missing: user_identification, affected_resource
	fields := []string{"request_id", "version", "url", "ip", "user-agent", "referer", "elapsed", "http.method", "http.status"}
	imports := map[string]string{"logrus": "github.com/sirupsen/logrus"}

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if result.Score != 3 {
		t.Errorf("expected score 3, got %d", result.Score)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if !result.TimestampAuto {
		t.Error("expected TimestampAuto=true for logrus import")
	}

	// Check matched categories.
	if _, ok := result.MatchedCategories["timestamp"]; !ok {
		t.Error("expected 'timestamp' in matched categories")
	}
	if _, ok := result.MatchedCategories["event_type"]; !ok {
		t.Error("expected 'event_type' in matched categories")
	}
	if _, ok := result.MatchedCategories["outcome"]; !ok {
		t.Error("expected 'outcome' in matched categories")
	}

	// Check missing categories.
	missingSet := make(map[string]bool)
	for _, m := range result.MissingCategories {
		missingSet[m] = true
	}
	if !missingSet["user_identification"] {
		t.Error("expected 'user_identification' in missing categories")
	}
	if !missingSet["affected_resource"] {
		t.Error("expected 'affected_resource' in missing categories")
	}

	// severity should be INFO for 3/5.
	sev := ScoreSeverity(result.Score)
	if sev != "INFO" {
		t.Errorf("expected INFO severity for 3/5, got %s", sev)
	}
}

func TestMatchPCIDSSFields_AllMatched(t *testing.T) {
	t.Parallel()
	fields := []string{"user_id", "timestamp", "action", "status", "resource"}
	imports := map[string]string{} // no auto-timestamp needed

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if result.Score != 5 {
		t.Errorf("expected score 5, got %d", result.Score)
	}
	if len(result.MissingCategories) != 0 {
		t.Errorf("expected no missing categories, got %v", result.MissingCategories)
	}
}

func TestMatchPCIDSSFields_OverlapRule(t *testing.T) {
	t.Parallel()
	// "path" matches BOTH event_type AND affected_resource.
	// "url" matches event_type only. "path" is in both category alias lists.
	fields := []string{"url", "path"}
	imports := map[string]string{"logrus": "github.com/sirupsen/logrus"} // auto-timestamp

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if result.Score != 3 {
		t.Errorf("expected score 3 (timestamp+event_type+affected_resource), got %d", result.Score)
	}

	if _, ok := result.MatchedCategories["event_type"]; !ok {
		t.Error("expected 'event_type' matched via 'url'/'path'")
	}
	if _, ok := result.MatchedCategories["affected_resource"]; !ok {
		t.Error("expected 'affected_resource' matched via 'path'")
	}
}

func TestMatchPCIDSSFields_NoMatch_Slog(t *testing.T) {
	t.Parallel()
	// slog does NOT auto-inject timestamp.
	fields := []string{"foo", "bar", "baz"}
	imports := map[string]string{"slog": "log/slog"}

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
	if result.TimestampAuto {
		t.Error("expected TimestampAuto=false for slog import")
	}
}

func TestMatchPCIDSSFields_SlogNotAutoTimestamp(t *testing.T) {
	t.Parallel()
	// locked: slog does NOT auto-inject timestamp.
	fields := []string{"user_id", "action"}
	imports := map[string]string{"slog": "log/slog"}

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if result.TimestampAuto {
		t.Error("slog should NOT auto-inject timestamp")
	}
	// Only user_identification + event_type = 2/5.
	if result.Score != 2 {
		t.Errorf("expected score 2 (user_identification + event_type), got %d", result.Score)
	}
}

func TestMatchPCIDSSFields_ZapAutoTimestamp(t *testing.T) {
	t.Parallel()
	fields := []string{"user_id"}
	imports := map[string]string{"zap": "go.uber.org/zap"}

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if !result.TimestampAuto {
		t.Error("expected TimestampAuto=true for zap import")
	}
}

func TestMatchPCIDSSFields_ZerologAutoTimestamp(t *testing.T) {
	t.Parallel()
	fields := []string{"user_id"}
	imports := map[string]string{"zerolog": "github.com/rs/zerolog"}

	result := MatchPCIDSSFields(fields, imports)
	if result == nil {
		t.Fatal("MatchPCIDSSFields returned nil")
	}

	if !result.TimestampAuto {
		t.Error("expected TimestampAuto=true for zerolog import")
	}
}

func TestScoreSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		matched int
		want    string
	}{
		{5, "INFO"},
		{4, "INFO"},
		{3, "INFO"},
		{2, "MEDIUM"},
		{1, "MEDIUM"},
		{0, "HIGH"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("matched=%d", tt.matched), func(t *testing.T) {
			got := ScoreSeverity(tt.matched)
			if string(got) != tt.want {
				t.Errorf("ScoreSeverity(%d) = %q, want %q", tt.matched, got, tt.want)
			}
		})
	}
}

func TestFormatFieldCoverage(t *testing.T) {
	t.Parallel()
	result := &FieldCoverageResult{
		Score: 3,
		Total: 5,
		MatchedCategories: map[string][]string{
			"timestamp":  {"auto-logrus"},
			"event_type": {"url", "http.method"},
			"outcome":    {"http.status"},
		},
		MissingCategories: []string{"user_identification", "affected_resource"},
		TimestampAuto:     true,
	}

	desc, sugg := FormatFieldCoverage("CreateToken", result)

	if !strings.Contains(desc, "3/5") {
		t.Errorf("description should contain '3/5', got: %s", desc)
	}
	if !strings.Contains(desc, "Found:") {
		t.Errorf("description should contain 'Found:', got: %s", desc)
	}
	if !strings.Contains(desc, "Missing:") {
		t.Errorf("description should contain 'Missing:', got: %s", desc)
	}
	if !strings.Contains(desc, "user_identification") {
		t.Errorf("description should mention 'user_identification', got: %s", desc)
	}
	if !strings.Contains(desc, "affected_resource") {
		t.Errorf("description should mention 'affected_resource', got: %s", desc)
	}
	if sugg == "" {
		t.Error("suggestion should not be empty")
	}
}

func TestFormatFieldCoverage_FullCoverage(t *testing.T) {
	t.Parallel()
	result := &FieldCoverageResult{
		Score: 5,
		Total: 5,
		MatchedCategories: map[string][]string{
			"user_identification": {"user_id"},
			"timestamp":           {"auto-zap"},
			"event_type":          {"action"},
			"outcome":             {"status"},
			"affected_resource":   {"resource"},
		},
		MissingCategories: nil,
		TimestampAuto:     true,
	}

	desc, sugg := FormatFieldCoverage("PayHandler", result)

	if !strings.Contains(desc, "5/5") {
		t.Errorf("description should contain '5/5', got: %s", desc)
	}
	if !strings.Contains(sugg, "Full PCI DSS 10.2.1 field coverage") {
		t.Errorf("suggestion should mention full coverage, got: %s", sugg)
	}
}
