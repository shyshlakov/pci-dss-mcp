package reportscanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
)

func TestFormatHumanReadable_ByteIdentical_Golden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTree(t, fixtureRoot)

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}

	gen := NewReportGenerator(db)
	report, err := gen.GenerateWithOptions(ctx, scanRoot, "offline", false, true)
	if err != nil {
		t.Fatalf("GenerateWithOptions: %v", err)
	}

	actual := FormatHumanReadable(report)
	actual = scrubVolatileFields(actual, scanRoot)

	goldenPath := filepath.Join("testdata", "format_golden.txt")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(actual), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden snapshot written: %s (%d bytes)", goldenPath, len(actual))
		return
	}

	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1 to create)", err)
	}
	if string(expected) != actual {
		expectedLines := strings.Split(string(expected), "\n")
		actualLines := strings.Split(actual, "\n")
		firstMismatch := -1
		minLen := len(expectedLines)
		if len(actualLines) < minLen {
			minLen = len(actualLines)
		}
		for i := 0; i < minLen; i++ {
			if expectedLines[i] != actualLines[i] {
				firstMismatch = i
				break
			}
		}
		if firstMismatch < 0 && len(expectedLines) != len(actualLines) {
			firstMismatch = minLen
		}
		t.Fatalf("FormatHumanReadable diverged from golden.\n"+
			"First mismatch at line %d.\n"+
			"Expected bytes: %d\nActual bytes:   %d\n"+
			"Run UPDATE_GOLDEN=1 go test -run TestFormatHumanReadable_ByteIdentical_Golden ./scanner/reportscanner/ to regenerate.",
			firstMismatch+1, len(expected), len(actual))
	}
}

// scrubVolatileFields normalises fields that change between runs (scan root
// tmp path, duration, generated_at timestamp) so the golden comparison is
// a pure formatter check.
func scrubVolatileFields(s, scanRoot string) string {
	s = strings.ReplaceAll(s, scanRoot, "<SCAN_ROOT>")
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "Target: ") {
			lines[i] = "Target: <SCAN_ROOT>"
			continue
		}
		if strings.HasPrefix(line, "Generated: ") {
			lines[i] = "Generated: <TS>"
			continue
		}
		if strings.HasPrefix(line, "Duration: ") {
			idx := strings.Index(line, "| Files:")
			if idx >= 0 {
				lines[i] = "Duration: <DUR> " + line[idx:]
			}
			continue
		}
	}
	return strings.Join(lines, "\n")
}
