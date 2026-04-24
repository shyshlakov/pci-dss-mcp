package reportscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddSBOMInventoryStatus(t *testing.T) {
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	emptyDir := t.TempDir()
	if werr := os.WriteFile(filepath.Join(emptyDir, "go.mod"), []byte("module example.com/empty\n\ngo 1.21\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	tt := []struct {
		name                 string
		path                 string
		wantStatus           string
		wantSubstrInXRef     string
		expectOtherUntouched bool
	}{
		{name: "fixture_pass", path: fixtureRoot, wantStatus: "PASS", wantSubstrInXRef: "components", expectOtherUntouched: true},
		{name: "missing_fail", path: "/definitely/does/not/exist/999", wantStatus: "FAIL", wantSubstrInXRef: "unavailable"},
		{name: "empty_fail", path: emptyDir, wantStatus: "FAIL", wantSubstrInXRef: "no dependencies"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			rs := map[string]RequirementStatus{
				"6.3.2": {RequirementID: "6.3.2", Title: "SBOM inventory", Status: "NOT_CHECKED"},
				"3.4.1": {RequirementID: "3.4.1", Title: "PAN handling", Status: "PASS"},
			}
			addSBOMInventoryStatus(rs, tc.path)
			if rs[sbomRequirementID].Status != tc.wantStatus {
				t.Errorf("Status: got %q want %q", rs[sbomRequirementID].Status, tc.wantStatus)
			}
			if !strings.Contains(rs[sbomRequirementID].CrossReference, tc.wantSubstrInXRef) {
				t.Errorf("CrossReference: got %q want substring %q", rs[sbomRequirementID].CrossReference, tc.wantSubstrInXRef)
			}
			if tc.expectOtherUntouched {
				if rs["3.4.1"].Status != "PASS" {
					t.Errorf("unrelated requirement modified: 3.4.1 status became %q", rs["3.4.1"].Status)
				}
			}
		})
	}
}
