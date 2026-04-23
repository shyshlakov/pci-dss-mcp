package pcidb

import (
	"regexp"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if db == nil {
		t.Fatal("New() returned nil DB")
	}
}

func TestDBCount(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	count := db.Count()
	if count < 240 {
		t.Errorf("DB.Count() = %d, want >= 240", count)
	}
}

func TestLookupDetectable(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	req := db.Lookup("3.3.1")
	if req == nil {
		t.Fatal("DB.Lookup(\"3.3.1\") returned nil")
	}
	if req.Title == "" {
		t.Error("Requirement 3.3.1 has empty Title")
	}
	if req.Description == "" {
		t.Error("Requirement 3.3.1 has empty Description")
	}
	if !req.Detectable {
		t.Error("Requirement 3.3.1 should be Detectable")
	}
}

func TestLookupNonDetectable(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	req := db.Lookup("1.1.1")
	if req == nil {
		t.Fatal("DB.Lookup(\"1.1.1\") returned nil")
	}
	if req.Detectable {
		t.Error("Requirement 1.1.1 should not be Detectable")
	}
}

func TestLookupNonexistent(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	req := db.Lookup("nonexistent")
	if req != nil {
		t.Errorf("DB.Lookup(\"nonexistent\") = %v, want nil", req)
	}
}

func TestDetectableHaveTestingProcedure(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	for _, req := range db.All() {
		if req.Detectable && req.TestingProcedure == "" {
			t.Errorf("Detectable requirement %s has empty TestingProcedure", req.RequirementID)
		}
	}
}

func TestAllRequirementsHaveIDAndTitle(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	for i, req := range db.All() {
		if req.RequirementID == "" {
			t.Errorf("Requirement at index %d has empty RequirementID", i)
		}
		if req.Title == "" {
			t.Errorf("Requirement %s has empty Title", req.RequirementID)
		}
	}
}

func TestNoDuplicateRequirementIDs(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	seen := make(map[string]bool)
	for _, req := range db.All() {
		if seen[req.RequirementID] {
			t.Errorf("Duplicate requirement ID: %s", req.RequirementID)
		}
		seen[req.RequirementID] = true
	}
}

func TestRequirementIDFormat(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	// IDs match pattern: digits.digits with optional sub-levels (e.g., "3.3.1", "9.5.1.2.1")
	pattern := regexp.MustCompile(`^\d+\.\d+(\.\d+){0,3}$`)
	for _, req := range db.All() {
		if !pattern.MatchString(req.RequirementID) {
			t.Errorf("Requirement ID %q does not match expected pattern", req.RequirementID)
		}
	}
}

func TestDetectableCount(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	dc := db.DetectableCount()
	if dc != 14 {
		t.Errorf("DB.DetectableCount() = %d, want 14", dc)
	}
}

func TestGhostRequirementsNotDetectable(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	ghosts := []string{
		"2.2.7", "3.3.1.1", "3.3.1.2", "3.3.1.3", "3.3.2", "3.3.3",
		"4.2.1.1", "6.2.3", "6.3.1", "6.3.2", "6.4.1", "6.4.2",
		"6.5.1", "6.5.2", "8.3.7", "10.2.1.1", "10.2.1.2", "10.2.1.3",
		"10.2.2", "12.3.1",
	}
	for _, id := range ghosts {
		req := db.Lookup(id)
		if req == nil {
			t.Errorf("Ghost requirement %s not found in DB", id)
			continue
		}
		if req.Detectable {
			t.Errorf("Ghost requirement %s should have Detectable=false", id)
		}
	}
}

func TestDetectableRequirementsHaveCoverageScope(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	for _, req := range db.All() {
		if req.Detectable && req.CoverageScope == "" {
			t.Errorf("Detectable requirement %s has empty CoverageScope", req.RequirementID)
		}
	}
}

func TestNotCheckedWithCoveredBy(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	// Sub-requirements that should have covered_by set
	coveredByExpected := map[string]string{
		"3.3.1.1":  "3.3.1",
		"3.3.1.2":  "3.3.1",
		"3.3.1.3":  "3.3.1",
		"4.2.1.1":  "4.2.1",
		"2.2.7":    "4.2.1",
		"10.2.1.1": "10.2.1",
		"10.2.1.2": "10.2.1",
	}
	for id, expectedParent := range coveredByExpected {
		req := db.Lookup(id)
		if req == nil {
			t.Errorf("Requirement %s not found", id)
			continue
		}
		if req.CoveredBy != expectedParent {
			t.Errorf("Requirement %s CoveredBy = %q, want %q", id, req.CoveredBy, expectedParent)
		}
	}
}

func TestAllReturnsAllRequirements(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	all := db.All()
	if len(all) != db.Count() {
		t.Errorf("len(All()) = %d, Count() = %d, want equal", len(all), db.Count())
	}
}

func TestAllTwelveCategoriesPresent(t *testing.T) {
	t.Parallel()
	db, err := New()
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Check that requirements from all 12 major categories (1.x - 12.x) are present
	categories := make(map[string]bool)
	categoryPattern := regexp.MustCompile(`^(\d+)\.`)
	for _, req := range db.All() {
		m := categoryPattern.FindStringSubmatch(req.RequirementID)
		if len(m) > 1 {
			categories[m[1]] = true
		}
	}

	expectedCategories := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}
	for _, cat := range expectedCategories {
		if !categories[cat] {
			t.Errorf("Category %s is not represented in the database", cat)
		}
	}
}
