package pcidb

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed data/pci-dss-v4.0.1.json
var requirementData []byte

// Requirement represents a single PCI DSS v4.0.1 requirement.
type Requirement struct {
	RequirementID    string `json:"requirement_id"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	TestingProcedure string `json:"testing_procedure"`
	Severity         string `json:"severity"`
	Detectable       bool   `json:"detectable"`
	NewInV4          bool   `json:"new_in_v4"`

	// Accuracy metadata for detectable requirements.
	CoverageScope string   `json:"coverage_scope,omitempty"`
	Limitations   []string `json:"limitations,omitempty"`
	NotCovered    string   `json:"not_covered,omitempty"`

	// NOT_CHECKED metadata for sub-requirements covered by parent scanners.
	CoveredBy           string `json:"covered_by,omitempty"`
	NotDetectableReason string `json:"not_detectable_reason,omitempty"`
	RequiresQSA         bool   `json:"requires_qsa,omitempty"`
}

// DB is the PCI DSS requirements database.
type DB struct {
	requirements map[string]*Requirement
	all          []*Requirement
}

// New parses the embedded PCI DSS JSON and returns a queryable DB.
func New() (*DB, error) {
	var reqs []*Requirement
	if err := json.Unmarshal(requirementData, &reqs); err != nil {
		return nil, fmt.Errorf("pcidb: failed to parse embedded data: %w", err)
	}
	db := &DB{
		requirements: make(map[string]*Requirement, len(reqs)),
		all:          reqs,
	}
	for _, r := range reqs {
		if _, exists := db.requirements[r.RequirementID]; exists {
			return nil, fmt.Errorf("pcidb: duplicate requirement ID: %s", r.RequirementID)
		}
		db.requirements[r.RequirementID] = r
	}
	return db, nil
}

// Lookup returns a requirement by ID, or nil if not found.
func (db *DB) Lookup(id string) *Requirement {
	return db.requirements[id]
}

// Count returns the total number of requirements.
func (db *DB) Count() int {
	return len(db.all)
}

// All returns all requirements.
func (db *DB) All() []*Requirement {
	return db.all
}

// DetectableCount returns the number of detectable requirements.
func (db *DB) DetectableCount() int {
	count := 0
	for _, r := range db.all {
		if r.Detectable {
			count++
		}
	}
	return count
}
