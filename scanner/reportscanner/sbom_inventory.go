package reportscanner

import (
	"fmt"

	"github.com/shyshlakov/pci-dss-mcp/scanner/sbomscanner"
)

const sbomRequirementID = "6.3.2"

func addSBOMInventoryStatus(requirementStatus map[string]RequirementStatus, projectDir string) {
	rs, ok := requirementStatus[sbomRequirementID]
	if !ok {
		rs = RequirementStatus{
			RequirementID: sbomRequirementID,
			Title:         "Software Inventory Maintained",
		}
	}
	res, err := sbomscanner.InventoryProbe(projectDir)
	switch {
	case err != nil:
		rs.Status = "FAIL"
		rs.CrossReference = fmt.Sprintf("SBOM inventory unavailable: %v", err)
	case !res.HasGoMod:
		rs.Status = "FAIL"
		rs.CrossReference = "go.mod missing; cannot generate CycloneDX inventory"
	case res.ComponentCount == 0:
		rs.Status = "FAIL"
		rs.CrossReference = "go.mod has no dependencies declared; inventory would be empty"
	default:
		rs.Status = "PASS"
		rs.FindingCount = 0
		rs.CrossReference = fmt.Sprintf("SBOM inventory: %d components", res.ComponentCount)
	}
	requirementStatus[sbomRequirementID] = rs
}
