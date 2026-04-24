package main

import (
	"context"
	"fmt"
	"log"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/shyshlakov/pci-dss-mcp/scanner/sbomscanner"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: sbomdump <project-dir>")
	}
	sbom, err := sbomscanner.GenerateSBOM(context.Background(), os.Args[1])
	if err != nil {
		log.Fatalf("GenerateSBOM: %v", err)
	}
	bom := sbomscanner.ToCycloneDX(sbom)
	enc := cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		log.Fatalf("encode: %v", err)
	}
	if bom.Components != nil {
		fmt.Fprintf(os.Stderr, "components: %d\n", len(*bom.Components))
	} else {
		fmt.Fprintln(os.Stderr, "components: 0")
	}
}
