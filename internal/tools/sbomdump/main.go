package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/shyshlakov/pci-dss-mcp/scanner/sbomscanner"
)

func main() {
	fixedSerial := flag.String("fixed-serial", "", "Override generated serialNumber (urn:uuid: or bare 36-char form)")
	noTimestamp := flag.Bool("no-timestamp", false, "Omit metadata.timestamp for reproducible builds")
	pretty := flag.Bool("pretty", false, "Indent JSON output (default: compact, matches MCP tool output)")
	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatal("usage: sbomdump [-fixed-serial=URN] [-no-timestamp] [-pretty] <project-dir>")
	}
	opts := sbomscanner.SBOMOptions{FixedSerial: *fixedSerial, NoTimestamp: *noTimestamp}
	raw, err := sbomscanner.GenerateSBOMRawJSON(context.Background(), flag.Arg(0), opts)
	if err != nil {
		log.Fatalf("GenerateSBOMRawJSON: %v", err)
	}
	if *pretty {
		var buf bytes.Buffer
		if jerr := json.Indent(&buf, raw, "", "  "); jerr != nil {
			log.Fatalf("indent: %v", jerr)
		}
		raw = buf.Bytes()
	}
	if _, werr := os.Stdout.Write(raw); werr != nil {
		log.Fatalf("write: %v", werr)
	}
	var probe map[string]any
	if perr := json.Unmarshal(raw, &probe); perr == nil {
		if comps, ok := probe["components"].([]any); ok {
			fmt.Fprintf(os.Stderr, "components: %d\n", len(comps))
		}
	}
}
