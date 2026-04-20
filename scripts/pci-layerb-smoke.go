//go:build smoke

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

const budgetBytes = 20480

func main() {
	target := "testdata/vulnerable-payment-service"
	if v := os.Getenv("TARGET_PATH"); v != "" {
		target = v
	}
	if len(os.Args) > 1 && os.Args[1] != "" {
		target = os.Args[1]
	}
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		fatal("abs", err)
	}

	db, err := pcidb.New()
	if err != nil {
		fatal("pcidb.New", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "layerb-smoke", Version: "v0.0.1"}, nil)
	triagescanner.RegisterTools(server, db)
	panscanner.RegisterTools(server)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(context.Background(), serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "layerb-smoke-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		fatal("client.Connect", err)
	}
	defer func() { _ = session.Close() }()
	ctx := context.Background()

	report := map[string]any{"target": abs}
	over := false

	triageRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "triage_findings",
		Arguments: map[string]any{
			"path":          abs,
			"dep_scan_mode": "offline",
			"include_taint": true,
		},
	})
	if err != nil {
		fatal("triage_findings", err)
	}
	triageBytes, mErr := json.Marshal(triageRes.StructuredContent)
	if mErr != nil {
		fatal("marshal triage", mErr)
	}
	report["triage_findings"] = summarise(triageRes, triageBytes)
	if len(triageBytes) >= budgetBytes {
		over = true
	}

	panRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan_pan_data",
		Arguments: map[string]any{"path": abs},
	})
	if err != nil {
		fatal("scan_pan_data", err)
	}
	panBytes, mErr := json.Marshal(panRes.StructuredContent)
	if mErr != nil {
		fatal("marshal pan", mErr)
	}
	report["scan_pan_data"] = summarise(panRes, panBytes)
	if len(panBytes) >= budgetBytes {
		over = true
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fatal("encode report", err)
	}
	if over {
		fmt.Fprintln(os.Stderr, "FAIL: one or more Layer B responses exceeded 20480-byte budget")
		os.Exit(1)
	}
}

func summarise(result *mcp.CallToolResult, raw []byte) map[string]any {
	out := map[string]any{
		"bytes":     len(raw),
		"under_20k": len(raw) < budgetBytes,
		"is_error":  result.IsError,
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err == nil {
		if shape, ok := m["response_shape"].(string); ok {
			out["response_shape"] = shape
		}
		if pag, ok := m["pagination"].(map[string]any); ok {
			if total, ok := pag["total_findings"]; ok {
				out["findings_total"] = total
			}
			if returned, ok := pag["returned"]; ok {
				out["top_findings_total"] = returned
			}
		}
	}
	return out
}

func fatal(where string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", where, err)
	os.Exit(2)
}
