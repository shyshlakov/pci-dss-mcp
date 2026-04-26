# Glama badge preview

Pick one of the two glama badge variants below. After you decide, this file gets deleted in the same PR and only the chosen variant lands in `README.md`.

---

## Option A: `score.svg` (compact, fits the existing badge block)

### Standalone

[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/score.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)

### Integrated into the current README badge block (CI removed, glama in its place)

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)
[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/score.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)
[![Release](https://img.shields.io/github/v/release/shyshlakov/pci-dss-mcp?label=release)](https://github.com/shyshlakov/pci-dss-mcp/releases/latest)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.shyshlakov%2Fpci--dss--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=pci-dss-mcp)

**Pros:** uniform badge-block style, fits beside Go Report Card / Scorecard / Release / MCP Registry. One number, scannable.
**Cons:** less visually distinctive than the card variant, casual readers may miss it.

---

## Option B: `card.svg` (large featured callout)

### Standalone

[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/card.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)

### Integrated as a "Featured on" callout below the badge block (CI still removed, no glama in topblock)

> Placed under the TL/DR claim, before the "What it does" section.

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)
[![Release](https://img.shields.io/github/v/release/shyshlakov/pci-dss-mcp?label=release)](https://github.com/shyshlakov/pci-dss-mcp/releases/latest)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.shyshlakov%2Fpci--dss--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=pci-dss-mcp)

**Featured on:**

[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/card.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)

**Pros:** much more visible, branded glama logo, includes name + description + score in one card. Stronger trust signal at a glance.
**Cons:** breaks the lean-landing aesthetic of the README (currently 119 lines, this card adds visual weight). Stands out as "marketing" rather than "metadata".

---

## Option C: both (score in topblock + card as standalone callout)

### Topblock with score

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)
[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/score.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)
[![Release](https://img.shields.io/github/v/release/shyshlakov/pci-dss-mcp?label=release)](https://github.com/shyshlakov/pci-dss-mcp/releases/latest)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.shyshlakov%2Fpci--dss--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=pci-dss-mcp)

### Plus a "Featured on" card lower in the README

[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/card.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)

**Pros:** scannable score badge for quick triage AND prominent card for first-time visitors.
**Cons:** redundant. Same data shown twice. Could feel like over-promotion.

---

## How to view this

1. After this branch is pushed, open
   https://github.com/shyshlakov/pci-dss-mcp/blob/quick/glama-badge/BADGES-PREVIEW.md
   on GitHub. The SVG badges render live from glama.
2. Pick A, B, or C.
3. Reply with your choice. I delete this file, apply the chosen layout to `README.md`, push final commit, open PR.
