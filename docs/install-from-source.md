# Install from source

Docker (see [README.md#install](../README.md#install)) is the recommended install path. Build from source when you want a faster dev loop than `docker build`, or when Docker is not available on your platform.

## Build

Requires **Go 1.25+**.

```bash
# Released version
go install github.com/shyshlakov/pci-dss-mcp@latest

# Main branch
git clone https://github.com/shyshlakov/pci-dss-mcp.git
cd pci-dss-mcp
go install .
```

The binary lands at `$(go env GOPATH)/bin/pci-dss-mcp` (usually `~/go/bin/pci-dss-mcp` on macOS and Linux, `%USERPROFILE%\go\bin\pci-dss-mcp.exe` on Windows).

## Find the absolute path to your binary

GUI-spawned MCP clients do not inherit shell PATH, so configs need an absolute path:

```bash
which pci-dss-mcp
# /Users/you/go/bin/pci-dss-mcp
```

If `which` returns nothing, use `echo "$(go env GOPATH)/bin/pci-dss-mcp"`.

## macOS provenance fix (SIGKILL on launch)

macOS tags unsigned binaries with a `com.apple.provenance` attribute that can cause `SIGKILL` when launched from a GUI-spawned MCP client. The reliable workaround:

```bash
codesign --force --sign - "$(which pci-dss-mcp)"
```

The Docker path does not hit this issue. The provenance attribute applies only to host-native binaries.

## Verify the binary runs

```bash
pci-dss-mcp < /dev/null
# Expected output on stderr:
#   level=INFO msg="PCI DSS database loaded" requirements=250
#   level=INFO msg="starting MCP server on stdio"
```

## MCP client config (go-install variant)

Use this JSON variant in place of the Docker block in any of the Usage sections of the README. Replace `/absolute/path/to/pci-dss-mcp` with the output of `which pci-dss-mcp`:

```json
{
  "mcpServers": {
    "pci-dss-mcp": {
      "command": "/absolute/path/to/pci-dss-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

For Cursor add `"type": "stdio"` next to `"command"`. For Claude Code use `claude mcp add --scope user pci-dss-mcp -- "$(which pci-dss-mcp)"` instead of a JSON file.

## Cosign verification (optional)

Every release image is signed with Sigstore keyless OIDC. To verify before use:

```bash
DIGEST=$(docker buildx imagetools inspect ghcr.io/shyshlakov/pci-dss-mcp:v0.6.2 --format '{{json .Manifest}}' | jq -r '.digest')
cosign verify ghcr.io/shyshlakov/pci-dss-mcp@$DIGEST \
  --certificate-identity-regexp '^https://github.com/shyshlakov/pci-dss-mcp/\.github/workflows/release-docker\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Install cosign locally with `brew install cosign` (macOS) or see [sigstore/cosign](https://github.com/sigstore/cosign#installation).

## Reloading after a rebuild

- **Claude Desktop:** quit and relaunch
- **Claude Code:** `/mcp reload` or restart session
- **Cursor:** restart Cursor
