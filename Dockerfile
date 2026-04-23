# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/pci-dss-mcp .

FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f

RUN apk add --no-cache git

LABEL io.modelcontextprotocol.server.name="io.github.shyshlakov/pci-dss-mcp"
LABEL org.opencontainers.image.source="https://github.com/shyshlakov/pci-dss-mcp"
LABEL org.opencontainers.image.description="Narrow-and-deep PCI DSS v4.0.1 compliance scanner for Go payment services, delivered as an MCP server"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/pci-dss-mcp /usr/local/bin/pci-dss-mcp

ENTRYPOINT ["/usr/local/bin/pci-dss-mcp"]
