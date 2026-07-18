# mcpdef-transport

The `Transport` trait and its implementations — stdio child, HTTP bridges, and the egress/SSRF guard that carries MCP traffic to upstream servers.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Defines the `Transport` trait plus stdio-child and in-memory duplex transports.
- Spawns stdio upstreams with token-broker env injection so servers never hold long-lived creds.
- Bridges Streamable HTTP and the legacy 2024-11-05 HTTP+SSE transport (probe/fallback, `Last-Event-ID` resumption).
- Enforces the egress/SSRF guard: cloud-metadata block, private/loopback classification, and DNS pinning.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-transport
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
