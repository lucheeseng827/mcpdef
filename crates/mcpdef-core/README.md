# mcpdef-core

The normalized JSON-RPC 2.0 envelope plus the MCP method and decision types shared across the MCPdef engine.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Defines the normalized JSON-RPC 2.0 request/response/error envelope used on the MCP wire.
- Models the MCP method surface (initialize/capabilities, `tools/list`, `tools/call`, etc.).
- Provides the shared decision types (allow / deny / transform) that the policy and audit layers speak.
- Acts as the common vocabulary every other `mcpdef-*` crate depends on.

## Usage

This is a foundational library consumed by the `mcpdef` binary and its sibling
engine crates; it has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-core
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
