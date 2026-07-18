# mcpdef-pin

Tool-definition pinning and rug-pull detection — canonical tool-def hashing backed by a persistent pin store.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Computes a canonical hash of each server's tool definitions.
- Persists approved definitions in a pin store.
- Detects rug-pulls — a server changing a tool's definition after approval — so the gateway can deny + audit them.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own (the `mcpdef pin` / `mcpdef diff-tools` subcommands drive
it). If you want it standalone:

```sh
cargo add mcpdef-pin
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
