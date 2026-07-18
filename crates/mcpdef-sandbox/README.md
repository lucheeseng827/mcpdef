# mcpdef-sandbox

The in-path WASM sandbox — run an untrusted `.wasm` MCP server under Wasmtime behind the same `Transport` seam as any other upstream.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Executes an untrusted MCP server in-process under **Wasmtime** — no child process.
- Bounds every call with **fuel** (CPU), a **linear-memory** ceiling, and an optional wall-clock **epoch** deadline.
- **Core module** path (`transport = "wasm"`): runs against an empty linker — zero ambient capability (no fs/net/clock).
- **Component** path (`transport = "wasm-component"`): a `wasm32-wasip2` component (`mcpdef:server` WIT world) under capability-scoped WASI whose only grant is outbound TCP, gated by a per-destination egress allowlist (default deny-all).

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-sandbox
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
