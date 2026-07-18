# mcpdef

The single MCPdef binary — config, the transport-mux gateway proxy loop, the downstream Streamable HTTP listener, and the CLI.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This is the binary crate that ties
the engine crates together; it is what most users install.

## What it does

- Runs the transport-multiplexing reverse proxy that fronts upstream MCP servers (stdio / Streamable HTTP / legacy HTTP+SSE).
- Serves clients over the downstream Streamable HTTP listener (Origin-validated, loopback-bound) with OAuth 2.1 termination + RBAC.
- Enforces the full governance pipeline — allowlist, RBAC, pinning, rate limits, egress guard, WASM sandbox — and writes the tamper-evident audit ledger.

## Usage

```sh
cargo install mcpdef
mcpdef validate --config mcpdef.toml   # check config
mcpdef up      --config mcpdef.toml    # serve over Streamable HTTP (= run --http)
mcpdef call list_issues --args '{}'    # one-shot governed tool call
```

Subcommands: `run`, `up`, `call`, `validate`, `version`, `servers list`,
`audit verify`, `audit tail`, `egress show`, `pin`, `diff-tools`.

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
