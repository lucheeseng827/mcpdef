# mcpdef-audit

The append-only, hash-linked, tamper-evident audit ledger — plus offline chain verification and SIEM export.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Appends every governed tool call to a hash-linked JSONL ledger (each record chains to the previous `hash`).
- Verifies the chain offline so any edit or deletion of an interior record is detectable.
- Exports the ledger to SIEMs in OCSF / CEF / syslog / JSON formats.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own (the `mcpdef audit verify` / `audit tail` subcommands drive
it). If you want it standalone:

```sh
cargo add mcpdef-audit
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
