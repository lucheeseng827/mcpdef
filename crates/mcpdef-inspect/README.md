# mcpdef-inspect

An inline injection / secret-exfil rule-pack scanner for untrusted tool descriptions and tool-call results.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Scans tool descriptions at connect time for prompt-injection patterns.
- Scans tool-call results per call for secret-exfil / injection signals.
- Runs a rule pack over the MCP wire content with off / warn / enforce / redact modes: `redact` blocks as `enforce` does, but tells the caller (`Scanner::redacts`) to rewrite a result's secrets in place rather than refuse it.
- Tells, with `secret_pattern`, whether other text holds a known credential shape: MCPdef asks it of values written in its config.
- Says where, with `Scanner::find_all`: every match with its byte range, in the order of the text and never overlapping, for a caller that rewrites what matched instead of refusing the whole text.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-inspect
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
