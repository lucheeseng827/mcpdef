# mcpdef-ratelimit

Token-bucket rate limiting for the gateway's `tools/call` hot path — per-tool and global.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Applies token-bucket rate limits on the `tools/call` hot path.
- Enforces both per-tool and global buckets.
- Feeds a `rate-limited` decision into the audit ledger when a call is throttled, defending gateway availability.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-ratelimit
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
