# mcpdef-secrets

Where a secret comes from, and reading it when it is needed: the value itself, an environment variable, a file, or a command's output.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Parses a secret reference from config: a plain string (the value itself), `{ env = "NAME" }`, `{ file = "/path" }` or `{ exec = ["command", "argument"] }`.
- Reads the value when it is needed, as a `SecretString`, whose memory is wiped when it is dropped.
- Reads a file afresh each time, so a rotated secret is picked up. It must be a regular file of at most 64 KiB of UTF-8 text, and a line ending at its end is not part of the value.
- Runs a command with no shell and nothing on its input, throws its error output away, and kills it past 5 s or 64 KiB of output.
- Reports a secret file that users other than its owner can read. A file root owns may be readable by its group when, on Linux, the process does not run as root: that group is how the process reads it, as with a Kubernetes Secret volume under the pod's `fsGroup`.
- Never prints a value: a reference's `Debug` and `Display` say where the value comes from, and so do its errors.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-secrets
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
