# Contributing to MCPdef

Thanks for your interest in MCPdef — a fast, self-hostable, single-binary **MCP
gateway & governance plane**. MCPdef sits *in the data path* of every agent action,
so contributions are held to a high bar for clarity, test coverage, and security.

## License-in = license-out (DCO, no CLA)

- Contributions to the **OSS engine** (the module root: `crates/**`) are accepted
  under **Apache-2.0** inbound — the same license they ship under. We do **not**
  require a CLA.
- Instead we use the **Developer Certificate of Origin** ([DCO](https://developercertificate.org/)).
  Sign off every commit:

  ```sh
  git commit -s -m "mcpdef-audit: add CEF export shape"
  ```

  The `-s` adds a `Signed-off-by: Your Name <you@example.com>` trailer
  certifying you wrote the patch or have the right to submit it under Apache-2.0.

- The **`ee/` plane is not open to outside contribution.** It is source-available
  under **BSL 1.1** for transparency and self-hosting, not community development.
  PRs touching `ee/**` are closed by policy — please file an issue instead.

## Before you open a PR

1. **Build & test the OSS engine standalone**, with `ee/` absent — this proves
   the safety + audit surface is self-contained:

   ```sh
   cargo build --release -p mcpdef
   cargo test            # unit + stdio/HTTP-bridge integration + CLI tests
   cargo clippy --all-targets
   cargo fmt --all -- --check
   ```

2. **Add tests.** New behavior needs a test; bug fixes need a regression test.
   Transport/protocol work should add a conformance fixture (see below).

3. **Keep the boundary.** MCPdef governs the **tool / MCP layer** only. It never
   routes model/completion traffic — that is out of scope, permanently
   (see ARCHITECTURE.md §1). PRs that blur this boundary will be declined.

4. **Never paywall safety.** Anything that decides allow/deny, isolates a server,
   or records what happened belongs in the OSS engine, not `ee/`
   (see OSS-ROLLOUT.md §2).

5. **Keep to one TLS stack and to Rust 1.88.** MCPdef speaks TLS through rustls
   on ring, and installs ring as rustls' provider when it starts. A dependency
   that brings `aws-lc-rs`, OpenSSL or `native-tls`, or a second version of
   `rustls`, is refused by CI. Add a rustls-based crate with its default
   features off and its `ring` feature on. A test that builds its own `reqwest`
   client calls `mcpdef_transport::install_crypto_provider()` first: `reqwest`
   panics without a provider. A test that needs certificates makes them with
   `mcpdef-testkit` when it runs: never commit a certificate or a key. The
   workspace builds on Rust 1.88 (`rust-version`), and `cargo update` keeps to
   dependency releases that do.

6. **Rebuild the console when you change it.** The console's source is
   `console/` (React + Vite, Node 22); its build is committed in
   `crates/mcpdef-console`, so building the gateway never needs Node. After a
   change there, run `make console` and commit what it writes. CI builds it
   again from the lockfile and fails on any difference. The admin listener's
   content security policy loads scripts and styles from files alone: no
   inline `<script>` or `<style>`, and no `data:` URI for a font or a script.

## Spec-conformance is a first-class lane

MCPdef tracks a moving protocol (the stateless **2026-07-28** RC removes the
`initialize` handshake and `Mcp-Session-Id`). Conformance fixtures and
transport-bridge fixes are explicitly welcomed and labeled `spec-conformance`.
Reference the spec revision in the PR description.

## Security issues are private

Do **not** open a public issue for a vulnerability. Follow the private,
embargoed disclosure process in [SECURITY.md](./SECURITY.md). Given MCPdef's
position in the data path, vulnerability reports are coordinated, not filed in
the open.

## Code style

- Match the surrounding code: the crates favor small, well-documented modules
  with doc comments that explain *why*, not just *what*.
- One logical change per PR. Keep diffs reviewable.
- Run `cargo fmt` and `cargo clippy` clean before pushing.
