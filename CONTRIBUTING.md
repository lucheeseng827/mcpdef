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
