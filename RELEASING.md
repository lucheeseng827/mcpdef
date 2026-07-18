# Releasing MCPdef

Releases are cut by tag. `.github/workflows/release.yml` (synced from `ops/release.yml`) does
the rest. MCPdef sits in the data path, so every artifact is **signed, attested, and SBOM'd** —
a security team can verify the binary end-to-end without trusting the publisher
(see [Verify a release](#verify-a-release-no-trust-in-the-publisher-required) below).

## Cut a release

1. Bump `version` in the workspace `Cargo.toml` (`[workspace.package]` **and** the internal
   `[workspace.dependencies]` version pins must match), update `CHANGELOG.md`, land on `main`.
2. Tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
   Exercise the pipeline first with a pre-release tag (`v0.1.0-rc.1`): it builds, signs, and
   attaches a GitHub **pre-release**, but skips crates.io, Homebrew, and `:latest` promotion.
3. On a real `v*` tag the `release` workflow:
   - **builds** static-musl (`x86_64`/`aarch64`) and macOS (`x86_64`/`arm64`) `mcpdef` binaries,
     each archived as `mcpdef-<target>.tar.gz` with a `.sha256`, a **cosign** keyless signature
     (`.sig` + `.pem`), and a **SLSA build-provenance** attestation;
   - generates a **CycloneDX SBOM** for the engine workspace;
   - **publishes** the GitHub release with every artifact + an aggregated `SHA256SUMS`;
   - **publishes** the OSS engine crates to crates.io in dependency order
     (`mcpdef-core` → `mcpdef-pin`/`mcpdef-ratelimit`/`mcpdef-audit`/`mcpdef-inspect`/`mcpdef-policy`/`mcpdef-auth`/`mcpdef-transport`
     → `mcpdef-sandbox` → `mcpdef`), idempotently; the paid `ee/` plane is a separate workspace and is **never** published;
   - **bumps** `Formula/mcpdef.rb` and commits it to `main` (this repo is its own tap);
   - **pushes** a multi-arch (`linux/amd64`+`linux/arm64`) distroless image to
     `docker.io/mancube/mcpdef:{vX.Y.Z,latest}`, cosign-signed + SLSA-attested.

`workflow_dispatch` re-runs the pipeline against an existing tag (input `tag`); `promote`
re-points Homebrew + `:latest` (use only for the newest tag).

## Distribution channels

| Channel | Source of truth |
|---|---|
| `cargo install mcpdef` | crates.io (engine crates published by the release workflow on each real tag) |
| `brew install mcpdef` | `Formula/mcpdef.rb` (this repo is its own tap) |
| `docker run … mancube/mcpdef` | `Dockerfile.release` (distroless, from the prebuilt static binary) |
| release tarballs | the GitHub release (`mcpdef-<target>.tar.gz` + `.sha256` + `.sig` + `.pem`) |

## Verify a release (no trust in the publisher required)

```bash
# 1. signature — keyless cosign against this repo's release workflow identity
cosign verify-blob \
  --certificate mcpdef-x86_64-unknown-linux-musl.tar.gz.pem \
  --signature  mcpdef-x86_64-unknown-linux-musl.tar.gz.sig \
  --certificate-identity-regexp '^https://github\.com/lucheeseng827/mcpdef/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mcpdef-x86_64-unknown-linux-musl.tar.gz

# 2. provenance — the SLSA attestation (built by the named workflow from the tagged commit)
gh attestation verify mcpdef-x86_64-unknown-linux-musl.tar.gz --repo lucheeseng827/mcpdef

# 3. checksums + 4. build from source (engine standalone, ee/ absent) + 5. observe egress
#    (`mcpdef egress show`) + 6. verify the audit chain (`mcpdef audit verify`).
```

## Verify a build locally

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --bin mcpdef --target x86_64-unknown-linux-musl
docker buildx build --platform linux/amd64,linux/arm64 -t mcpdef:dev .
```

## Mirror first-release setup (one-time)

The pipeline runs on the **public mirror** (`lucheeseng827/mcpdef`), populated by the monorepo's
OSS-sync workflow per [`.ossync.yaml`](./.ossync.yaml). The `release.yml` code is correct as
authored — a first release fails only when the mirror repo/registry aren't set up. Do all of
the following **before pushing the first `v*` tag**, or the `docker` / `cratesio` / `brew` jobs
fail (some silently):

1. **`cicd` environment + secrets.** Create a GitHub Environment named `cicd` on the mirror with
   `DOCKER_USERNAME`, `DOCKER_PASSWORD` (a Docker Hub **access token** with write scope, not the
   account password), and `CRATESIO_TOKEN`. The `docker` and `cratesio` jobs are
   `environment: cicd`; missing secrets → registry/publish login fails.
2. **`cicd` deployment-branch policy must allow the `v*` TAG ref.** The pipeline is
   tag-triggered. If the environment restricts deployments to `main` only, the tag-run
   `docker`/`cratesio` jobs are **blocked with no obvious error**. Leave the policy unrestricted,
   or add a tag pattern (`v*`) to the allowed refs. *(Easiest gotcha to miss.)*
3. **Create the Docker Hub repo `mancube/mcpdef` first.** Docker Hub (or an org that restricts
   repo auto-creation) rejects the first `push` and the `dockerhub-description` update if the
   repo doesn't exist. Pre-create it (public), and confirm the `DOCKER_PASSWORD` token has push
   rights to the `mancube` namespace. *(Same lesson as the sibling EE images — repos are created
   manually before the first release.)*
4. **Enable Actions + "Read and write" workflow permissions.** Public mirrors often ship with
   Actions disabled. The `brew` job commits `Formula/mcpdef.rb` back to `main` via
   `github.token`, so Settings → Actions → General → Workflow permissions must be **Read and
   write**.
5. **Don't let branch protection on `main` block the actions bot.** The `brew` job pushes
   directly to `main`. A protection rule requiring a PR/review with no bypass for
   `github-actions[bot]` fails that push (the image + crates still publish; only the formula
   bump fails).
6. **Sync token needs the Workflows scope.** The OSS-sync maps `ops/release.yml` →
   `.github/workflows/release.yml` on the mirror; a Contents-only PAT `403`s on
   `.github/workflows` and the workflow file never lands. (Noted in the `.ossync.yaml` header.)

Also confirm the crate names (`mcpdef`, `mcpdef-*`) are free on crates.io before tagging —
`cargo publish` is append-only and a name clash aborts mid-sequence.

### First-release smoke test

The Phase-4 Wasmtime/Cranelift-JIT sandbox now ships in the musl binary, so confirm the one
interaction the CI doesn't exercise: pull the freshly-pushed image and run it.

```bash
docker run --rm mancube/mcpdef:v0.1.0 version     # binary starts on distroless/static
# then exercise one wasm-component upstream to confirm runtime JIT codegen works on this base
```

Static-musl + runtime JIT (mmap'd code pages, not dynamic glibc) is expected to work on
`distroless/static`; verify once so a hardened-host W^X issue surfaces here, not in a user's
cluster (the no-JIT Pulley profile is the fallback for hosts that forbid W^X pages).
