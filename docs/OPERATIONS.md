# MCPdef operations runbook

How to deploy, back up, verify, monitor, and debug a running `mcpdef`. Everything
here describes the shipped OSS binary (`crates/mcpdef`, v0.1.x) — grounded in
[`main.rs`](../crates/mcpdef/src/main.rs) / [`listener.rs`](../crates/mcpdef/src/listener.rs) /
[`gateway.rs`](../crates/mcpdef/src/gateway.rs). Config knobs are in
[CONFIG.md](./CONFIG.md); the wire surface is in [API.md](./API.md).

## Deploy

MCPdef is one binary + one TOML file. No database, no sidecars.

- **From source:** `cargo build -p mcpdef --release` → `target/release/mcpdef`.
- **Container:** [`Dockerfile`](../Dockerfile) builds a distroless
  (`gcr.io/distroless/static-debian12:nonroot`) image from a musl-static build;
  `EXPOSE 7878`. CI releases assemble multi-arch images from prebuilt binaries
  via [`Dockerfile.release`](../Dockerfile.release) — see
  [RELEASING.md](../RELEASING.md) and [docs/DOCKERHUB.md](./DOCKERHUB.md).
  Musl caveat: Wasmtime's Cranelift JIT must be validated on the fully-static
  target — "static-ish", not a blanket promise.
- **Run:** `mcpdef run --config mcpdef.toml` (stdio client) or
  `mcpdef up --config mcpdef.toml` (HTTP listener). Validate first:
  `mcpdef validate --config mcpdef.toml`.
- **HTTPS:** `[gateway.tls]` serves the listener over TLS, from a
  certificate in files or one a local CA of MCPdef's own issues: see
  [Serving HTTPS](#serving-https).
- **Readiness signal:** one stderr line —
  `mcpdef 0.5.0 ready · 1 upstream(s) · audit ./mcpdef-audit/audit.log · listening streamable-http 127.0.0.1:7878`
  (plus `· ⚠ N down, retrying: '<id>', …`, `· profile <p>`,
  `· ⚠ N rug-pulled tool(s) denied`, `· oauth on · N role(s)` when applicable;
  `mtls on`, `keys on`, or the methods joined by `or` or `and`
  (`oauth or mtls on`, `oauth or keys on`, `oauth and mtls on`) in place of
  `oauth on`, as `[gateway.auth] methods` and `require` say, and `· tls <mode> · client
  certificates <mode>` after the listen address with mTLS on).
  Startup **fails fast** if the config is invalid, the audit ledger can't be
  opened, or — with auth on — the JWKS is unreadable / the `jwks_uri` fetch is
  egress-blocked. An upstream that cannot start does **not** stop it: see
  [Upstream supervision](#upstream-supervision).
- **Upgrade / rollback:** stateless swap — stop, replace the binary, start.
  The audit ledger re-opens and resumes its hash chain; the pin store is
  re-read. There is no on-disk migration.
  - **One ledger, upgraded together:** from 0.5.0, each process that writes a
    ledger takes a lock on its file (`flock`) while it appends. A writer
    before 0.5.0 takes none, so a 0.4.0 writer beside a 0.5.0 one forks the
    chain: upgrade the gateway, its hooks, a filter and any `mcpdef call`
    script that write one ledger together. A ledger on a file system that
    refuses the lock, as a network share without locking can, stops the
    start: keep it on a local disk. 0.4.0 still verifies a ledger 0.5.0
    wrote.
  - **The pin store goes one way:** from 0.5.0, each pin it writes keeps the
    definition beside its hash, as a table, and a release before 0.5.0 reads a
    hash alone, so it does not load the store. To go back to one, put back
    the store as it was before the upgrade: it is in version control, as
    [State](#state-what-to-back-up) says it should be. `mcpdef pin` with the
    older release pins what the servers offer then, unchecked.

## State: what to back up

| File | Config key | Format | Loss impact |
|---|---|---|---|
| Audit ledger | `[gateway] audit` (default `./mcpdef-audit/audit.log`) | JSONL hash chain (append-only) | Your tamper-evident record of every governed call. Back up continuously (it is the compliance artifact). Snapshot-friendly: append-only, safe to copy live. |
| Pin store | `[gateway] pins` (optional) | TOML, `server → tool →` the sha256 and the definition approved | Your approved tool-definition baseline. Losing it means every tool re-pins on next start (trust-on-first-use) — a rug-pull window. Keep it in version control; it is deterministic and diff-clean by design. |
| Config + JWKS | `mcpdef.toml`, `[gateway.auth] jwks` file | TOML / JSON | The policy itself. Version-control both. |
| Bundle floor | `<state_dir>/bundle.json`, with `mcpdef bundle apply` | JSON: the last revision applied | Lost, the node takes a signed bundle of any revision again, an older one among them. Back it up with the rest of the state. |
| Bundle beside the config | `<config>.bundle`, as `mcpdef.toml.bundle`, with `mcpdef bundle apply` | JSON: the bundle applied, byte for byte | With `--bundle-trust`, the gateway runs the config only as it holds it. Lost, the gateway refuses a reload, and does not start, until the bundle is applied again. Keep it with the config. |
| Local CA | `[gateway] state_dir` (default `./mcpdef-state`), `tls/` | PEM: `ca.crt`, `ca.key`, `tls.crt`, `tls.key` | With `[gateway.tls] mode = "self-signed"`: the CA every client was told to trust. Lost, the gateway makes a new one at its next start, and every client has to trust that instead. Back up `ca.crt` and `ca.key` as you would any key: `ca.key` can issue certificates for the listener's names. `tls.crt` and `tls.key` are issued again at will. |
| Session key | `[gateway] state_dir`, `session.key`, unless `[gateway.admin.session] key` is set | 32 bytes, `0600` | Seals the console's sessions. Lost, the gateway makes a new one, and everyone signed in signs in again; nothing else is lost. Replicas behind one `public_url` need the same key: set `[gateway.admin.session] key` for them, rather than each making its own. |

`[server.env]` values (brokered upstream credentials) are best read from a
file, a variable of MCPdef's own or a command, so that the config holds none:
see [CONFIG.md § Secrets](./CONFIG.md#secrets). One written in the config as a
string, and found to be a secret, is warned about at startup. A config that
still holds one: protect it like a secret store (file permissions, encrypted at
rest, no world reads).

Durability note (honest guarantee): by default each ledger record is written to
the operating system before its call is answered, **not** `fsync`ed. A crash of
MCPdef loses no record, but a host crash can lose the last ones. With
`[gateway] audit_fsync = true`, each record is on disk before its call is
answered, at the cost [PERFORMANCE.md](./PERFORMANCE.md) gives. Either way, the
hash chain proves *integrity*, not *durability*.

## Audit-ledger verification

Routine (proves internal consistency — any edit/delete of an interior record):

```sh
$ mcpdef audit verify --config mcpdef.toml
chain OK · 2 record(s) · head=25efafd3189176952f679b50ea5aee711188aaf04b4b9aa345d9068c8ff88e59
```

Exit is non-zero on a break, printing `chain BROKEN at seq=<n>`.

**Plain `verify` cannot detect tail-truncation or wholesale replacement** — a
shortened-but-valid chain still verifies. To close that, periodically **seal**
the `(head, count)` pair somewhere the same attacker cannot edit (a ticket, a
separate WORM store), then verify against the seal:

```sh
# seal: record the current head hash and record count out-of-band, then later:
mcpdef audit verify --config mcpdef.toml --head <sealed-head-hash> --count <sealed-count>
```

`--head`/`--count` must be given together. A mismatch (fewer records, different
head) fails verification even when the chain is internally consistent.

SIEM streaming from the free binary:

```sh
mcpdef audit tail --format ocsf -n 500 | your-siem-forwarder   # also: json | cef | syslog
```

## Signed receipts

A receipt is one decision the gateway made, signed, so that anyone with the
public key can check it offline, without your ledger or your gateway. MCPdef
writes the format of the IETF Internet-Draft
[`draft-farley-acta-signed-receipts-03`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).
Each tool call in the ledger becomes an Access Decision Receipt
(`"type": "protectmcp:decision"`) in the draft's envelope shape. Its signature
is Ed25519 over the payload's RFC 8785 (JCS) form. Other records, such as admin
actions, reloads, upstream changes and resource reads, have no receipt type in
the draft, and get no receipt.

```sh
$ mcpdef receipts key                                  # once: the signing key
wrote mcpdef-receipts.jwk: the key receipts are signed with, named sb:issuer:BnHVtAv9v3Wc. …
$ mcpdef receipts jwks --key mcpdef-receipts.jwk > keys.json        # its public half
$ mcpdef receipts export --key mcpdef-receipts.jwk --out receipts.jsonl
signed 3 receipt(s), for the tool calls among 3 record(s) · ledger head=3decfb9b…
record the last receipt's hash and the count somewhere else, … --last sha256:46445d3e… --count 3`
$ mcpdef receipts verify receipts.jsonl --jwks keys.json
receipts OK · 3 receipt(s) · 1 chain(s) · last=sha256:46445d3e…
```

One receipt, laid out:

```json
{
  "payload": {
    "decision": "allow",
    "issued_at": "2026-10-15T09:03:54.039Z",
    "issuer_id": "sb:issuer:BnHVtAv9v3Wc",
    "mcpdef": { "seq": 0, "server": "mock" },
    "tool_name": "echo",
    "type": "protectmcp:decision"
  },
  "signature": { "alg": "EdDSA", "kid": "sb:issuer:BnHVtAv9v3Wc", "sig": "13824a60…" }
}
```

- **The key.** `receipts key` writes a private JWK (RFC 8037) that only its
  owner can read, and never over a file that is there. Whoever holds the key
  can sign receipts. The export runs wherever the ledger file can be read, so
  the key need not be on the gateway's host at all.
- **Publishing the public half.** `receipts jwks` prints it as a JWK Set.
  Publish it where whoever checks the receipts can fetch it; the draft
  suggests `https://<your domain>/.well-known/acta-keys.json`. A verifier must
  get the key from there, or from you, and never from a receipt.
- **What the export signs.** One receipt per tool call, in order. It reads
  the ledger once and checks its chain as it reads, and with `--head` and
  `--count` the seal too.
  - **What it refuses:** a ledger that fails, and a record with U+001F in a
    field, which an older gateway let in: that record's hash cannot tell one
    reading of its fields from another.
  - **Nothing is kept from a ledger it refuses.** The receipts reach standard
    output, or the `--out` file, only once the whole ledger has checked.
  - **The chain:** each receipt after the first links to the one before by
    `previousReceiptHash`.
  - **The same bytes every time:** the same ledger and key always give the
    same receipts, because Ed25519 signs deterministically. A new export can
    be compared with an earlier one.
  - **`--out`** never replaces a file without `--force`.
- **What a receipt holds:**
  - `tool_name`: the tool as its server names it.
  - `decision`: `allow`, `deny`, or `rate_limit` for a call over the rate
    limit.
  - `reason`: the rule the record names, such as the one that refused the
    call.
  - `issued_at`: when the gateway decided, as its record says. The draft
    defines `issued_at` as when the receipt was made. MCPdef signs a receipt
    when it exports it, and gives it the decision's time instead, so that the
    same ledger always gives the same receipts.
  - `issuer_id`: the key's name.
  - `mcpdef`: the server, and the `seq` of the record, which ties the receipt
    to its record in the ledger.

  It holds no caller identity, address, arguments or result.
- **What a receipt does not show.** A receipt shows a decision. It does not
  show that the tool then ran, nor what it returned. The chain shows that no
  receipt between two others was changed, taken out or moved. It cannot show
  that none were taken off the end. The export prints the last receipt's hash
  and the count: record them somewhere else, and check against them later with
  `receipts verify --last <hash> --count <n>`. `receipts verify` also says when
  the first receipt links to one that is not in the file.
- **Checking them elsewhere.** `receipts verify` checks the envelope shape,
  signed with Ed25519 or P-256 (`ES256`) keys. A receipt that names a member
  twice fails, as RFC 8785 requires: a reader that keeps the first one would
  read what was never signed. Any verifier that implements the draft's §5.2
  can check the receipts as well: the signing input is the payload's JCS form,
  and the key comes from the JWK Set.

## Hook mode: no proxy in the path

Claude Code and Codex can ask MCPdef before each MCP tool call, and MCPdef
answers by the same config a gateway runs on. There is no gateway to run and
no client config to change: the call goes to its server as it would, once
MCPdef lets it.

```text
$ mcpdef import --out mcpdef.toml        # or a config of your own
$ mcpdef hook install --config mcpdef.toml --write
updated .claude/settings.local.json, the old one kept as .claude/settings.local.json.bak
Claude Code now asks MCPdef before each MCP tool call: a server not in /home/me/proj/mcpdef.toml is refused. Its decisions go to /home/me/proj/mcpdef-audit/audit.log
```

For Codex, name it:

```text
$ mcpdef hook install --client codex --config mcpdef.toml --write
wrote .codex/hooks.json
Codex now asks MCPdef before each MCP tool call: ...
Codex runs a new or changed hook only once you trust it: open /hooks in Codex and trust this one. ...
```

A call the config refuses comes back to the model with why, as Claude Code
puts it:

```text
PreToolUse:mcp__github__delete_repo hook error: MCPdef denied (not-on-allowlist): tool 'delete_repo' is not on the allowlist for 'github'
```

- **What it judges:** what a gateway would, of what a hook sees:
  - the server's allowlist and deny list, and the active profile;
  - the policy rules, over the arguments the client is about to send.

  A transform rule that would change the arguments refuses the call: a hook
  can let a call through or stop it, not change what it sends.
- **What it cannot judge** is what only the path sees:
  - the definitions a server lists (pins, the injection scan);
  - what a call returns (result transforms, the result scan);
  - who the caller is by its token (RBAC);
  - how often calls come (rate limits, which would need state across the
    hook's processes).

  For those, put the gateway in the path, with the same config.
- **What it answers:** a refusal, with why, and exit status `2`, which
  blocks the call whatever else Claude Code reads: why goes to standard
  error and, as a `deny` answer, to standard output. An allowed call gets no
  answer and exits `0`, so Claude Code goes on as it would, asking the user
  where its own permissions say to: MCPdef never answers that a call is
  allowed, which would pass over them. A tool that is no MCP tool, such as
  `Bash`, is not MCPdef's: no answer and no record.
- **Fail closed:** a call to a server the config does not name is refused,
  as the gateway refuses one, and so is any MCP call when the config does
  not read. An event or a command line that does not read, and a panic,
  exit `2` too, which refuses whatever the call was.
- **A hook that fails before MCPdef can answer**, its program gone, killed or
  out of time, is up to the client:
  - **Claude Code** goes on with the call unless the hook says otherwise.
    The hook `install` writes says `"onFailure": "block"`, so the call is
    refused. Claude Code reads that setting from 2.1.295; an earlier one
    ignores it and goes on with the call.
  - **Codex** has no such setting and goes on with the call. Only a refusal
    MCPdef gets to make stops one there.
- **A timeout of seconds, not minutes:** the hook `install` writes gives up
  after `--timeout` seconds, 10 unless told. Both clients wait 600 seconds
  for a hook that names none, so a hook that hung would hold each MCP call
  for ten minutes.
- **Held to its bundle:** with `--bundle-trust <keys>`, the hook judges by
  the config only while the signed bundle beside it holds it, as a gateway
  held to its bundle runs it
  ([DEPLOY.md § Holding the gateway to its bundle](./DEPLOY.md#holding-the-gateway-to-its-bundle)).
  `install` writes the keys into the hook:

  ```text
  $ mcpdef hook install --config mcpdef.toml --bundle-trust /etc/mcpdef/bundle-keys.json --write
  ...
  It judges by that config only while the signed bundle beside it holds it, revision 3 now: a config changed by hand refuses every MCP call, until a bundle is applied. Whoever can edit .claude/settings.local.json can still take the hook out
  ```

  An agent that rewrites `mcpdef.toml` to let itself a tool then has every
  MCP call refused, as Claude Code puts it:

  ```text
  PreToolUse:mcp__github__delete_repo hook error: MCPdef denied (bundle-unverified): --bundle-trust judges a call only by a config the signed bundle beside it holds: /home/me/proj/mcpdef.toml is not the config that /home/me/proj/mcpdef.toml.bundle, revision 3, holds: put a signed one in place with `mcpdef bundle apply`
  ```

  Each call's hook checks what a gateway checks as it starts: the
  signature, the config byte for byte, and the floor. A refusal has no
  record, since the ledger is named by a config the hook may not judge by.
  `install` writes no hook that would refuse every call. Keep the keys, and
  the `state_dir` that keeps the floor, where the user cannot write; then
  `mcpdef bundle apply` is run by whoever can. A bundle carried in raises
  the floor at the first call it judges; where the hook cannot raise it,
  the call is refused.
- **A guardrail, not a lock:** in the user's own settings, the user can take
  the hook out or turn hooks off. In Claude Code's managed settings, only
  managed settings can: `install --write --file` puts it in
  `/etc/claude-code/managed-settings.json` on Linux,
  `/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, or
  `C:\Program Files\ClaudeCode\managed-settings.json` on Windows, run by
  whoever may write there. Either way it keeps an agent to the config; it
  does not keep its user from going around it, with another client say. For
  that, put the gateway in the path, holding the servers' credentials
  itself.
- **The record:** each decision the config makes goes to its ledger, as a
  gateway's do, with `hook = "claude-code"` or `hook = "codex"`. A write that fails is logged on
  standard error and leaves the decision as it was, as at the gateway. A call
  refused because the config does not read, or under `--bundle-trust` because
  no bundle holds it, has no ledger to go to, and no record. The call went to
  its server without
  MCPdef in between, so the record says what MCPdef decided, not that the
  call ran. `mcpdef receipts export` signs them as it signs the gateway's,
  `mcpdef audit tail` shows them, and a gateway sending spans on the same
  ledger (`[gateway.otel]`) sends theirs too. A
  config's relative paths are read from its own directory, as a gateway
  started there reads them, so the hook and a gateway write the same ledger.
- **Many at once:** each call's hook runs in a process of its own. Writers
  take turns on the ledger's lock, so hooks running at once, a gateway and
  `mcpdef call` keep one chain in one ledger.
- **Install:** `mcpdef hook install` prints the hook; `--write` merges it
  into the project's `.claude/settings.local.json`, the user's own settings
  for the project, which the repository does not share. It keeps a `.bak`,
  and every other hook there, in place of an earlier `mcpdef hook`
  (`mcpdef.exe` on Windows).
  `--file ~/.claude/settings.json` installs it for every project.
- **Install for Codex:** `--client codex` merges the hook into the project's
  `.codex/hooks.json`, in the same way. Three things differ from Claude Code:
  - The file is the repository's, not the user's own; Codex has no
    project file of the user's alone. It holds this machine's paths, so
    commit it or ignore it accordingly. `--file ~/.codex/hooks.json`
    installs the hook for every project instead.
  - Codex runs a project's hooks only in a trusted project.
  - Codex runs a new or changed hook only once the user trusts it in
    `/hooks`. Until then the hook refuses nothing, and `install` says so.
  - On Windows Codex runs a hook through `%COMSPEC% /C`, and reads
    `commandWindows` there in place of `command`. So the hook carries both:
    the POSIX line, and the line `cmd.exe` reads, each path in double quotes
    and a `\\?\` path given as the plain one. CI runs what `install` writes
    through `cmd.exe` on Windows, as Codex runs it
    (`.github/workflows/mcpdef-windows-hook.yml`).
  - A path holding `%`, `!` or a line break cannot be handed to `cmd.exe`
    safely: it expands those even in quotes. On Windows `install --client
    codex` then refuses, since Codex would go on with every call whose hook
    did not run; move the file, or put the gateway in the path. Elsewhere the
    hook is written without the Windows line.

## Filter mode: behind a proxy that routes

An estate that already routes its MCP traffic through Envoy, or through
anything that asks an authorization service as Envoy's `ext_authz` filter
does, keeps its routing: the proxy asks MCPdef about each request before it
sends it on, and MCPdef answers by the same config a gateway runs on, and
records the decision in its ledger. No upstream is opened by MCPdef; the
proxy reaches them.

```toml
[gateway]
audit = "/var/lib/mcpdef/audit.log"

[gateway.filter]
listen = "127.0.0.1:7880"   # where the proxy sends its checks
path_prefix = "/authz"      # Envoy's http_service.path_prefix, if it sets one

[[server]]
id = "github"
transport = "streamable-http"
url = "http://github-mcp:8080/mcp"   # where the proxy sends its calls
filter_path = "/github"              # the path the proxy routes to it
tools = ["list_*", "get_*"]
```

```text
$ mcpdef filter --config mcpdef.toml
mcpdef 0.5.0 filter ready · 1 server(s) routed · audit /var/lib/mcpdef/audit.log · listening 127.0.0.1:7880
```

The filter reads its config once, as it starts: a new config takes a
restart. With `--bundle-trust <keys>`, it starts only from a config the signed
bundle beside it holds, as a gateway does
([DEPLOY.md § Holding the gateway to its bundle](./DEPLOY.md#holding-the-gateway-to-its-bundle)),
and its ready line names the revision, `· bundle r8`.

In Envoy, the `ext_authz` filter goes before the router, with the body sent
along, since the body is what MCPdef judges:

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    with_request_body: { max_request_bytes: 2097152, allow_partial_message: false }
    allowed_headers:
      patterns: [{ exact: origin }, { exact: traceparent }]
    failure_mode_allow: false
    http_service:
      server_uri: { uri: "http://127.0.0.1:7880", cluster: mcpdef, timeout: 1s }
      path_prefix: "/authz"
      authorization_response:
        allowed_upstream_headers:
          patterns: [{ exact: x-mcpdef-record }]
- name: envoy.filters.http.router
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

`mcpdef` is a cluster that points at `[gateway.filter] listen`. A call the
config refuses comes back to the client from Envoy as MCPdef answered it,
a `403` with a JSON-RPC error:

```text
$ curl -s localhost:10000/github/mcp -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}'
{"error":{"code":-32001,"data":{"rule":"not-on-allowlist"},"message":"MCPdef denied (not-on-allowlist): tool 'delete_repo' is not on the allowlist for 'github'"},"id":2,"jsonrpc":"2.0"}
```

- **Which server:** the path the proxy routed, less `path_prefix`, names it:
  the `[[server]]` whose `filter_path` the path is at or below, by whole
  segments, the longest winning. `/` takes any path. Set each one to what the
  proxy routes to that server: MCPdef judges a request by the server its path
  names, and cannot see where the proxy actually sends it.
  - A path under no `filter_path` is refused (`unknown-route`), and a call
    there is recorded under the server `(unrouted)`.
  - A path that a proxy could read as another, with a `.` or `..` segment,
    a `//`, a `\` or an escaped `/`, `\` or `.`, is refused
    (`path-refused`), whatever the proxy would make of it.
- **What it judges:** what a gateway would, of what a request alone shows,
  in the gateway's order:
  - a `tools/call`: the server's allowlist and deny list, the active
    profile, the argument transforms, the policy rules, RBAC and the rate
    limit;
  - a `resources/read`, and a `resources/subscribe` as a read: the resource
    allowlist, the rules, RBAC and the rate limit;
  - a `prompts/get` and a `completion/complete`: the prompt and template
    allowlists, the rules, RBAC and the rate limit.

  A transform rule that would change a call's arguments refuses it, and so
  does a URI that is not in normal form: MCPdef cannot change what the proxy
  sends, so the server would get other arguments, or read another URI, than
  the ones judged.
- **What passes unjudged:** a list, `initialize`, a ping, a notification, a
  response, and requests other than `POST`, such as the `GET` that opens a
  server's stream. Nothing of them is recorded.
- **What it cannot judge** is what only the path sees, as in hook mode:
  - the definitions a server lists (pins, the injection scan), so a client
    sees every tool a server lists, and a call to one off the allowlist is
    refused;
  - what a call returns (result transforms, the result scan).

  For those, put the gateway in the path, with the same config.
- **The caller:** with `[gateway.auth]`, a bearer token or a client key the
  gateway issued is checked as the listener checks it, and a request without
  one gets its `401` and challenge, which the proxy hands the client. Set
  `resource` to the URL clients reach the server at, through the proxy: its
  origin is where the challenge sends them for the resource's metadata,
  `/.well-known/oauth-protected-resource`, to find where they get a token.
  `mcpdef filter` answers a `GET` of it for anyone, as a check and as a
  request, so route that path to it:

  ```yaml
  routes:
  - match: { path: "/.well-known/oauth-protected-resource" }
    route: { cluster: mcpdef }
  - match: { path_separated_prefix: "/github" }
    route: { cluster: github }
  ```

  A client certificate never reaches MCPdef, so filter mode refuses to start
  on a config that takes one. A request's `Origin`, when the proxy sends it,
  is checked as the listener checks it.
- **Fail closed:** a `POST` whose body does not reach MCPdef, or is not one
  JSON-RPC message, is refused (`invalid-request`): set `with_request_body`.
  Leave `failure_mode_allow` off, so that a check that fails stops the
  request rather than passing it.
- **The record:** each decision goes to the config's ledger, as a gateway's
  do, with `hook = "ext_authz"`, and the `x-mcpdef-record` header of the
  answer names its `seq`, for a proxy that hands it to the upstream. The
  record says what MCPdef decided, not that the call ran: the proxy sent it.
  `mcpdef receipts export` signs them as it signs the gateway's, and
  `[gateway.otel]` sends their spans. The record's peer is left out, since
  the check's peer is the proxy.
- **Not yet:** Envoy's gRPC `ext_authz`, agentgateway's MCP guardrails
  (ExtMCP, over gRPC), and a reload: restart `mcpdef filter` to take a
  changed config. CI runs this section's Envoy configuration against `mcpdef
  filter` on every change, with Envoy 1.35.

## Traces: each call as an OpenTelemetry span

With [`[gateway.otel]`](./CONFIG.md#gatewayotel--spans-to-an-opentelemetry-endpoint),
the gateway sends each governed request it records to an OTLP/HTTP endpoint,
as an OpenTelemetry span: evald's, an OpenTelemetry Collector's, or any
tracing backend's. The span is the gateway's part of the agent's trace. In it,
a tool call sits beside the agent's own spans, such as those of its model
calls and what they cost.

```toml
[gateway.otel]
endpoint = "http://127.0.0.1:4318"   # evald, where it listens by default
token = { env = "EVALD_TOKEN" }      # when evald is started with --auth-token
```

A real run: evald, an agent's model call in trace `4bf92f35…` as its span
`00f067aa…`, and two tool calls the agent makes in it through the gateway,
one of which the allowlist refuses:

```text
$ curl -s http://127.0.0.1:7878/mcp -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,
    "method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"},
    "_meta":{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}}'
$ curl -s http://127.0.0.1:4318/v1/traces/4bf92f3577b34da6a3ce929d0e0e4736 \
    -H "Authorization: Bearer $EVALD_TOKEN"     # a few members of each span:
service        name                    parent            oi_kind  status
triage-agent   chat claude-sonnet-4-5  -                 LLM      -
mcpdef         tools/call echo         00f067aa0ba902b7  TOOL     -
mcpdef         tools/call delete_repo  00f067aa0ba902b7  TOOL     2 not-on-allowlist
```

So one query to evald answers what a run cost and what it did:

```text
$ cat run.sql
SELECT trace_id,
       SUM(CASE WHEN oi_kind = 'LLM' THEN 1 ELSE 0 END) AS model_calls,
       SUM(cost_usd) AS cost_usd,
       SUM(CASE WHEN oi_kind = 'TOOL' THEN 1 ELSE 0 END) AS tool_calls,
       SUM(CASE WHEN oi_kind = 'TOOL' AND status_code = 2 THEN 1 ELSE 0 END) AS refused
FROM spans GROUP BY trace_id
$ jq -Rs '{sql: .}' run.sql | curl -s http://127.0.0.1:4318/v1/sql -H "Authorization: Bearer $EVALD_TOKEN" -d @-
{"columns":["trace_id","model_calls","cost_usd","tool_calls","refused"],"rows":[{"cost_usd":0.0081,
"model_calls":1,"refused":1,"tool_calls":2,"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}],…}
```

- **Joining the agent's trace.** A span is in the trace the request's W3C
  `traceparent` names, under the caller's span. It is read from:
  - `params._meta.traceparent`, where the OpenTelemetry conventions for MCP
    put it (SEP-414), over stdio and HTTP alike;
  - else the request's `traceparent` HTTP header, which an instrumented HTTP
    client sends.

  A request with neither, or with one that does not read, is a trace of its
  own. evald, like most backends, puts spans together by trace: that is how a
  tool call meets the model calls of the same run. The ledger keeps the trace
  too, as each record's `trace_id` and `parent_id`.
- **What a span holds:**

  | | |
  |---|---|
  | Name | `tools/call <tool>`, `prompts/get <prompt>`, or the method alone. The name in a call to a tool no server lists is the caller's to choose, so it is kept out of the span's name, and left to `gen_ai.tool.name` |
  | Kind | `SERVER` |
  | Status | `ERROR` for a request refused, with the rule as its message; unset for one allowed |
  | `mcp.method.name` | the method |
  | `gen_ai.operation.name` | `execute_tool` on a tool call. It is what makes it a tool's span to evald, and to the OpenTelemetry GenAI conventions |
  | `gen_ai.tool.name`, `gen_ai.prompt.name`, `mcp.resource.uri` | what the request named |
  | `error.type` | the rule that refused it |
  | `client.address`, `client.port` | where it came from, on the HTTP listener |
  | `mcpdef.agent`, `mcpdef.server`, `mcpdef.decision`, `mcpdef.rule` | the record's caller, server, `allow` or `deny`, and rule |
  | `mcpdef.seq` | the record's number in the ledger |
  | `mcpdef.tool_digest` | with a pin store, the pinned digest of the tool's definition: which definition the call ran against |
  | `mcpdef.actor`, `mcpdef.transforms` | when the record has them |

  The resource is `service.name`, `mcpdef` unless `service_name` says
  otherwise, and `service.version`. A span holds no arguments, no result and
  no credential, as the ledger holds none. The records the gateway writes of
  itself (`agent = "mcpdef"`), such as admin actions, reloads, upstream events
  and findings at an upstream's connection, are no agent's request, and become
  no span.
- **The same span every time.** A span is made from its record alone, and
  its id from the record's hash. So `mcpdef audit tail --format otlp`, run on
  the ledger later, gives the spans the gateway sent, ids and all. evald's
  trace views show a span sent twice once; its `/v1/sql` view counts each
  copy. So send again only what was not sent.
- **Delivery.** No call waits for the exporter: it reads the ledger's file, a
  second after a record is written, and sends what it finds. An endpoint that
  is down, or busy, holds back only the exporter. What is written meanwhile
  waits in the ledger, and is sent once the endpoint takes spans again. One
  that refuses spans for good has them dropped, with a log line. A restart
  starts from the ledger's end, so spans not sent before it are not sent
  after it. To send them, post the lines `mcpdef audit tail --format otlp`
  prints for those records to the endpoint's `/v1/traces`, each with
  `Content-Type: application/json`.

## Upstream supervision

MCPdef keeps each upstream running. At startup they all open at once, so
startup takes about as long as the slowest.

- **An upstream that cannot start** (its command fails, its URL refuses the
  connection, its handshake is rejected, or it takes longer than
  `upstream_timeout_ms` to open) does not stop the gateway. It starts **down**,
  the log and the ready line name it, and MCPdef keeps trying it in the
  background. Under `[gateway] strict = true` it fails the start instead,
  `initializing upstream '<s>': <why>`: a strict gateway starts whole or not
  at all.
- **A stdio server's `[server.env]` is read each time it starts**, a restart
  included, so a secret rotated in its file is picked up then. A value that
  cannot be read, a file gone or a command that failed, is why it could not
  start. A reload that finds such a file changed starts the server again, on
  its new value.
- **An upstream that goes down is started again.** Down means a stdio server's
  process exited or its pipes closed, a legacy SSE stream ended, a
  Streamable-HTTP server ended the session (`404` on its `Mcp-Session-Id`), or
  **5 calls in a row** to an HTTP upstream (`streamable-http`, `sse`) failed or
  timed out. A restart spawns the process again (or opens a new HTTP session),
  runs the handshake, lists the tools, checks them against the pins (a changed
  definition is graded, and held as a `rug-pull` unless `[gateway] pin_accept`
  takes it; a new tool is pinned on first use) and routes calls to them.
- **Backoff:** the first attempt comes 0.5 s after it went down, then 1 s, 2 s,
  4 s, 8 s, and every 10 s after that, each with up to a quarter more at random.
  An upstream that had stayed up for 30 s starts again from 0.5 s.
- **Meanwhile**, a call to it fails at once with a tool error,
  `MCPdef error: upstream '<s>' is down (<why>); MCPdef is restarting it — retry
  shortly`, audited as `upstream-down`. Its tools stay in `tools/list` while it
  restarts. Calls to the other upstreams carry on untouched.
- **Health**, per upstream: `starting` (opening), `up`, `degraded` (open, but
  its last call failed or timed out), or `down`. `GET /api/v1/servers` shows it
  with the restart count and the last error, and `/metrics` has
  `mcpdef_upstream_up{server}` and `mcpdef_upstream_restarts_total{server}`.
  For an HTTPS upstream, `/api/v1/servers` also shows how its certificate was
  checked and the certificate it presented, and `/metrics` when that
  certificate expires; see [Monitoring](#monitoring).
- **The ledger** records each upstream going down and coming back up as a
  record of its own: `kind = "upstream"`, `agent = "mcpdef"`, `method` = `down`
  or `up`, and `rule = "upstream-down"` for a down. A change to its tools is
  one too, `method = "tools-changed"`: see
  [When an upstream's tools change](#when-an-upstreams-tools-change). Why it went down is in the
  log and on `/api/v1/servers`, not in the ledger: an error message can carry
  what a ledger must not, such as credentials in a URL. An upstream with
  `insecure_skip_verify` gets a record for every connection opened to it:
  `method = "connect"`, `decision = "allow"`, `rule = "tls-verify-disabled"`.
- A sandbox (`wasm`, `wasm-component`) that traps fails only that call, as
  `upstream-error`; the sandbox stays up.
- Without `upstream_timeout_ms` nothing bounds an opening: an upstream that
  accepts the connection and never answers holds up startup, and later its
  restart, for as long as that lasts. Set it to bound both.
- A client that listed tools before an upstream came up is told over stdio,
  with `notifications/tools/list_changed`. Over HTTP it sees that upstream's
  tools on its next `tools/list`.

## When an upstream's tools change

An upstream that sends `notifications/tools/list_changed` has its tools listed
again, without a restart. MCPdef hears it from a stdio server, on a 2024-11-05
SSE bridge's stream, and in a Streamable HTTP server's answer to a request, but
not on a stream of the server's own ([WIRE.md](./WIRE.md#status)).

- **Once a burst ends.** MCPdef waits for the word to stop for 100 ms, and at
  most 1 s after it began, then lists the tools once.
- **Word sent as the upstream opens** is kept too. If it comes while the
  opening lists the tools, the list may already be out of date, so the tools
  are listed again once the upstream is in place.
- **On the same connection**, each request bounded by `upstream_timeout_ms`,
  or 30 s when that is unset. It reads every page, as an opening does,
  following `nextCursor` up to 20 pages and 10,000 tools.
- **A failed re-list changes nothing.** An error or a timeout, on any page, or
  an answer with no tool list, leaves the upstream with the tools it had. Part
  of a list would read as tools removed. The log says:
  `mcpdef: upstream '<s>' said its tools changed, but listing them again
  failed: <why>; it keeps the tools it had`. The next word tries again.
- **Each new or changed tool is judged as at connect:**
  - with `[gateway] pins`, a new one is pinned on first use, and one that no
    longer matches its pin is graded: pinned again if `[gateway] pin_accept`
    takes its grade, and otherwise hidden and refused as a `rug-pull` until
    `mcpdef pin` approves it and a reload reads the pins
    ([When a tool drifts from its pin](#when-a-tool-drifts-from-its-pin));
  - with `[gateway.inspect]`, it is scanned, and a finding is recorded with
    `method = "tools-changed"`;
  - a tool that did not change keeps its verdict and is not scanned again.
- **Every tool's `x-mcp-header` annotations are read again**, changed or not:
  a call goes out with the `Mcp-Param-*` headers they ask for now, and a
  client's are checked by them. A tool whose annotations now break the
  revision's rules is hidden and refused, and one whose annotations are mended
  is served again ([WIRE.md](./WIRE.md#status)). The log names each tool newly
  refused: `mcpdef: warning — tool '<t>' on '<s>' is not served: <why>`.
- **The allowlist and names** apply as always. A name that a second server now
  offers is a collision, and the warning is printed as at startup. Under
  `strict` it cannot refuse a start that has already happened: it is printed,
  and shown on `/api/v1/servers`.
- **The log** says what changed:
  `mcpdef: upstream '<s>' changed its tools: 1 added, 0 removed, 2 changed; 1
  no longer matches its pin and is refused until `mcpdef pin` approves it`.
- **The ledger** records it: `kind = "upstream"`, `agent = "mcpdef"`,
  `server = "<s>"`, `method = "tools-changed"`, and `tool_changes`, the counts
  of tools `added`, `removed` and `changed`, and of those newly `drifted` from
  their pins. `latency_ms` is how long the re-list took. `decision` is `allow`,
  or `deny` with `rule = "rug-pull"` when a tool drifted. A re-list that finds
  the same tools records nothing.
- **Clients:** a stdio client is sent `notifications/tools/list_changed`. An
  HTTP client, or a 2026-07-28 one, sees the change on its next `tools/list`.
- An upstream that changes its tools without saying so, or says so only where
  MCPdef does not hear it, is listed again when it next opens: restart it, or
  let a reload that changes its settings reconnect it.

## When a tool drifts from its pin

With `[gateway] pins`, each tool's definition is pinned the first time the
gateway sees it: its hash, and from 0.5.0 the definition itself. A definition
that no longer matches its pin, when an upstream opens or lists its tools
again, is graded against the one pinned, change by change, by what each could
do to an agent that calls the tool:

| Grade | What changed | For example |
|---|---|---|
| `info` | Nothing it says or does | `required`, `enum` or a list of types reordered; whitespace in a text; `1.0` for `1` |
| `risky` | It takes less, or returns less | a property required now, or gone from an object that takes no other (`additionalProperties: false`); an enum value gone; `integer` for `number`; a bound added or tightened; a `pattern`, `format`, `const` or `multipleOf` added; `additionalProperties` closed |
| `breaking` | Anything else | the description or any other text the model reads; a tool that takes or returns more, as when a property is gone from an object that takes others, which then takes any value there; a schema in a `oneOf` narrowed, which can let through a value two of them took; any annotation; a keyword MCPdef does not read, such as `$ref` |

The drift's grade is its worst change's. `[gateway] pin_accept` says which
grades the gateway takes in its stride: `info` (the default), or `risky` as
well. There is no `breaking`.

- **A drift within `pin_accept`** is pinned again, and the tool is served. The
  log says `mcpdef: upstream '<s>': '<t>' changed since it was pinned, graded
  info: <first change>, within [gateway] pin_accept: pinned again`, and the
  ledger records it: `kind = "upstream"`, `agent = "mcpdef"`, `method = "pin"`,
  the tool, `decision = "allow"`, `rule = "drift-accepted"`, and `drift`, the
  grade and each change.
- **Any other drift is held:** the tool is hidden from `tools/list`, and a
  call to it is refused with `MCPdef denied: tool '<t>' on '<s>' changed since
  it was pinned (possible rug-pull, graded breaking: description: changed (32
  → 88 characters))` and how to approve it. The call's record has
  `rule = "rug-pull"` and the same `drift`, and `GET
  /api/v1/servers/<id>/tools` gives it too. Approve it with `mcpdef pin` and a
  reload, or `POST /api/v1/servers/<id>/pins`.
- **`mcpdef diff-tools`** prints each changed tool with its grade and its
  changes, and exits non-zero only if one is held, so a cron job or CI step
  fails on what the gateway would refuse and not on what it re-pins.
- **A pin from before 0.5.0** holds the hash alone, so its drift cannot be
  graded: it is held as `ungraded`. Approving it keeps the definition, and the
  next change is graded.

A description is graded as any text: only a change of whitespace in it is
`info`. A server that rewords a description after it was approved changes what
the model reads, which is how a tool is turned against the agent that trusted
it, so a reworded description is `breaking`. For the same reason the grades
are about what reaches the agent, not about whether a caller written against
the old definition still works: a property newly required breaks such a
caller, and is `risky`, because the tool can do no more than it could.

## What the tools cost each agent

Every agent that lists the tools reads the whole `tools/list` answer into its
context before it does anything else. `mcpdef tools list --cost` says what each
server adds to it:

```text
$ mcpdef tools list --cost --config mcpdef.toml
SERVER       TOOLS           BYTES   ~TOKENS
github       4 of 4            495      ~124
files        1 of 2            120       ~30
total        5 of 6            615      ~154
BYTES is what the tools take up in tools/list, which every agent reads into its context.
~TOKENS is BYTES ÷ 4, an estimate: the real count depends on the model.
```

- **TOOLS** is how many of a server's tools are listed, of those its
  connection lists: what the allowlist, the active profile, the pins and the
  scanner leave, less a name listed from another server.
- **BYTES** is what those take up in the answer: each entry as it is sent,
  compact, by the name it is listed by (with its prefix, under
  `tool_namespace = "prefix"`) and with its `_meta`. The commas between the
  entries and the rest of the answer are not counted. The entries are the same
  bytes whichever revision the client speaks.
- **~TOKENS** is BYTES ÷ 4, rounded: an estimate, since tokenizers differ.

The command opens every upstream, as `mcpdef run` does, so it pins a new tool
on first use. A server that did not open counts `0 of 0`, and is named under
the table. To see what a profile saves, compare the count with and without
`--profile <name>`, which counts as `mcpdef run --profile <name>` would list.
Without `--cost`, `mcpdef tools list` prints each tool listed, and its server.

A running gateway shows the same counts on `/api/v1/servers`, as each server's
`listing` ([API.md](./API.md#admin-listener-gatewayadmin)). They follow the live
list: a re-list, a reload or a restart changes them.

## Reloading the config

`kill -HUP <pid>` makes a running gateway read its config again and apply it,
with no restart and no call dropped. Under systemd, that is
`ExecReload=/bin/kill -HUP $MAINPID`. So does `POST /api/v1/reload` on the
admin listener, for a caller holding `console:operator`, which answers with
what changed, or `409` with why nothing did ([API.md](./API.md#admin-listener-gatewayadmin)).
With `[gateway] watch_config = true` the
gateway also checks, every 30 s, whether the config or a file it names (a
`[gateway.auth] jwks` file, a wasm module, a certificate, key or CRL a TLS
table names, a file a `[server.env]` value is read from) changed, and reloads
if one did. A `[server.auth]` secret's file is not among them: it is read
again when the upstream answers `401`, and an `oauth2` client secret's at each
fetch of a token. The
check compares content, so it also sees a Kubernetes ConfigMap update, which
the kubelet makes by swapping a `..data` symlink rather than writing the file.
A file watcher would miss that.

- **Whole or not at all.** A config that does not parse or validate, or whose
  pin store does not load, is refused as `invalid-config`, and so is one with
  anything to warn about when it sets `[gateway] strict = true`. One that
  changes a setting only a restart can apply is refused as `restart-required`:
  the `[gateway]` keys `listen`, `allowed_origins`, `max_inflight`, `wire`,
  `audit` and `audit_fsync`, `[gateway.admin]`'s `enabled` and `listen`, the `[gateway.auth]`
  table, a `jwks` file's content included, and TLS turned on or off on either
  listener. A listener certificate that does not read, or a name the local CA
  does not vouch for, is refused as `invalid-config`. A refused config changes
  nothing, and the gateway
  keeps serving the one it had. The watch refuses a config once, not every
  30 s, and looks again when the content changes.
- **What applies**, as one step for every call that starts after it: the
  allowlists, denies and profiles, `[[policy]]` rules, `[[role]]`s,
  `upstream_timeout_ms`, `[gateway.inspect]`, `[gateway.egress]`,
  `[gateway.rate_limit]` (changed limits start with full buckets) and the pin
  store. The upstreams are matched by `id`:
  - **added**: it opens before the new config takes effect, so its tools are
    there as soon as the config is. One that does not open starts down and is
    retried, as at startup;
  - **removed**: it takes no new calls. The calls it is running finish, then
    it closes;
  - **changed**, in how it is reached (`transport`, `command`, `url`, `env`,
    `spec`, `max_inflight`, a sandbox limit, its wasm module's content,
    `[gateway.egress]` for an HTTP one, or for an HTTPS one its TLS profile:
    `[server.tls]`, `[gateway.upstream_tls]` under it, or the content of a
    file either names, so a certificate renewed in place is picked up, or for
    a stdio one the content of a file its `[server.env]` reads): a
    second connection opens on its new
    settings, new calls go to it, and the old one closes after its last call.
    If the new settings do not start, the upstream serves on its old
    connection while they are retried with the usual backoff. Neither case
    counts as a restart. If the old connection goes down meanwhile, that
    upstream is down like any other, and comes back on its new settings;
  - **unchanged**, or changed only in its `tools`, `deny` or `profile`: it
    keeps its connection;
  - the order of the `[[server]]` entries is the order calls prefer when two
    upstreams list the same tool.
- **A call in flight** finishes under the configuration it started with,
  connection included.
- **The pin store is read again** on every reload, and every upstream's tools
  are checked against it as it now stands. After `mcpdef pin` re-approves a
  tool, `kill -HUP` lets it back in.
- A `--profile` given at launch applies again on every reload.
- **Under `--bundle-trust`**, a reload runs only a config the signed bundle
  beside it, `<config>.bundle`, holds, as at the start: one it does not hold
  is refused as `bundle-unverified`, and one older than the floor or than the
  revision running as `bundle-older`, whatever else is wrong with it. A floor
  that does not read refuses it as `invalid-config`. A change to the bundle
  alone is a change to the watch. A config taken above the floor raises it
  ([DEPLOY.md § Holding the gateway to its bundle](./DEPLOY.md#holding-the-gateway-to-its-bundle)).
- **The ledger** records every reload, applied or refused: `kind = "reload"`,
  `agent = "mcpdef"`, `server = "(config)"`, `method = "reload"`, `actor` =
  `sighup`, `watch`, or for one asked through the admin API, its caller
  (`local`, `cert:<identity>`), with the address it called from as `peer`;
  and `latency_ms` = how long the reload took. An admin API caller without
  the role an action needs is refused, and that is recorded too:
  `kind = "admin"`, `method` the action, `decision = "deny"`,
  `rule = "console-role"`, and the caller as `actor`.
  `config_from` and `config_to` hold the digests of the config that ran and
  the one read. `decision` is `allow`, or `deny` with `rule` =
  `invalid-config` or `restart-required`, or under `--bundle-trust`,
  `bundle-unverified` or `bundle-older`, and then `bundle` names the bundle
  beside the config. A digest is `sha256:<hex>` over the
  config's bytes and the content of each file it names, so it changes when a
  wasm module does.
- **The log** says what changed, or why nothing did:
  `mcpdef: config reloaded (sighup): added b; removed a; now sha256:9c1e0b7d4f2a`,
  `mcpdef: config reloaded (admin API, local): …`
  or
  `mcpdef: config reload refused (watch), restart-required: [gateway] listen (127.0.0.1:7878 → 0.0.0.0:7878) changed; still serving sha256:41d0c3a9b8e7`.
  A digest in the log is cut to its first 12 hex digits, and under
  `--bundle-trust` each line ends with the revision running, `· bundle r8`.
  After a reload it applies, the gateway prints the new config's warnings, as
  a start does.
- `/api/v1/servers`, `/api/v1/status` and `mcpdef_upstreams` show the reloaded
  config. A client sees new tools on its next `tools/list`.
- A `jwks_uri` refresh goes out with the reloaded `[gateway.egress]` and
  `[gateway.upstream_tls]`, reading the files the latter names afresh.
- On Windows there is no `SIGHUP`; `watch_config` is the only trigger.

## Serving HTTPS

`[gateway.tls]` puts the listener on TLS, and the admin listener with it
unless `[gateway.admin.tls]` says otherwise. Keys and details:
[CONFIG.md § TLS on MCPdef's own listeners](./CONFIG.md#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners).

**On one machine, or a private network: `self-signed`.**

1. Name the hosts clients use besides `localhost` in `hostnames`, and set
   `mode = "self-signed"`. The local CA vouches for the names it is made with
   and no others, so name them first.
2. `mcpdef tls init` makes the CA and the listener's certificate under
   `[gateway] state_dir`, and prints how each client trusts the CA:
   `export NODE_EXTRA_CA_CERTS=<ca.crt>` for Claude Code,
   `export CODEX_CA_CERTIFICATE=<ca.crt>` for Codex, and the command that
   adds it to the system's store, which VS Code and Cursor read.
   `mcpdef tls export-ca --out ca.crt` hands the certificate to another
   machine; the key stays where it is.
3. `mcpdef up`. The ready line says `listening streamable-http <addr> · tls
   self-signed`, and clients connect to `https://<host>:<port>/mcp`.

The certificate lasts thirty days, and the running gateway issues it again
with ten left, under the same CA; nothing has to be trusted again. A gateway
stopped for longer issues one as it starts. A new name needs a new CA:
`mcpdef tls init --new-ca`, then every client trusts the new one. Until then
the gateway refuses to start or reload with that name, and says so.

**Behind a public name: `files`.** cert-manager, certbot or your own PKI
writes the certificate and key; `cert` and `key = { file = … }` name them.
With `watch_config = true` the gateway serves a renewed pair within 30 s of it
landing, and a `SIGHUP` does it at once. A pair that does not read, a key
that is not the certificate's say, refuses the reload and the pair before it
serves on. Claude's custom connectors reach a gateway from the internet, so
they need this, or a TLS-terminating edge in front.

**Either way:**

- `mcpdef tls show` prints what each listener serves: its certificate's
  names, issuer, expiry and fingerprint, the local CA's, and each HTTPS
  upstream's profile, with a warning for a certificate that expired or soon
  will.
- A connection keeps the certificate it was accepted with; a swap serves every
  connection after it.
- Turning TLS on or off needs a restart: it changes every client's URL.
- A listen address other than loopback with neither TLS nor `[gateway.auth]`
  is warned about, and refused under `strict`.

### Client certificates (mTLS)

`[gateway.tls.client_auth]` asks each client for a certificate, from the CAs
in `ca`, and takes one of its names as who the client is: see
[CONFIG.md § mTLS](./CONFIG.md#gatewaytlsclient_auth--mtls-client-certificates-as-identity).
It is for SDK, workload and mesh callers, which can present one; most
interactive clients cannot yet, and use a bearer token.

1. Give the agents' CA, or the SPIFFE trust bundle spiffe-helper writes, in
   `ca`, the CRLs in `crl` if your PKI publishes them, and pick `identity`.
   Start with `mode = "optional"`: clients without a certificate keep working
   while the ones with one start to be named by it.
2. Map identities to roles with `[[identity.cert_map]]`. A certificate no
   entry maps holds no role: with `[[role]]`s defined, it is granted nothing.
3. `mcpdef tls show` prints what each listener asks: `client certs :
   required, identity spiffe`, the trust domains, and the CA and CRL files.
4. When every caller presents one, `mode = "required"`, or
   `[gateway.auth] methods = ["mtls"]`, or both a token and a certificate with
   `methods = ["bearer", "mtls"]` and `require = "all"`: the token's subject is
   then the record's `agent`, and the certificate its `actor`.

**With no PKI of your own**, the local CA issues them. `mcpdef tls issue
--client ci-bot --spiffe-id spiffe://prod.acme.internal/ns/ci/sa/bot --out
./certs` writes `ci-bot.crt` and `ci-bot.key`, the key readable by you alone,
for the workload to present; prints the serial that revokes it; and prints
the `[gateway.tls.client_auth]` that takes it, with the local CA as `ca` and
its CRL, `<state_dir>/tls/ca.crl`, as `crl`. Its common name is `ci-bot`, for
`identity = "subject-cn"`, and its SPIFFE ID, if given, is for `identity =
"spiffe"`. It carries no DNS name: the local CA vouches for the listeners'
names alone, so `san-dns` cannot read one of its clients. Before a
certificate is written it is checked, and each of its names read, as the
gateway would check and read it. It lasts 30 days unless `--days` says
otherwise. `mcpdef tls revoke <serial>`, or `mcpdef tls revoke ci-bot.crt`,
puts it in the CRL; the next reload refuses it.

**Rotating and revoking.** A new CA bundle or CRL, written over the files the
config names, applies at the next reload: within 30 s with `watch_config`,
at once with `SIGHUP`. It applies to the next request on a connection already
open as well as to new connections, so a revoked certificate stops working
everywhere, without a restart and without closing anything. A file that does
not read refuses the reload and the bundle before it stays in force.

**What the log and the ledger show.** A certificate refused at the handshake
is logged, `mcpdef: refused the client certificate <addr> presented: <why>`;
no request was made, so no record. A request refused for its certificate
afterwards is answered `403`, saying why, and is not recorded either, as a
request refused for its token is not. A governed call's record names the
certificate, `cert:<identity>`, and the address it came from, `peer`.

**Behind a proxy that terminates TLS.** When Envoy, or an Istio sidecar or
gateway, checks clients' certificates in front of MCPdef, set
[`[gateway.trusted_proxy]`](./CONFIG.md#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front):
the addresses the proxy connects from, and the header it forwards each
client's certificate in. MCPdef then reads that header from the proxy alone,
checks the certificate against `[gateway.tls.client_auth]` as if the client
had presented it at its own handshake, and reads who the client is. The
listener can serve plain HTTP: keep it where only the proxy reaches it, such
as on the pod's loopback beside a sidecar.

1. Have the proxy set the header, never append to it or pass on what its
   client sent. For Envoy, on the route to MCPdef:

   ```yaml
   forward_client_cert_details: SANITIZE_SET
   set_current_client_cert_details:
     cert: true    # MCPdef checks the certificate itself
     chain: true   # and its intermediates, when an intermediate CA issues it
   ```

   and `client_cert_header = "x-forwarded-client-cert"`. A proxy that writes
   RFC 9440's `Client-Cert` takes the default.
2. Give in `cidrs` the address MCPdef sees the proxy connect from: a
   sidecar's, on the pod's loopback (`127.0.0.0/8`); a gateway's pod range;
   never a service's virtual IP, which no connection comes from.
3. `mcpdef tls show` prints `trusted proxy: <header> from <cidrs>`, and the
   ready line says `· <header> from a trusted proxy`.

Each record's `peer` is then the proxy's address. A forged header from any
other peer is not read, so it names no one: under `mode = "required"` its
request is refused with `403 a client certificate is required`.

## The console: signing in, automation and break-glass

Signing people in ([SSO.md](./SSO.md), provider by provider; [CONFIG.md § `[gateway.admin.oidc]`](./CONFIG.md#gatewayadminoidc--signing-people-in-to-the-console)):

1. `mcpdef sso init --provider <keycloak|entra|okta|google|authentik|generic|saml-broker>`
   prints what to set at the provider and the config for it (`--write`
   merges the config in). In short: register a confidential client with the
   identity provider: its redirect URI `<public_url>/callback`, its
   post-logout redirect URI `<public_url>/`, the authorization code grant
   with PKCE. Where groups say who may do what,
   have the provider put them in the ID token (a `groups` scope or claim
   mapper), or set `userinfo = true` where it puts them there alone.
2. Give people console roles: roles the provider puts in a claim
   `roles_claims` reads (`console:viewer`, `console:operator`,
   `console:admin`), or groups `[[identity.role_map]]` maps to them.
3. Restart the gateway (the identity provider is read at start), open
   `<public_url>`, and sign in. Someone given no console role sees what
   MCPdef received of them: the claim names to map are there.

A SAML identity provider (ADFS, Entra ID, Okta, Shibboleth) signs people in
through a broker that checks its assertions and speaks OpenID Connect to
MCPdef: [SAML.md](./SAML.md), and
[deploy/compose/sso-saml](../deploy/compose/sso-saml) to try it on one
machine.

Each sign-in, refusal and sign-out is an `admin` record: `mcpdef audit tail
--format json | jq 'select(.method == "sign-in")'`. A refusal's `rule` says
why: `sign-in-state` (the sign-in started elsewhere, took over ten minutes,
or was replayed), `sign-in-issuer`, `sign-in-provider` (the provider, its
token endpoint or its discovery failed), `sign-in-token` (the ID token, or
the subject `[identity]` names), `sign-in-userinfo`, `no-console-role`. Past twenty refused in a minute, one more record, with the rule
`sign-in-refusals-unrecorded`, says the rest of that minute's are not
recorded: anyone who reaches the listener can be refused, so the ledger grows
by so much at most.

**Automation** calls the admin API with a token the provider issues for
`[gateway.admin.oidc] api_audience` (an API registered with it, and a client
credentials grant): `mcpdef:admin:read` to read, `mcpdef:admin:write` to
reload, restart, test and approve drift. Its records name it
`token:<subject>`.

**Break-glass**, for when no one can sign in:

1. Before you need it: `mcpdef admin token` prints a token, once, and the
   `[gateway.admin.break_glass]` table that keeps its SHA-256. Put the table
   in the config and reload; put the token offline, in the safe or the
   vault the on-call reaches in an emergency.
2. In an emergency: `curl -H "Authorization: Bearer mcpdef_bg_…" https://<admin>/api/v1/…`.
   The token holds `console:admin`.
3. Every request it makes is recorded, before it is served: `mcpdef audit
   tail --format json | jq 'select(.actor == "break-glass")'`. Review them.
4. After, make a new token, put its table in the config and reload: the old
   token opens nothing from then on. Remove the table to have none.

## Client keys

For an MCP client with no identity provider to get a token from:

1. `mcpdef keys create --name <client> --role <role>` prints a key, once,
   and the `[[key]]` table that keeps its SHA-256. Put the table in the
   config, with `"key"` in `[gateway.auth] methods`, and reload.
2. Give the client the key as a secret: `mcpdef connect <client>
   --token-env MCPDEF_KEY` writes an entry that sends it from that variable.
3. Its calls are recorded as `key:<client>`. To revoke a key, remove its
   table and reload: from the next request it opens nothing.

## Monitoring

The audit ledger is the source of truth, and the optional **admin listener**
(`[gateway.admin]`, off by default) exposes it for humans and scrapers on a
separate port: Prometheus `GET /metrics`
(`mcpdef_tools_calls_total{server,tool,decision,rule}`, a call-latency histogram,
`mcpdef_upstreams`, `mcpdef_upstream_up{server}`,
`mcpdef_upstream_restarts_total{server}`, `mcpdef_upstream_cert_expiry_seconds{server}`,
`mcpdef_upstream_auth_failures_total{server}`,
`mcpdef_credential_expiry_seconds{server,credential}`, `mcpdef_uptime_seconds`), a
JSON API
([API.md](./API.md#admin-listener-gatewayadmin)), and the console at `/`. It
signs its callers in as [`[gateway.admin]`](./CONFIG.md#gatewayadmin--the-admin-listener-console-api-and-metrics)
says: on loopback with nothing set, anyone on the machine is admin. Where it
signs callers in, a scraper is one: [DEPLOY.md](./DEPLOY.md#metrics--grafana)
says how Prometheus authenticates. What to watch:

- **Deny spikes:** `mcpdef audit tail --format json` → `decision:"deny"` grouped
  by `rule`. A burst of `rate-limited` = an agent loop or an undersized bucket;
  `rug-pull` = a server changed a pinned tool; `not-on-allowlist`/`rbac` = an
  agent probing beyond its grants; `bundle-older` = a signed policy bundle
  older than the one applied, replayed; `bundle-unverified` = a bundle no
  trusted key signed as it is, or, on a gateway's reload under
  `--bundle-trust`, a config its bundle does not hold: one written by hand.
  An allowed record with
  `rule = "drift-accepted"` is a change `[gateway] pin_accept` took, with its
  grade.
- **Latency:** each record carries `latency_ms`; `upstream-timeout` records
  mean a wedged upstream.
- **Upstream health:** `mcpdef_upstream_up == 0` for more than a restart or
  two, or a climbing `mcpdef_upstream_restarts_total` (a crash loop), and
  `kind = "upstream"` records in the ledger.
- **Upstream certificates:** `mcpdef_upstream_cert_expiry_seconds - time() <
  14 * 86400` (an HTTPS upstream's certificate expires within two weeks).
  It is when the certificate that upstream's server presented last expires,
  as a Unix time, and it is there for each HTTPS upstream that has opened.
  `/api/v1/servers` shows the same certificate's `fingerprint` and
  `not_after`, and `verify`: `ca`, `pin` or `disabled`. A certificate is
  seen when a response comes over it, so after a renewal the new one shows
  once a connection makes a full handshake with the server. A connection kept
  alive, or one that resumes an earlier TLS session, is still vouched for by
  the certificate it began with, and shows that one. A pinned upstream's
  expiry is shown too, though a pin does not check it.
- **Credentials:** a climbing `mcpdef_upstream_auth_failures_total` means an
  upstream refuses MCPdef's credentials, or MCPdef has none to send it: the
  calls audited as `upstream-auth-failed` and `credentials-unavailable`, and
  the openings that failed so. Its `credential` on `/api/v1/servers` says
  when the upstream last took them (`last_ok`), and the last failure and why
  (`last_error`). And
  `mcpdef_credential_expiry_seconds{credential="client_cert"} - time() <
  14 * 86400`: the certificate MCPdef presents to an HTTPS upstream
  (`client_cert`) expires within two weeks. Replace the file before then; a
  reload, or the next restart of that upstream, reads it again. An `oauth2`
  token's expiry is `credential="token"`. It is not one to alert on: a
  token is fetched when a request needs one, so one past its expiry only
  means no call has gone to that upstream since.
- **Refused reloads:** `kind = "reload"` records with `decision:"deny"`: a
  config change that did not apply, so what runs is not what is on disk.
- **Drift at startup:** the ready line's `⚠ N rug-pulled tool(s) denied`, or
  `mcpdef diff-tools` in cron/CI (exits non-zero on a drift the gateway holds).
- **Chain integrity:** scheduled `mcpdef audit verify` (+ sealed `--head/--count`).
- **Process:** it is one foreground process; supervise it with systemd or a
  container restart policy. MCPdef supervises its upstreams, not itself. HTTP `503` responses (shed load) are visible to clients, not
  logged by mcpdef.

## Troubleshooting (symptom first)

What the client sees → why → what to do. Full gate semantics in
[API.md](./API.md#toolscall-gate-order).

Start with `mcpdef doctor --config <file>`. It checks the config, the TLS of
the listeners, the identity provider's keys and clock, the admin listener and
every upstream in one report, and names many of the causes below.

| Symptom (exact error/status) | Cause | Fix |
|---|---|---|
| Console: `503 Sign-in unavailable` with why; stderr at start: `mcpdef: the console's identity provider was not found: …` | `[gateway.admin.oidc] issuer`'s discovery document, or its keys, could not be read: the provider is down, the egress guard or `[gateway.upstream_tls]` refuses it, or its `issuer` is not written exactly as the config's | Fix what the message names. The gateway looks again at a sign-in, at most every 5 seconds; nothing else waits on it. |
| Console: `400 Sign-in refused`: `… the answer came from …` or `… does not say which provider sent it …` | The provider's answer carried another `iss`, or none where its discovery document says it sends one | A proxy or a second provider in the path; the issuer configured is not the one people sign in at. |
| Console: `400 Sign-in refused`: `its ID token: invalid token: InvalidAudience` | The ID token was not issued to `client_id` | Set `client_id` to the client registered with the provider. |
| Console: `403 No console role` | The provider signed them in, and none of the roles `[identity]` read from their claims is a console role | Give them one at the provider, or map a claim the page lists with `[[identity.role_map]]`. |
| Admin API: `401 Bearer token refused` | A bearer token that is neither the break-glass token nor one the provider issued for `api_audience`, or one expired | A token for the MCP listener does not open the admin API: ask the provider for one for `api_audience`. |
| Tool result `isError:true`: `MCPdef denied: tool '<t>' is not on the allowlist` | Server has a `tools = […]` allowlist and `<t>` is not on it | Add the tool to `[[server]] tools` (or the profile), then reload (`kill -HUP`). Deliberate deny-by-default. |
| `MCPdef denied: tool '<t>' matches deny pattern '<p>' …` | A `deny` glob (server or profile) matched; deny wins over allow | Remove/narrow the glob if the tool is legitimate. |
| `MCPdef denied: tool '<t>' is not in the gateway's active profile` | `[gateway] profile` (or `--profile`) scopes the whole surface | Run without the profile override or extend `[profile.<name>] tools`. |
| `MCPdef denied: transform rule '<r>' could not apply to the result of '<t>' on '<server>': <why>` | A `transform` rule's `result` edit met a result it cannot edit: a `mask` of something that is not a string, a `redact` of a secret in an object's key, or an edit the tool's `outputSchema` may not allow (a string it constrains, a key it requires, a place MCPdef cannot check) | The call ran: only its result was withheld. Narrow the rule's `tools` or its path, `remove` what the schema does not require, or set `on_error = "skip"`. |
| `MCPdef blocked: … matched secret-exfil rule '<id>', which MCPdef could not redact: <why>` | `[gateway.inspect] mode = "redact"` found a secret it could not redact: one the tool's `outputSchema` constrains, one in an object's key, or one where the redaction of strings does not reach, such as an image's base64. It refused the result as `enforce` would | Keep the secret out of that place upstream, or, for a field, mask one the schema does not constrain. |
| `MCPdef denied: transform rule '<r>' could not apply to '<t>' on '<server>': <why>` | A `transform` rule's edit met arguments of another shape: a `clamp` of something that is not a number, or a path through something that is not an object | Fix what the caller sends, or narrow the rule's `tools` / `args`. `on_error = "skip"` on the rule lets such a call go on without it. |
| `MCPdef denied: no governed server exposes tool '<t>'` | No running upstream lists that tool, and no upstream that has not started names it in its `tools` | Check the upstream actually exposes it. Tools are listed when an upstream opens, and again when it sends `notifications/tools/list_changed` where MCPdef hears it ([When an upstream's tools change](#when-an-upstreams-tools-change)). An upstream that adds tools without saying so is listed again only when it opens again: restart that upstream, and MCPdef lists its tools when it starts it again, or restart MCPdef. |
| stderr: `mcpdef: upstream '<s>' said its tools changed, but listing them again failed: <why>; it keeps the tools it had` | The upstream announced a change, then refused or did not answer `tools/list` in time | Check the upstream. Its next `notifications/tools/list_changed` lists them again, as does its next opening. |
| A tool vanished from `tools/list` while its server stayed up, and a call to it is `MCPdef denied: … changed since it was pinned (possible rug-pull, graded …)` | The server changed the tool's definition and said so. The re-list found it no longer matches its pin. The ledger has a `tools-changed` record with `rule = "rug-pull"` | Review with `mcpdef diff-tools`; if legitimate, re-approve with `mcpdef pin`, then reload (`kill -HUP`), or approve it from the admin API (`POST /api/v1/servers/<id>/pins`), which saves the pin and serves the tool at once. |
| warning: `tool '<t>' is offered by '<a>' and '<b>': it is listed once, from '<a>', and a call to it goes there` (`strict: …`, and no start, under strict mode) | Two servers' allowlists both take a tool of that name. A client sees one tool, and every call to it goes to `<a>` | Take the name off one server's allowlist (`deny`), or set `[gateway] tool_namespace = "prefix"` to list each as `<prefix>__<t>`. The admin servers view lists it under `tool_collisions`. |
| `MCPdef denied: no governed server exposes tool '<t>'`, with `tool_namespace = "prefix"` | Each tool is called by its listed name, `<prefix>__<name>`: a name without a prefix, or with one no server has, is no tool's | Call the name `tools/list` gives. A server's prefix is its `prefix`, or else its `id`. |
| `MCPdef denied: server '<s>' is not governed by MCPdef` | Tool routed to a server with no policy entry (fail-closed) | Add a `[[server]]` entry for it. |
| `MCPdef denied: no role grants '<t>' on '<s>'` | RBAC: the caller's roles hold no matching `[[role]]` grant: a token's scopes/roles, or, for a client certificate without a token, the roles `[[identity.cert_map]]` gives its identity | Grant `"<server-glob>:<tool-glob>"` to a role the caller holds, or fix the IdP scopes. For a certificate, map its identity to a role in `[[identity.cert_map]]`: one no entry matches holds none. |
| `MCPdef denied: tool '<t>' on '<s>' changed since it was pinned (possible rug-pull, graded <grade>: <change>)` | Pinned definition drifted (description/schema/annotations changed), graded worse than `[gateway] pin_accept` takes, or `ungraded` for a pin from before 0.5.0 ([When a tool drifts from its pin](#when-a-tool-drifts-from-its-pin)) | Review with `mcpdef diff-tools`; if legitimate, re-approve with `mcpdef pin`, then reload (`kill -HUP`), or from the admin API (`POST /api/v1/servers/<id>/pins`). The tool is also hidden from `tools/list` until re-pinned. |
| `MCPdef denied: global/tool rate limit exceeded … — retry shortly` | Token bucket empty (`[gateway.rate_limit]`) | Retry with backoff; raise `*_per_sec`/`*_burst` if the budget is undersized. |
| `MCPdef denied: tool '<t>' on '<s>' asked for input, which MCPdef passes on only to a 2026-07-28 client` | A 2026-07-28 server asked the client for something first (an elicitation, a sampling, its roots), in an `InputRequiredResult`, and the client speaks 2025-11-25, which cannot read one. Audited under `input-required`. A read or a prompt get says the same, as JSON-RPC error `-32000` | Use a 2026-07-28 client, or a way to call the tool that needs no input. See [WIRE.md](./WIRE.md#status). |
| `MCPdef denied: tool '<t>' on '<s>' asked for input the client cannot give: <why>` | The server asked for something the client did not declare it can answer (a sampling from a client that declared only `elicitation`, an elicitation in URL mode from one that did not declare `elicitation.url`), or its interim result breaks the revision's rules. Audited under `input-required` | Declare the capability in the client, if it can answer that. A server that asks for what was not declared, or sends a malformed result, is at fault: report it to its maintainers. |
| stderr: `mcpdef: upstream '<s>' asked its client for `<m>`, which MCPdef does not relay; it was refused` | A 2025-11-25 server sent its client a request of its own (`elicitation/create`, `sampling/createMessage`, `roots/list`). MCPdef answered it with `-32601`, and the server's call goes on with that answer | Expected. Through MCPdef, a server can ask for input only on the 2026-07-28 wire: set its `spec = "2026-07-28"` if it speaks that revision. |
| `-32601 MCPdef denied: method '<m>' is not one MCPdef serves: …` (HTTP `404` on the modern wire) | The client sent a method MCPdef neither answers nor routes, such as `logging/setLevel` or `tasks/get`. Until 0.4 such a request went to the first server, ungoverned | Deliberate: MCPdef fails closed. The ledger's `method-not-found` records name each method and who sent it. A client that must have one has to reach that server some other way. |
| `MCPdef error: upstream '<s>' did not respond to '<t>' within <n>ms` | `upstream_timeout_ms` fired; upstream wedged or slow. The time counts waiting for a slot under `[[server]] max_inflight` too | Check the upstream process/endpoint; raise the timeout for legitimately slow tools, or `max_inflight` if calls queue behind each other. |
| `MCPdef error: upstream '<s>' is down (<why>); MCPdef is restarting it — retry shortly` | The upstream did not start, or went down: its process exited, its stream or session ended, or 5 calls in a row to it failed. Audited as `upstream-down`; calls to other upstreams carry on | Retry: MCPdef restarts it with backoff. If it stays down, the log's `did not start: …` lines and `GET /api/v1/servers` say why. |
| `MCPdef error: upstream '<s>' failed the call: <why>` | The upstream could not take or answer this one call: an HTTP error status with no JSON-RPC body, a refused connection, a sandbox trap. Audited as `upstream-error` | Check the upstream's own logs. 5 in a row to an HTTP upstream count as down, and MCPdef connects it again. |
| `MCPdef error: upstream '<s>' refused MCPdef's credentials: <url> answered 401 Unauthorized` | The upstream refused the `[server.auth]` credentials, and reading the secret again gave nothing it takes. Audited as `upstream-auth-failed` | Put a credential it takes where `[server.auth]` reads it: the next refused request reads it again. 5 refusals in a row count as down, and MCPdef connects it again, reading every secret afresh. |
| upstream `<s>` down: `<url> answered 401 Unauthorized` | It asks for credentials at its opening: none are set in `[server.auth]`, or it refused them | Set `[server.auth]`, or fix its secret. MCPdef tries again with the backoff. |
| warning: `server '<s>': [server.auth] sends its credentials over plain HTTP to <host>` | Its `url` is `http://` to another machine: anyone on the path can read the credential | Use `https://`. |
| `MCPdef error: no credentials for upstream '<s>': token endpoint <url> answered <status>: <code>` | Its `oauth2` token endpoint refused to issue a token, so the call was not sent. Audited as `credentials-unavailable` | Go by the code. `invalid_client`: the `client_id` or `client_secret` is wrong, or `client_auth` is not the method the server expects. `unauthorized_client`: the client may not use the client credentials grant. `invalid_scope`: a scope in `scopes` is not the client's. `invalid_target`: the server does not know the `resource` (by default the server's `url`): set it to the one it knows, or `resource = ""` if it takes none. The next call asks again. |
| `MCPdef error: no credentials for upstream '<s>': token endpoint <url>: http: …` | The token endpoint could not be reached, or did not answer within 10 s | Check that MCPdef's host reaches it. An `UnknownIssuer` in the message: its certificate comes from a CA `[gateway.upstream_tls]` does not trust, so add it there. The server's own `[server.tls]` does not apply to it. |
| `MCPdef error: no credentials for upstream '<s>': token endpoint <url>: egress blocked: …` | The egress guard refused the token endpoint: a private address with `[gateway.egress] allow_private = false`, plain HTTP to a public host, or cloud metadata | Give a `token_url` the guard allows, or loosen `[gateway.egress]` if the endpoint is one of yours. |
| `MCPdef error: no credentials for upstream '<s>': token endpoint <url> answered with no token`, or `gave a token whose token_type is not Bearer` | The server answered with no `access_token`, or with a token to use another way (`DPoP`, say) | Configure the client on the server to issue plain bearer tokens. |
| `MCPdef error: no credentials for upstream '<s>': client_secret <where>: …` | The client secret could not be read at a fetch: a variable not set, a file gone, a command that failed | As for `client_key` below. |
| warning: `server '<s>': [server.auth] sends its client secret over plain HTTP to <host>` | Its `token_url` is `http://` to another machine: anyone on the path can read the client secret | Give `token_url` as `https://`. |
| stderr: `mcpdef: upstream '<s>' did not start: <why>; next attempt in <n>s` | An opening failed, at startup or on a restart | Fix what it names (the command, the URL, credentials); MCPdef keeps trying, every 10 s at the slowest. |
| `did not start: … invalid peer certificate: UnknownIssuer` | The upstream's certificate comes from a CA MCPdef does not trust | Give that CA in `ca` (`[server.tls]`, or `[gateway.upstream_tls]` for every upstream). For a self-signed upstream, pin it: `mcpdef tls pin <url>`. |
| `mcpdef_upstream_auth_failures_total` climbs for an upstream that has no `[server.auth]` | It answers `401`: it wants credentials MCPdef is not given. Its `last_error` names the refusal | Set `[server.auth]` with a credential it takes. |
| `credential.last_error` on `/api/v1/servers` names a refusal, though calls to it go through | The upstream refused a token or secret once, and took the one read or fetched again; `last_error` keeps the last failure | Nothing, if `credential.last_ok` is later. If refusals recur, check how the upstream's credentials rotate. |
| `mcpdef_upstream_cert_expiry_seconds` still shows the old certificate after the upstream renewed it | Connections to it were kept alive, or resumed a TLS session begun with the old certificate. They are still vouched for by it, and it is what they show | Nothing is wrong: it moves to the new certificate when a connection makes a full handshake, once the old connections close and the server stops resuming the old session. Restarting MCPdef makes new connections at once. |
| `did not start: … no pin_sha256 matches the server's key, whose pin is "<p>"` | The upstream's key is not one its `pin_sha256` names: it has a new key, or it is not the server that was pinned | Check `mcpdef tls pin <url>`'s fingerprint against the server's own. If the new key is the server's, put its pin in `pin_sha256` (beside the old one while both are in use) and reload. |
| stderr: `mcpdef: config reload refused (<trigger>), invalid-config: <why>; still serving sha256:…` | The config does not parse or validate, or its pin store does not load | Fix what it names (`mcpdef validate --config …` lists every problem), then reload again. The gateway serves the config it had meanwhile. |
| stderr: `mcpdef: config reload refused (<trigger>), invalid-config: strict: <warning>; still serving sha256:…` | The config sets `[gateway] strict = true`, and the gateway would warn about it: a secret written in it, a secret file others can read, `insecure_skip_verify`, credentials in the clear | Fix what the warning names, then reload again. `mcpdef validate --config …` lists every one. |
| stderr: `mcpdef: config reload refused (<trigger>), restart-required: <setting> changed; still serving sha256:…` | The config changes a setting that only a restart applies | Restart to apply the whole config, or undo that setting to reload the rest. |
| stderr: `mcpdef: upstream '<s>': its new settings did not start: <why>; it keeps its old connection; next attempt in <n>s` | A reload changed how `<s>` is reached, and it does not start that way | Fix the settings and reload. `<s>` serves on its old connection meanwhile. |
| stderr: `mcpdef: upstream '<s>': dropping a message that is not JSON-RPC` | A stdio upstream wrote something other than JSON-RPC to stdout (often a log line) | Harmless to other calls; point the server's logging at stderr. A reply lost this way ends in `upstream_timeout_ms`. |
| HTTP `401` + `WWW-Authenticate: Bearer resource_metadata=…` | Auth on and the bearer is missing/invalid (bad signature, wrong `aud`/`iss`, expired, not valid yet, an `exp` or `nbf` that is not a number, unknown `kid`, HMAC/`none` alg) | Fetch the PRM document from the challenge URL, get a token from the advertised AS with `aud` = `[gateway.auth] resource`. An identity provider that writes `exp` or `nbf` as a string must write a number of seconds instead: RFC 7519 requires one. A token refused as expired, or as not valid yet, just after it was issued points at the clocks: `mcpdef doctor` measures how far this machine's is from the identity provider's, of which 60 s are allowed. Set it by NTP. |
| HTTP `403` `origin "…" not allowed` | Browser cross-site `Origin` (DNS-rebinding defense) | Add the origin to `[gateway] allowed_origins` if it is your web app. |
| HTTP `405` on `GET /mcp` | No server→client SSE stream in this phase | Expected; use `POST`. A change to the tools shows on the next `tools/list`. |
| HTTP `413` | Request body > 2 MiB (`MAX_BODY_BYTES`) | JSON-RPC messages are small by design; oversized tool args need a code change. |
| HTTP `503` + `Retry-After: 1`, `gateway overloaded — retry shortly` | `max_inflight` cap reached (deliberate shed, never an unbounded queue) | Retry; raise `max_inflight` or add replicas if sustained. |
| HTTP `404` on `/.well-known/oauth-protected-resource` | `[gateway.auth]` disabled, or its `methods` do not name `bearer` (`methods = ["mtls"]`) | Expected: no token is asked for. |
| Startup: `mcpdef: warning — [gateway.auth] is enabled but applies only to the HTTP listener` | Running stdio with auth configured | Use `--http`; stdio has no per-request identity to authenticate. |
| stderr: `did not start: upstream '<id>' did not finish opening within <n>ms` | Upstream wedged while opening. The gateway starts without it and keeps retrying | Fix the upstream; `upstream_timeout_ms` bounds each opening. |
| Startup fails: `N validation error(s) in mcpdef.toml` | Structural config problem | Run `mcpdef validate` — it lists every error (unknown transport, missing url/command/wasm, dead rate buckets, incomplete auth…). |
| `✗ strict: <warning>`, and startup or `mcpdef validate` fails | `[gateway] strict = true`, or `validate --strict`: what would be a warning is an error | Fix what it names: read the secret from a file, a variable or a command; `chmod 600` the file (or `640`, root owning it); give the CA in place of `insecure_skip_verify`; use `https://`. A config you mean to run with such a finding cannot be strict. |
| Startup fails: `initializing upstream '<s>': <why>` | `[gateway] strict = true`, and `<s>` did not open: a strict gateway starts whole or not at all | Fix what `<why>` names, or leave `strict` off to start without it and have it retried. |
| warning: `server '<s>': url holds a password` (or `a secret, its query parameter …`) | The URL carries a credential, and so does every message that names it: the log, `servers list`, `/api/v1/servers` | Send it with `[server.auth]` (`basic` for a password, `header` or `bearer` for a key), if the upstream takes it so. |
| warning: `server '<s>': command[<n>] holds a secret` | An argument has a known credential's shape. Any user of the machine can read a process's arguments | Give it to the server in `[server.env]`, read from a file, a variable or a command, if the server reads it from its environment. |
| Sandboxed call fails — HTTP `500` `gateway error: …` / CLI error naming e.g. `all fuel consumed` or an epoch deadline | `wasm_fuel` / `wasm_deadline_ms` / `wasm_max_memory_mb` exceeded (a trap) | Raise the specific cap. Note: trap-failed calls are not audited today (denials/timeouts are). |
| Sandboxed component's outbound connect fails (error text depends on the guest) | The destination is not in `wasm_allow_egress` (default deny-all), or is in an always-blocked class | Add the exact `ip:port` to `wasm_allow_egress` (metadata/special-use ranges are rejected even if listed; hostnames not accepted). |
| `client_key $<NAME>: not set in MCPdef's environment` | The key is read from a variable, `{ env = "<NAME>" }`, and MCPdef was started without it | Set it where MCPdef starts: the unit's `Environment=`, the container's `env`. A stdio upstream never sees it. |
| `client_key (exec <program>): exited with status <n>` | The command failed. What it wrote is not shown, since it can hold secrets | Run it by hand, as MCPdef's user, in MCPdef's environment. |
| `client_key (exec <program>): had not ended within 5s, and was stopped` | It waits on something: a passphrase prompt, an interactive sign-in, a slow network. Or it left a process running in the background that holds its output open | Give it credentials that need no one: a service-account token, an age key file. Start a background process with its output sent elsewhere, such as `>/dev/null`. |
| `client_key (exec <program>): could not start: No such file or directory` | The program is not on MCPdef's `PATH` | Give its full path. |
| upstream `<id>` down: `server '<id>': [server.env] <NAME>: <where>: <why>` | A value of its `[server.env]` could not be read when it started: a variable not set, a file gone, a command that failed | As for `client_key` above. MCPdef tries it again with the backoff; a reload that finds the file changed starts it at once. |
| warning: `server '<id>': [server.env] <NAME> is a secret written in the config` | The value is a string in the config, and its name or its shape says it is a secret | Move it out: `{ file = "…" }`, `{ env = "…" }` or `{ exec = […] }`. A value that is no secret but is named like one: rename it if you can. |
| `client_key (literal): a string is the key itself, and this one holds no PEM` | A path was written as a plain string, which is the key itself | Write `client_key = { file = "<path>" }`. |
| warning: `client_key: <path> can be read by its group and every user (mode 644)` | Users other than the key's owner can read it | Give it to MCPdef's user and `chmod 600` it. Or let root own it and MCPdef's group alone read it: `chown root:<group>` and `chmod 640`. For a Kubernetes Secret volume, set `defaultMode: 0400`: the kubelet makes its files root's, readable by the pod's `fsGroup` too, which MCPdef accepts. |
| `mcpdef pin` fails: `` `mcpdef pin` needs a pin store `` | `[gateway] pins` unset | Set `pins = "./mcpdef-pins.toml"`. |
| `mcpdef bundle apply`: `… is not applied: revision <n> is older than revision <m>, which this node applied` | A signed bundle older than the last one this node applied: replayed, or signed at a revision already used. The ledger has a `bundle-older` record | Sign the config again at a revision above `<m>`. To go back to an earlier config, sign that one again at a revision above `<m>`. |
| `mcpdef bundle apply`: `… is not applied: no key it trusts is named <kid>`, or `its signature does not verify` | Signed by a key this node was not given, or changed after it was signed. The ledger has a `bundle-unverified` record | Check that `--trust` holds the signer's public half (`mcpdef bundle jwks --key …`), and carry the bundle in again from where it was signed. |
| `mcpdef up --bundle-trust` (or `filter`): `not running mcpdef.toml: …`, or a reload refused as `bundle-unverified: mcpdef.toml is not the config that mcpdef.toml.bundle, revision <n>, holds`; or a hook held to its bundle refusing every MCP call as `MCPdef denied (bundle-unverified): …` | The config was written without a bundle, by hand or by a tool, or `apply` stopped part way | Put a signed config in place with `mcpdef bundle apply`. A change that has to be made is signed as a new revision where the policy is made. |
| `mcpdef up --bundle-trust` (or `filter`, or `hook`): `there is no mcpdef.toml.bundle` | The config was never applied from a bundle, or applied by a release before the one that keeps the bundle beside it | Apply the last bundle again: it puts `mcpdef.toml.bundle` in place. |
| A hook held to its bundle: `MCPdef denied (config): the bundle floor is not raised to revision <n>: …` | A bundle carried in above the floor, where the hook's user cannot write the `state_dir` that keeps it | Apply the bundle with `mcpdef bundle apply`, run by whoever can write there: it raises the floor. |
| `mcpdef audit verify` fails: `audit ledger … does not exist` | Fresh install — the ledger is written on first governed call | Expected before first run. |
| A client says `unable to verify the first certificate`, `self signed certificate in certificate chain` or `UnknownIssuer` connecting to the gateway | `[gateway.tls] mode = "self-signed"`, and the client does not trust the local CA | Trust it as `mcpdef tls init` prints: `NODE_EXTRA_CA_CERTS` for Claude Code, `CODEX_CA_CERTIFICATE` for Codex, the system store for the rest. `mcpdef tls export-ca` prints the certificate. |
| A client says the certificate is not valid for the name it connected to | It connects by a name the certificate does not carry | Add the name to `hostnames`. If the CA was made without it, `mcpdef tls init --new-ca`, and have every client trust the new CA. |
| `mcpdef: refused the client certificate <addr> presented: invalid peer certificate: UnknownIssuer` | `[gateway.tls.client_auth]` is on, and the client's certificate does not chain to a CA in `ca` | Add the CA that issued it to `ca`, or issue the client one from a CA that is there. `Revoked`: a CRL in `crl` revokes it. `UnknownRevocationStatus`: none of the CRLs is from the CA that issued it, or one above it; give each one's CRL. |
| A client's handshake fails with no line in the log | `mode = "required"`, and the client presented no certificate | Give the client its certificate and key. A client that cannot present one needs `mode = "optional"`, and, with auth on, a token: `methods` has to name `bearer`, with `require = "any"` where it names `mtls` too. |
| `403 the client certificate names no identity MCPdef accepts: …` | The certificate checked out, but has none of the name `identity` reads, or a SPIFFE ID in a trust domain not in `trust_domains` | The message says which. Issue the certificate with that name, add its trust domain, or pick another `identity`. |
| `403 the client certificate is refused: invalid peer certificate: Revoked` on a connection that worked a moment ago | A reload brought in a CRL that revokes its certificate | Issue the client a new certificate. |
| `403 the client certificate the proxy forwarded does not read: x-forwarded-client-cert carries no Cert: …` | The proxy in front forwards the client's names and not its certificate, as Istio's XFCC does by default | Have it forward the certificate: Envoy's `set_current_client_cert_details` with `cert: true`, and `chain: true` for one an intermediate CA issues. |
| `403 the client certificate the proxy forwarded does not read: x-forwarded-client-cert has 2 elements: …` | A proxy appended to the header (`APPEND_FORWARD`), or passed on one its client sent (`FORWARD_ONLY`) | Have the proxy in front of MCPdef set it: `forward_client_cert_details: SANITIZE_SET`. |
| `403 the client certificate is refused: invalid peer certificate: UnknownIssuer`, behind a proxy | The forwarded certificate does not chain to a CA in `ca`, or an intermediate CA issued it and the proxy forwarded no chain | Add its CA to `ca`, or have the proxy forward the chain: `chain: true` in Envoy, `Client-Cert-Chain` in RFC 9440. |
| `403 a client certificate is required` | The request came without a certificate where nothing else will do: `methods = ["mtls"]`; `require = "all"`, though it carried its token; or a reload made `mode = "required"`, and its connection was opened without one. Behind a proxy: it forwarded none, or the request came from an address not in `[gateway.trusted_proxy] cidrs`, whose header is not read | Give the client its certificate and key; after such a reload, it presents them on a new connection. A token stands in for a certificate only with `methods = ["bearer", "mtls"]`, `require = "any"` and `mode = "optional"`: then a request with neither gets the `401` challenge, not this. Behind a proxy, give in `cidrs` the address the listener sees it connect from, and have it ask its clients for a certificate. |
| `the local CA vouches only for the names it was made with, and not for <name>` | A `hostnames` entry, or a listen address, the local CA was not made for: startup fails, or a reload is refused | `mcpdef tls init --new-ca`, and have every client trust the new CA. Or take the name out. |
| `there is no local CA in <dir>` | `[gateway] state_dir`'s `tls/` lost its CA while the gateway ran | `mcpdef tls init` makes one; clients have to trust it. Restore `ca.crt` and `ca.key` from a backup to keep the old one. |
| `[gateway.tls] key <path>: does not match the certificate first in cert <path>` | The files are from two different pairs, or were read halfway through a renewal | Give it the pair; a `SIGHUP` once both are written serves them. |
| warning: `[gateway] listen = "0.0.0.0:7878" takes connections from other machines, and neither TLS nor auth is on` | A listener other machines reach, with no TLS and no `[gateway.auth]`. Behind `[gateway.trusted_proxy]`, with client certificates `optional`: a client can connect to the listener directly, and is served as no one | Set `[gateway.tls]` and `[gateway.auth]`, or listen on `127.0.0.1` behind a proxy that does both. Behind a trusted proxy, set `[gateway.tls.client_auth] mode = "required"`. |
| warning: `[gateway.trusted_proxy] cidrs entry "0.0.0.0/0" trusts every address: …` | A range that holds every address: anyone who reaches the listener can forward a client's certificate, which is no secret, and be taken for that client | Give the proxy's own addresses alone. |

## Security posture

- **What listens where.** Nothing, by default: `mcpdef run` is stdio-only. With
  `--http`/`up`, exactly one TCP socket — `[gateway] listen`, default
  **loopback** `127.0.0.1:7878`. For a non-loopback bind, turn on
  `[gateway.tls]` (see [Serving HTTPS](#serving-https)) or put a
  TLS-terminating proxy in front, and turn on `[gateway.auth]`: with neither
  TLS nor auth, such a bind is warned about, and refused under `strict`.
- **TLS on the listeners.** TLS 1.2 and 1.3 on ring, HTTP/1.1, a 10 s
  handshake timeout, and a client certificate asked for only with
  `[gateway.tls.client_auth]`: checked by rustls against `ca` and `crl` at the
  handshake, and again at a connection's first request after each reload, and
  read as the caller's identity by MCPdef's own code. The local CA of
  `mode = "self-signed"` is name-constrained to `localhost`, the loopback
  addresses, the listen addresses and `hostnames`, so clients refuse a
  certificate its key, were it stolen, signs for any other name; its keys are
  `0600` in a `0700` directory. Certificates are swapped whole on reload.
- **Authn/z.** OAuth 2.1 Resource Server per request (JWKS-validated bearer
  JWT, asymmetric-only — algorithm-confusion-safe, `aud`/`iss`/`exp`/`nbf`
  checked, and a token whose `exp` or `nbf` is not a number refused), RFC 9728
  discovery on 401, and client certificates as a second method, or the only
  one (`[gateway.auth] methods`). RBAC roles layer over the deny-by-default
  allowlist: a token's, or a certificate's from `[[identity.cert_map]]`, which
  gives an unmapped one none. The stdio path and `mcpdef call` are
  trusted-operator paths with no bearer.
- **Token handling.** The client's bearer is validated and dropped — it is
  **never forwarded** to upstreams. Upstream credentials are brokered from
  config: into stdio children via `[server.env]`, and onto each request to an
  HTTP upstream via `[server.auth]`, marked sensitive: a secret the config
  names, or a token MCPdef fetches for itself by the OAuth client credentials
  grant, kept until 30 s before it expires. Tokens are not written to the
  audit ledger (only the token's `sub` is, as the audit identity), and nor is
  a token MCPdef fetches, or a token endpoint's error description.
- **Secrets in URLs.** A URL can hold a secret of its own: a password, a key
  in its query. Wherever MCPdef shows a URL (its log, a call's error, the
  error a command exits with, `/api/v1/servers`, `servers list`,
  `egress show`, `validate`) its user name and password, a path segment
  with a known credential's shape, and a query or fragment parameter that
  is a secret by its name or its shape are shown as `***`. Still, the
  config holds the secret, and `validate` warns about it: send it with
  `[server.auth]` if the upstream takes it in a header.
- **Strict mode.** `[gateway] strict = true` makes every warning an error:
  the gateway does not start, or reload, with a secret written in its config,
  a secret file others can read, a certificate not checked, or credentials in
  the clear, and an upstream that does not open fails its start. `mcpdef
  validate --strict` is the same check for CI. See
  [CONFIG.md § Strict mode](./CONFIG.md#strict-mode).
- **Secrets.** A secret the config names (`client_key`, each `[server.env]`
  value, and each `[server.auth]` secret, an `oauth2` client secret among
  them) is read from a file, a variable of
  MCPdef's own, a command's output, or the config itself, when it is needed:
  see [CONFIG.md § Secrets](./CONFIG.md#secrets). A command runs as MCPdef's
  user with no shell, for at most 5 s and 64 KiB of output, and its error
  output is thrown away. Its value is never printed: errors, warnings,
  `servers list` and `/api/v1/servers` name where it comes from. The memory
  MCPdef reads it into is wiped when done with, though the TLS library keeps
  its own copy of a client key, the HTTP library holds a `[server.auth]`
  header for as long as the upstream is open, and a token request's body or
  header until it is sent, and a stdio server holds its environment. A variable a secret is read from is withheld from stdio
  upstreams, and a secret file others can read, or a secret written in the
  config, is warned about.
- **Egress.** HTTP upstream, `jwks_uri` and OAuth token endpoint fetches pass
  the SSRF guard: cloud-metadata/link-local always blocked, DNS-pinned, HTTPS
  required for public hosts (`[gateway.egress]`). Verify with `mcpdef egress
  show`. A `connect_to` address passes the same guard.
- **TLS towards upstreams.** An HTTPS upstream, a `jwks_uri` and an OAuth
  token endpoint are verified against Mozilla's roots bundled into the binary,
  or against a TLS profile's (`[gateway.upstream_tls]`, `[server.tls]` for an
  upstream alone): a private CA, the host's store, CRLs, TLS 1.3 only, and a
  client certificate for mTLS. A self-signed upstream is pinned by its key
  (`pin_sha256`, which `mcpdef tls pin` prints), not trusted by turning
  verification off. Redirects are never followed. `insecure_skip_verify` is
  warned about at startup and audited on every connection. `mcpdef egress
  show` prints the profile each HTTPS upstream is verified with, and
  `/api/v1/servers` how each one's certificate was checked (`verify`) and the
  certificate it presented.
- **Sandbox boundaries.** `transport = "wasm"` runs against an empty linker —
  no filesystem, network, or clock (a module importing WASI fails to load).
  `transport = "wasm-component"` gets capability-scoped WASI whose only grant
  is outbound TCP to the explicit `wasm_allow_egress` list (default deny-all).
  Both are fuel-, memory-, and optionally wall-clock-bounded per call.
- **Listener hardening.** Origin validation (DNS-rebinding), 2 MiB body cap
  before auth/parse, optional in-flight cap with explicit `503` shed, no
  sessions (stateless per the 2026-07-28 direction).
- **Deliberately out of scope:** ACME inside MCPdef (cert-manager or certbot
  writes the files `mode = "files"` serves), HTTP-to-HTTPS redirects and
  HSTS (an edge's job),
  and multi-replica coordination (each replica has its own ledger/pin store/metrics registry — see
  [Monitoring](#monitoring) for the `[gateway.admin]` `/metrics` endpoint this no
  longer excludes). Disclosure policy: [SECURITY.md](../SECURITY.md).
