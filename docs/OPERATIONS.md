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
  `mcpdef 0.1.0 ready · 1 upstream(s) · audit ./mcpdef-audit/audit.log · listening streamable-http 127.0.0.1:7878`
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
  re-read. There is no on-disk migration in 0.1.x.

## State: what to back up

| File | Config key | Format | Loss impact |
|---|---|---|---|
| Audit ledger | `[gateway] audit` (default `./mcpdef-audit/audit.log`) | JSONL hash chain (append-only) | Your tamper-evident record of every governed call. Back up continuously (it is the compliance artifact). Snapshot-friendly: append-only, safe to copy live. |
| Pin store | `[gateway] pins` (optional) | TOML, `server → tool → sha256` | Your approved tool-definition baseline. Losing it means every tool re-pins on next start (trust-on-first-use) — a rug-pull window. Keep it in version control; it is deterministic and diff-clean by design. |
| Config + JWKS | `mcpdef.toml`, `[gateway.auth] jwks` file | TOML / JSON | The policy itself. Version-control both. |
| Local CA | `[gateway] state_dir` (default `./mcpdef-state`), `tls/` | PEM: `ca.crt`, `ca.key`, `tls.crt`, `tls.key` | With `[gateway.tls] mode = "self-signed"`: the CA every client was told to trust. Lost, the gateway makes a new one at its next start, and every client has to trust that instead. Back up `ca.crt` and `ca.key` as you would any key: `ca.key` can issue certificates for the listener's names. `tls.crt` and `tls.key` are issued again at will. |
| Session key | `[gateway] state_dir`, `session.key`, unless `[gateway.admin.session] key` is set | 32 bytes, `0600` | Seals the console's sessions. Lost, the gateway makes a new one, and everyone signed in signs in again; nothing else is lost. Replicas behind one `public_url` need the same key: set `[gateway.admin.session] key` for them, rather than each making its own. |

`[server.env]` values (brokered upstream credentials) are best read from a
file, a variable of MCPdef's own or a command, so that the config holds none:
see [CONFIG.md § Secrets](./CONFIG.md#secrets). One written in the config as a
string, and found to be a secret, is warned about at startup. A config that
still holds one: protect it like a secret store (file permissions, encrypted at
rest, no world reads).

Durability note (honest guarantee): the ledger append is `write` + userspace
`flush`, **not** `fsync` — a host crash can lose the last unsynced record(s).
The hash chain proves *integrity*, not *durability*.

## Audit-ledger verification

Routine (proves internal consistency — any edit/delete of an interior record):

```sh
$ mcpdef audit verify --config mcpdef.toml
chain OK · 2 record(s) · head=f4bb388a0ba59cef9af31b5732c5f03c4dfb27d24e68fc078abafbe1a40fa17a
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
  definition is denied as a `rug-pull`, a new tool is pinned on first use) and
  routes calls to them.
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
    longer matches its pin is hidden and refused as a `rug-pull` until
    `mcpdef pin` approves it and a reload reads the pins;
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
  the `[gateway]` keys `listen`, `allowed_origins`, `max_inflight`, `wire` and
  `audit`, `[gateway.admin]`'s `enabled` and `listen`, the `[gateway.auth]`
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
  `invalid-config` or `restart-required`. A digest is `sha256:<hex>` over the
  config's bytes and the content of each file it names, so it changes when a
  wasm module does.
- **The log** says what changed, or why nothing did:
  `mcpdef: config reloaded (sighup): added b; removed a; now sha256:9c1e0b7d4f2a`,
  `mcpdef: config reloaded (admin API, local): …`
  or
  `mcpdef: config reload refused (watch), restart-required: [gateway] listen (127.0.0.1:7878 → 0.0.0.0:7878) changed; still serving sha256:41d0c3a9b8e7`.
  A digest in the log is cut to its first 12 hex digits. After a reload it
  applies, the gateway prints the new config's warnings, as a start does.
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
  agent probing beyond its grants.
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
  `mcpdef diff-tools` in cron/CI (exits non-zero on drift).
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
| A tool vanished from `tools/list` while its server stayed up, and a call to it is `MCPdef denied: … changed since it was pinned (possible rug-pull)` | The server changed the tool's definition and said so. The re-list found it no longer matches its pin. The ledger has a `tools-changed` record with `rule = "rug-pull"` | Review with `mcpdef diff-tools`; if legitimate, re-approve with `mcpdef pin`, then reload (`kill -HUP`), or approve it from the admin API (`POST /api/v1/servers/<id>/pins`), which saves the pin and serves the tool at once. |
| warning: `tool '<t>' is offered by '<a>' and '<b>': it is listed once, from '<a>', and a call to it goes there` (`strict: …`, and no start, under strict mode) | Two servers' allowlists both take a tool of that name. A client sees one tool, and every call to it goes to `<a>` | Take the name off one server's allowlist (`deny`), or set `[gateway] tool_namespace = "prefix"` to list each as `<prefix>__<t>`. The admin servers view lists it under `tool_collisions`. |
| `MCPdef denied: no governed server exposes tool '<t>'`, with `tool_namespace = "prefix"` | Each tool is called by its listed name, `<prefix>__<name>`: a name without a prefix, or with one no server has, is no tool's | Call the name `tools/list` gives. A server's prefix is its `prefix`, or else its `id`. |
| `MCPdef denied: server '<s>' is not governed by MCPdef` | Tool routed to a server with no policy entry (fail-closed) | Add a `[[server]]` entry for it. |
| `MCPdef denied: no role grants '<t>' on '<s>'` | RBAC: the caller's roles hold no matching `[[role]]` grant: a token's scopes/roles, or, for a client certificate without a token, the roles `[[identity.cert_map]]` gives its identity | Grant `"<server-glob>:<tool-glob>"` to a role the caller holds, or fix the IdP scopes. For a certificate, map its identity to a role in `[[identity.cert_map]]`: one no entry matches holds none. |
| `MCPdef denied: tool '<t>' on '<s>' changed since it was pinned (possible rug-pull)` | Pinned definition drifted (description/schema/annotations changed) | Review with `mcpdef diff-tools`; if legitimate, re-approve with `mcpdef pin`, then reload (`kill -HUP`), or from the admin API (`POST /api/v1/servers/<id>/pins`). The tool is also hidden from `tools/list` until re-pinned. |
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
