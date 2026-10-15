# MCPdef configuration reference

Every knob MCPdef reads, in one place. MCPdef is configured by **one TOML file**
(default `mcpdef.toml`, overridable per command with `--config`) plus a handful of
CLI flags. **MCPdef reads no environment variables of its own** — the variables
it deals in are the ones *it injects* into stdio upstreams via `[server.env]`
(the token broker), the ones a config names a [secret](#secrets) by, and
`SSL_CERT_FILE`/`SSL_CERT_DIR`, which locate the host's CA store for a TLS
profile with `roots = "system"` or `"both"`, as they do for OpenSSL. Source of truth: the serde structs in
[`crates/mcpdef/src/config.rs`](../crates/mcpdef/src/config.rs) and the clap derive
in [`crates/mcpdef/src/main.rs`](../crates/mcpdef/src/main.rs); regenerate this file
when they change. A commented, runnable example is
[`mcpdef.example.toml`](../mcpdef.example.toml).

`mcpdef validate --config <file>` checks everything below structurally (unknown
transport, missing `command`/`url`/`wasm`, dead rate-limit buckets, incomplete
`[gateway.auth]`, unknown profile references, malformed egress entries) without
starting the gateway. It also reads the certificates, keys and CRLs the TLS
tables name, and warns about what it lets through but should not have to
(`insecure_skip_verify`).

## Glob patterns

Several settings take glob patterns:
- `tools` and `deny`, in a `[[server]]` or a `[profile.<name>]`;
- a `[[server]]`'s `prompts` and `resource_templates`;
- a `[[role]]`'s `grants` and `prompt_grants`;
- a `[[policy]]` rule's `servers`, `tools`, `prompts`, `agents` and its `args`
  `glob`.

A `[[server]]`'s `resources` takes URI patterns instead, whose `*` stops at a
`/`: see [Resource URI patterns](#resource-uri-patterns).

They all follow the same rules:
- `*` matches any run of characters, including none. It can appear anywhere in a
  pattern, any number of times.
- `*` is the only wildcard. Every other character matches only itself, `?` and
  `[` included.
- Matching is case-sensitive, and a pattern must match the whole name:
  `delete_*` does not match `undelete_file`. To match a name that *contains*
  something, put a `*` on both sides.
- A pattern without `*` is an exact match. A lone `*` matches everything.

| Pattern | Matches | Does not match |
|---|---|---|
| `delete_*` | `delete_file`, `delete_` | `undelete_file` |
| `*_secret` | `db_secret` | `db_secret_ro` |
| `*delete*` | `delete`, `delete_file`, `rm_delete_all` | `Delete_file`, `remove_file` |
| `get_*_info` | `get_user_info`, `get__info` | `get_info` |

Releases up to 0.2.1 honoured `*` only as a pattern's first or last character.
A pattern with a `*` inside it or at both ends matched nothing there, so a deny
written that way denied nothing and an allow allowed nothing. Both now match as
written.

## Resource URI patterns

A `[[server]]`'s `resources` lists the resources it may expose, as URI patterns.
A `resources/read` is served only for a URI one of them matches, and
`resources/list` shows only such resources. With no `resources`, a server
exposes none of its resources. That is unlike `tools`, where no allowlist
exposes every tool: a resource is data, such as a file or a row, so none is
exposed until one is named.

A pattern is written as a URI:
- In the path, `*` matches within one segment, and never matches an empty one.
  A segment that is `**` alone matches any number of segments, none included.
- Before the path, `*` matches any run of characters, as in a name pattern:
  `https://*.example.com/**` takes any subdomain. It never reaches into the
  path.
- A URI with a query or a fragment matches only a pattern that has one.
- `*` or `**` alone matches every URI.

| Pattern | Matches | Does not match |
|---|---|---|
| `file:///srv/docs/*` | `file:///srv/docs/a.md` | `file:///srv/docs/sub/a.md`, `file:///srv/docs/`, `file:///srv/docs/a.md?x=1` |
| `file:///srv/docs/**` | `file:///srv/docs`, `file:///srv/docs/sub/a.md` | `file:///srv/docsx/a.md` |
| `file:///srv/*/readme.md` | `file:///srv/team/readme.md` | `file:///srv/a/b/readme.md` |
| `https://*.example.com/v1/**` | `https://api.example.com/v1/users` | `https://example.com.evil.net/v1/x` |
| `db://orders/rows?id=*` | `db://orders/rows?id=7` | `db://orders/rows` |

**Normal form.** Every URI a client names, and every pattern, is judged in
normal form (RFC 3986), and the upstream is sent the URI in that form, never as
the client wrote it:
- the scheme is lowercased;
- an escape of a letter, a digit, `-`, `.`, `_` or `~` is decoded, and the hex
  of every other escape is uppercased;
- `.` and `..` segments are removed, so `file:///srv/docs/../secret` is
  `file:///srv/secret`, and `%2e%2e` counts as `..`;
- for `http`, `https`, `ws`, `wss`, `ftp` and `file` only, the host is
  lowercased, a default port is dropped and an empty path is `/`;
  `file:/p` and `file://localhost/p` are `file:///p`. Any other scheme's
  authority is compared as written.

**Refused.** A URI that two readers could take two ways is refused. A read of
it is denied and audited under `uri-refused`, and a pattern like it fails
`mcpdef validate`. That is a URI with:
- an encoded `/` or `\` (`%2F`, `%5C`) in its path;
- a backslash, a NUL (raw or `%00`), or a control character;
- an empty segment inside its path (`a//b`);
- `%25` before an escaped dot, separator, NUL or `%`, as in `%252e`, however
  the second escape's digits are written: `%25%32%65` is `%252e` too;
- no scheme.

**Overlaps.** Two servers whose patterns overlap, so that one URI could be read
from either, are warned about, and refused under [strict mode](#strict-mode). A
read of such a URI goes to the server that listed it or linked it in a tool
result, and otherwise to the first in config order.

## Tool names

`tools/list` gives each tool name once. A name more than one server offers (its
server lists it, and its allowlist takes it) is listed once, from the first of
them in config order, and a call to it goes there. The other servers' copies
are not listed.

A collision is reported, naming every server that offers the name:
- by `mcpdef validate`, for a name two allowlists give outright (a pattern
  names no one tool);
- at startup, for what the servers turn out to offer: printed as a warning,
  and failing the start under [strict mode](#strict-mode);
- on the admin servers view, as each server's `tool_collisions`
  ([API.md](./API.md#admin-listener-gatewayadmin)).

A tool that drifts from its pin, or whose description trips the scanner, keeps
its name. It is hidden, and a call to it is refused; it is not handed to the
next server that offers the name.

**Prefixes.** With `[gateway] tool_namespace = "prefix"`, every tool is listed
as `<prefix>__<name>`, such as `gh__create_issue`, and called by that name.
MCPdef takes the prefix off and sends the upstream the name it knows. A
server's prefix is its `prefix`, or else its `id`. Only the listed name
changes. `tools`, `deny`, a profile, a `[[role]]` grant, a `[[policy]]` rule's
`tools`, the per-tool rate limit, the pin store and the audit ledger all name
the tool as its server does (`github`, `create_issue`), so switching prefixes
on moves no pin. On the 2026-07-28 wire a client's `Mcp-Name` mirrors the name
it calls, which is the prefixed one.

`validate` refuses a prefix a tool name may not start with: an empty one, or
one with a character other than letters, digits, `_`, `-` and `.`. It warns
about:
- a listed name longer than 50 characters: some clients cut or refuse a long
  tool name once they add a prefix of their own;
- two servers that share a prefix;
- a `prefix` set while `tool_namespace` is off, where nothing uses it.

Two prefixed names can still meet: `gh` with `x__y` and `gh__x` with `y` both
give `gh__x__y`. That is a collision like any other.

## Secrets

A setting that takes a secret takes it in one of four forms: `client_key`,
each value of a stdio server's [`[server.env]`](#server--the-governed-upstreams),
an HTTP server's [`[server.auth]`](#serverauth--credentials-towards-an-http-upstream)
token, value, password or client secret, and the console's
[`client_secret`](#gatewayadminoidc--signing-people-in-to-the-console) and
[session keys](#gatewayadminsession--the-consoles-sessions).

| Form | Example | The value |
|---|---|---|
| `{ file = "path" }` | `client_key = { file = "/run/secrets/client.key" }` | The file's content: a Kubernetes or Compose secret mount, say, or a file a secret manager's agent writes. |
| `{ env = "NAME" }` | `client_key = { env = "MCPDEF_CLIENT_KEY" }` | A variable of MCPdef's own environment. |
| `{ exec = ["command", "argument", …] }` | `client_key = { exec = ["op", "read", "op://Infra/mcpdef/key"] }` | What the command writes: a secret manager's CLI, say. |
| a string | `client_key = """…"""` | The string itself, written in the config. Anything that copies the config copies it too, so prefer another form. |

- **A secret is read when it is needed**, not when the config is loaded: a
  client key at each connection, a `[server.env]` value each time its server
  starts, a restart included, a `[server.auth]` token, value or password each
  time its upstream is opened and again when the upstream answers `401`, an
  `oauth2` client secret at each fetch of a token, and the console's client
  secret at each sign-in. So a file rotated in place is read afresh at the
  next. The console's session keys are read once, when the gateway starts. `mcpdef validate` and startup
  read each client key once, to check it; a `[server.env]` or `[server.auth]`
  secret is read only when its server starts, and one that cannot be read
  leaves that server down, with an error that names it.
- **A file** has to be a regular file of UTF-8 text, of at most 64 KiB. One
  line ending at its end, `\n` or `\r\n`, is not part of the value: `echo`
  and most editors add one. A secret file that users other than its owner can
  read is warned about at startup and by `mcpdef validate`. Give it to
  MCPdef's user and `chmod 600` it. Or let root own it and MCPdef's group
  alone read it, `chmod 640`: a file root owns may be readable by its group
  when, on Linux, MCPdef does not run as root, since that group is then how
  MCPdef reads it. A Kubernetes Secret volume with `defaultMode: 0400` is
  such a file: the kubelet gives its files to root, and lets the pod's
  `fsGroup` read them too. Its default mode, `0644`, lets every user read
  them.
- **A command** runs with no shell. Each array element is one argument, as
  written, so `$VAR`, `*`, quotes and `;` mean nothing to it. It runs as
  MCPdef's user, in MCPdef's environment and working directory, with nothing on
  its standard input, and its error output is thrown away.
  - It has 5 s to write at most 64 KiB of UTF-8 text and exit with status 0. A
    command that runs over either limit is killed. Its output is read as a
    file's is, so one line ending at its end is dropped.
  - Its output ends when every process that holds it has closed it. So a
    process it leaves running in the background must not keep it open, or the
    command runs over.
  - It runs each time the secret is needed. For a client key, that is once when
    the config is checked, and again at each connection. For a `[server.env]`
    value, it is each time its server starts; for a `[server.auth]` token,
    value or password, each time its upstream is opened and once more after a
    `401`; and for an `oauth2` client secret, at each fetch of a token.
  - An error names the command's program alone, as in `(exec sops)`, never its
    arguments or what it wrote. To see why a command fails, run it by hand, as
    MCPdef's user.

  For example:

  ```toml
  # SOPS: one value from an encrypted YAML file. SOPS finds its own key (an age
  # key file, a KMS key) in MCPdef's environment.
  client_key = { exec = ["sops", "--decrypt", "--extract", "[\"mcpdef\"][\"client_key\"]", "/etc/mcpdef/secrets.enc.yaml"] }

  # 1Password: a field of an item, read with a service account's token,
  # OP_SERVICE_ACCOUNT_TOKEN, from MCPdef's environment.
  client_key = { exec = ["op", "read", "op://Infra/mcpdef-mtls/private key"] }

  # Vault: one field of a KV secret, with VAULT_ADDR and a token in MCPdef's
  # environment.
  client_key = { exec = ["vault", "kv", "get", "-field=key", "secret/mcpdef/mtls"] }
  ```
- **A variable** a secret is read from is withheld from the stdio upstreams
  MCPdef starts, which otherwise inherit its environment. A server whose
  `[server.env]` sets that name gets what `[server.env]` says. So
  `GITHUB_TOKEN = { env = "GITHUB_TOKEN" }` hands MCPdef's `GITHUB_TOKEN` to
  that server alone.
- **A secret written in the config** is warned about at startup, at a reload,
  and by `mcpdef validate`, and [strict mode](#strict-mode) refuses it:
  - a client key, a `[server.auth]` secret, the console's client secret or a
    session key written as a string;
  - a `[server.env]` string that is a secret by its name or by its shape;
  - a server's `url` that holds a password, a query parameter that is a secret
    by its name or its shape, or a credential's shape anywhere. The config
    holds it, and so does any copy of it, though wherever MCPdef shows the URL
    the secret is masked (see below);
  - a `command` argument with a credential's shape. Any user of the machine
    can read a process's arguments: give the secret to the server in
    `[server.env]` instead.

  By its name: its last word is `KEY`, `PASS` or `PAT`, or ends in `TOKEN`,
  `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE` or `APIKEY`, as in
  `GITHUB_TOKEN`, `PGPASSWORD`, `OPENAI_API_KEY` and `?api_key=`.
  `SSH_KEY_PATH` is not one. By its shape: a GitHub, Slack, AWS or Stripe key,
  or a private key, as the
  [inspector](#gatewayinspect--injection--secret-exfil-scanning) finds them in
  tool results. An empty string is no secret, and nor is `LOG_LEVEL = "debug"`.
- **A value is never printed.** An error, a warning or a config's debug output
  says where a secret comes from (`$NAME`, the file's path, `(exec PROGRAM)` or
  `(literal)`), never what it holds. So do `mcpdef servers list` and the admin
  API's `/api/v1/servers`, for each variable a `[server.env]` sets and each
  `[server.auth]` secret. A URL is shown with each secret it holds masked
  as `***`: its user name and password, a path segment with a credential's
  shape, and a query or fragment parameter that is a secret by its name or
  its shape, by the rule above. So `https://mcpdef:hunter2@api.internal/mcp?api_key=k1&v=2`
  shows as `https://***:***@api.internal/mcp?api_key=***&v=2` in the log, in
  errors, in `servers list`, `egress show` and `/api/v1/servers`. The memory
  MCPdef reads a value into is wiped when it is done with it. The TLS library
  keeps its own copy of a client key, for as long as a client built with it
  lasts, and a server's process holds its environment for as long as it runs.

## Strict mode

`[gateway] strict = true` makes every warning an error, and so does
`mcpdef validate --strict` for one check. Each is then reported as
`strict: <the warning>`:

- **a secret written in the config**, as [Secrets](#secrets) lists them;
- **a secret file others can read**: one every user can read, or its group,
  unless root owns it and MCPdef reads it through that group, as
  [Secrets](#secrets) says;
- **a certificate not checked**: `insecure_skip_verify = true`;
- **credentials sent in the clear**: `[server.auth]` credentials, or an
  `oauth2` client secret, over plain `http://` to a host other than this
  machine;
- **a listener other machines can reach, with neither TLS nor auth**:
  `[gateway] listen` on an address other than a loopback one or `localhost`,
  with [`[gateway.tls]`](#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners)
  and `[gateway.auth]` both off;
- **two servers that could serve one resource or show one prompt**: their
  `resources`, or their `prompts`, patterns overlap;
- **a resource grant to no server**: a `resource_grants` entry whose server
  part matches no `[[server]]`, as a URI written alone would;
- **a tool name more than one server offers**: named outright by two
  allowlists, or found at startup among what the servers offer, as
  [Tool names](#tool-names) says;
- **with prefixes, a listed name longer than 50 characters, or a prefix two
  servers share**, and **a `prefix` set while `tool_namespace` is off**.

Where it applies:

- **`mcpdef validate`** fails on such a config, listing each finding.
  `--strict` checks a config strictly whatever its `strict` says, which is what
  a CI gate wants.
- **The gateway does not start with it**: `mcpdef run`, `up` and `call` list
  each finding and exit. Nor does it start once its upstreams open if they
  offer a tool name more than one of them does, or, with prefixes, a name too
  long: what a server offers is known only then.
- **A reload to it is refused**, as `invalid-config`, and the gateway keeps
  serving the config it had. A reload that turns `strict` on or off applies
  like any other, and the new config is checked as it says. What the servers
  offer after a reload is printed as a warning, and shown on the admin
  servers view, but refuses nothing: the reload has applied by then.
- **An upstream that does not open at startup fails the start**:
  `initializing upstream '<id>': …`. Without `strict`, the gateway starts
  without it and keeps trying it. Once it runs, an upstream that goes down is
  restarted, strict or not, and a reload that adds one that does not open
  applies as it would otherwise.

`validate --strict` reads what `validate` reads, and no more: the files a TLS
table names, and each client key, from wherever it comes, to check them. It
reads no `[server.env]` or `[server.auth]` secret, and runs none of their
commands: one that cannot be read is found when its server starts, which a
strict start then fails. So a CI job can check a config without the secrets its
servers are given, though it needs the TLS files and client keys. The gateway's
ready line says `· strict`.

## `[gateway]`

Struct: `GatewayConfig` (`config.rs`).

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen` | string `host:port` | `"127.0.0.1:7878"` | Bind address for the downstream Streamable HTTP listener (`mcpdef run --http` / `mcpdef up`). Loopback by default — binding wider is a deliberate act. It is bound before the upstreams start, and the ready line names the address taken: port `0` takes one the system gives. One that cannot be bound stops the start. |
| `audit` | path | `"./mcpdef-audit/audit.log"` | The append-only, hash-linked audit ledger (JSONL, one record per governed call). Parent dirs are created on first run. |
| `policy` | path | unset | **Reserved** for a policy directory. Parsed but unused today — declare rules inline with [`[[policy]]`](#policy--policy-as-code-rules). |
| `pins` | path | unset (pinning off) | Tool-def pin store (TOML). When set, MCPdef pins each upstream tool's definition (trust-on-first-use) and denies + audits a `rug-pull` if a definition later drifts. Managed with `mcpdef pin` / `mcpdef diff-tools`. |
| `profile` | string | unset | The active gateway profile — a `[profile.<name>]` layered over **every** server, scoping the whole tool surface an agent sees. Overridable at launch with `--profile`. |
| `upstream_timeout_ms` | int (ms) | unset / `0` = no timeout | Per-call upstream bound, covering the whole call: waiting for a slot under the server's `max_inflight`, sending the request (a Streamable-HTTP POST, a wasm module's run) and waiting for the reply. A wedged upstream is failed as an audited `upstream-timeout` instead of hanging the gateway; a reply that arrives later is dropped. Also bounds each upstream's opening, at startup and on every restart: one that does not open in time starts down and is retried. Unset, an opening waits as long as it takes. And it bounds the `tools/list` MCPdef sends when an upstream says its tools changed; unset, that waits 30 s at most. A `spec = "auto"` upstream gets the era probe's 5s **on top of** this for its opening, since the probe measures something else — see [WIRE.md](./WIRE.md). |
| `allowed_origins` | array of strings | `[]` | Extra `Origin` values accepted on the HTTP listener beyond loopback (`localhost`/`127.0.0.1`/`::1`, any port, always allowed; requests with no Origin always pass). Anything else → `403` (DNS-rebinding defense). |
| `max_inflight` | int | unset = unlimited | Max concurrent in-flight HTTP requests; excess is shed with `503` + `Retry-After: 1` (fail-fast load-shedding). A request keeps its slot until its call ends, even if its client disconnects first. Over stdio, at most 64 requests run at once, and reading pauses beyond that instead of shedding. |
| `wire` | `legacy` \| `dual` \| `modern` | `legacy` | Which MCP revisions the HTTP listener serves. `legacy` = 2025-11-25 only (an `initialize` handshake); `modern` = the stateless 2026-07-28 only; `dual` = both on the one endpoint, chosen per request. Defaults to `legacy` so an upgrade never changes what a deployment accepts. See [WIRE.md](./WIRE.md). |
| `watch_config` | bool | `false` | Every 30 s, check whether the config, or a file it names (a `[gateway.auth] jwks` file, a wasm module, a file a TLS table names), changed, and reload if so. The check compares content, so it also sees a Kubernetes ConfigMap update, which swaps a symlink instead of writing the file. `SIGHUP` reloads with or without it. See [OPERATIONS.md § Reloading the config](./OPERATIONS.md#reloading-the-config). |
| `strict` | bool | `false` | Make every warning an error: a secret written in the config, a secret file others can read, a certificate not checked, credentials sent in the clear, a listener open to other machines with neither TLS nor auth. `mcpdef validate` fails on such a config, the gateway does not start with it, and a reload to it is refused. And an upstream that does not open at startup fails the start, instead of starting down and being retried. See [Strict mode](#strict-mode). |
| `tool_namespace` | `off` \| `prefix` | `off` | How `tools/list` names each tool. `off`: as its server names it, with a name more than one server offers listed once, from the first. `prefix`: as `<prefix>__<name>`, each server's `prefix` or else its `id` before the `__`. See [Tool names](#tool-names). |
| `state_dir` | path | `"./mcpdef-state"` | Where MCPdef keeps what it makes for itself: under `tls/`, the local CA and the certificate it issues the listeners with `[gateway.tls] mode = "self-signed"`. The directory is made `0700` and the keys in it `0600`. Keep it across restarts and upgrades: a new CA is one every client has to trust anew. |

A reload (`SIGHUP`, or `watch_config`) applies every setting except these:
the `[gateway]` keys `listen`, `allowed_origins`, `max_inflight`, `wire` and
`audit`; `[gateway.admin]`'s `enabled` and `listen`; the `[gateway.auth]`
table, a `jwks` file's content included; and TLS turned on or off on either
listener. A config that changes one of them is refused whole, and applies at
the next restart. TLS profiles apply on a reload, a certificate renewed in
place included, and so does each listener's certificate, and what it asks of a
client's: see
[TLS on MCPdef's own listeners](#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners).

## `[gateway.rate_limit]`

Struct: `RateLimitConfig`. Token buckets on the `tools/call` hot path (checked
**after** the authorization gates, so a flood of denied calls cannot drain the
buckets). Over-limit calls get a tool-error result + a `rate-limited` audit
record — the stdio analog of a 429.

A `resources/read` spends a token from the global bucket too, and one from its
server's own reads bucket, which refills at the per-tool rate. A server's reads
share that one bucket, apart from any tool's, and an over-limit read gets
`-32002` and a `rate-limited` record. A `prompts/get` does the same with its
server's prompts bucket, a third apart from both, and an over-limit get gets
`-32602`. A `completion/complete` spends its server's completions bucket, a
fourth, so a client completing as a user types starves no get or read; an
over-limit completion gets `-32602` too.

| Key | Type | Default | What it does |
|---|---|---|---|
| `per_tool_per_sec` | float > 0 | unset = per-tool scope off | Refill rate (tokens/sec) for each tool's own bucket: one per server and tool, so two servers' tools of one name spend apart. |
| `per_tool_burst` | float ≥ 1 | = `per_tool_per_sec` | Per-tool bucket capacity (max burst). |
| `global_per_sec` | float > 0 | unset = global scope off | Refill rate for the gateway-wide bucket (checked before the per-tool one). |
| `global_burst` | float ≥ 1 | = `global_per_sec` | Gateway-wide bucket capacity. |

Validation rejects non-positive rates, bursts < 1, and a rate < 1 without an
explicit burst (the defaulted sub-1 bucket could never admit a whole token, so
every call would be denied).

## `[gateway.egress]`

Struct: `EgressConfig`. The SSRF guard for **HTTP upstreams**
(`streamable-http` / `sse`) and the `jwks_uri` fetch. Cloud-metadata
(`169.254.169.254`), link-local (`169.254.0.0/16`, `fe80::/10`), and the
unspecified address are **always blocked — there is no knob to allow them**.
Resolved IPs are DNS-pinned to defeat rebinding. Inspect the effective policy
with `mcpdef egress show`.

| Key | Type | Default | What it does |
|---|---|---|---|
| `allow_private` | bool | `true` | Allow private / loopback / unique-local upstream addresses (MCPdef commonly fronts internal or localhost MCP servers). Set `false` to reach only public upstreams. |
| `require_https` | bool | `true` | Require HTTPS for public destinations (private/loopback may be plain HTTP). |

## `[gateway.upstream_tls]` and `[server.tls]` — TLS towards upstreams

Struct: `TlsConfig`. How MCPdef checks an HTTPS upstream's certificate, and
which certificate it presents to one that asks for one. `[gateway.upstream_tls]`
is the profile of every `https://` upstream and of the gateway's own fetches (a
`jwks_uri`). A server's `[server.tls]` goes over it field by field: a key the
server's table sets replaces the gateway's, and the rest are the gateway's.
With neither table, an HTTPS upstream is verified against Mozilla's roots,
bundled into the binary, as it always was.

Every file is PEM, and is read at each connection, so a certificate renewed in
place is the one the next connection presents. A reload reconnects the
upstreams whose files changed (see
[OPERATIONS.md § Reloading the config](./OPERATIONS.md#reloading-the-config)).

| Key | Where | Type | Default | What it does |
|---|---|---|---|---|
| `roots` | both | `"bundled"` \| `"system"` \| `"both"` | `"bundled"` | Whose root certificates to trust: Mozilla's, bundled into the binary and the same on every host; the host's store (the files `SSL_CERT_FILE` and `SSL_CERT_DIR` name, if either is set, else the system's); or both. On a host with no store, `system` fails each connection, saying so. |
| `ca` | both | array of paths | `[]` | More roots: files of CA certificates, such as a private CA's. A server's `ca` replaces the gateway's; `ca = []` drops it. |
| `crl` | both | array of paths | `[]` | Files of CRLs. A server certificate one of them revokes is refused. So is one whose status none of them tells: rustls checks every certificate in the chain, so each CA on the path to the server needs its CRL here. Behind an intermediate, that is the root's CRL as well as the intermediate's. |
| `min_version` | both | `"1.2"` \| `"1.3"` | `"1.2"` | The oldest TLS version to speak. |
| `client_cert` | both | path | unset | A certificate to present to an upstream that asks for one (mTLS): the certificate first, then any intermediates. Set with `client_key`: a server's pair replaces the gateway's. It is presented whichever roots verified the server. |
| `client_key` | both | a [secret](#secrets) | unset | The certificate's key, as PEM: unencrypted, PKCS#8, PKCS#1 or SEC1. A key file may be the certificate's file too. Keep it readable by MCPdef alone. A plain string is the key itself, so a path goes in `{ file = "…" }`. |
| `connect_to` | `[server.tls]` | IP address | unset | Dial this address in place of what the URL's host resolves to, and still check the certificate against the host's name, which is also the SNI. The address passes the egress guard as a resolved one would: `169.254.169.254` is refused. The URL has to name a host, not an address. |
| `insecure_skip_verify` | `[server.tls]` | bool | `false` | Accept whatever certificate the upstream presents: no chain, name or CRL is checked. `mcpdef validate` and startup warn about it, and every connection opened with it is audited (`kind = "upstream"`, `method = "connect"`, `rule = "tls-verify-disabled"`). Give the upstream's CA in `ca`, or pin it, instead. |
| `pin_sha256` | `[server.tls]` | array of strings | unset | SPKI pins, as [`mcpdef tls pin`](#cli-flags) prints them: the base64 SHA-256 of a key. With any, the upstream is trusted by its key alone. The certificate's issuer, names and dates are not checked, so a self-signed upstream works, and a certificate renewed on the same key keeps its pin. The handshake is still checked against the key, so a copy of the certificate is no use to anyone without the key. List a new key's pin beside the old one before the server moves to it. Refused in the same table as `roots`, `ca` or `crl`, which it would make pointless, and as `insecure_skip_verify`. |

For a self-signed upstream, pin it rather than turn verification off:
`mcpdef tls pin https://host:port/mcp` prints a `pin_sha256` line to paste
into its `[server.tls]`, once its fingerprint checks out against the
server's own.

`mcpdef egress show` prints the profile each HTTPS upstream ends up with, and
the admin API's `/api/v1/servers` the certificate each one presented, with its
expiry (see [API.md § Admin listener](./API.md#admin-listener-gatewayadmin)).

`[server.tls]` is for an `https://` upstream, and is refused on a stdio, wasm
or `http://` one. A PKCS#12 or DER file is refused, with the `openssl` command
that makes PEM of it, and so is an encrypted key. An unknown key in either
table fails the config: a misspelled `crl` must not pass unnoticed.

## `[gateway.tls]` and `[gateway.admin.tls]` — TLS on MCPdef's own listeners

Struct: `ListenerTlsConfig`. `[gateway.tls]` is the MCP listener's (`mcpdef run
--http`, `mcpdef up`). The admin listener serves the same, unless
`[gateway.admin.tls]` sets its own. Off by default: an upgrade changes nothing.

```toml
[gateway.tls]
mode = "self-signed"               # off (default) | files | self-signed
hostnames = ["mcpdef.internal"]    # besides localhost, 127.0.0.1, ::1 and the listen address

# mode = "files", as cert-manager or certbot writes them:
# cert = "/etc/mcpdef/tls/tls.crt"
# key  = { file = "/etc/mcpdef/tls/tls.key" }
```

| Key | Mode | Type | Default | What it does |
|---|---|---|---|---|
| `mode` | — | `off` \| `files` \| `self-signed` | `off` | `off`: plain HTTP. `files`: serve the certificate and key that `cert` and `key` name. `self-signed`: serve a certificate a local CA of MCPdef's own issues (below). |
| `hostnames` | `self-signed` | array of strings | `[]` | What the certificate is for besides `localhost`, `127.0.0.1`, `::1` and the address the listener binds to (none for `0.0.0.0` or `[::]`, which are every address): DNS names or IP addresses, no wildcards. The local CA vouches for the names it was made with and no others: name them before `mcpdef tls init`. |
| `cert` | `files` | path | unset | The certificate, then any intermediates it needs, as PEM. |
| `key` | `files` | secret | unset | Its key, unencrypted, as PEM: `{ file = "…" }`, `{ env = "…" }`, `{ exec = […] }`, or the key itself, which is warned about as any secret in the config is. Read as a client key is (see [Secrets](#secrets)): PEM only, as PKCS #8, PKCS #1 or SEC1, and the certificate's own. |

A key the mode does not take is refused, and so is a hostname that is neither
a DNS name nor an IP address. `files` needs both `cert` and `key`, and
`mcpdef validate` reads them as the gateway would.

**The local CA** (`self-signed`). `mcpdef tls init` makes it, or the gateway
as it starts if there is none, under [`[gateway] state_dir`](#gateway):
`tls/ca.crt` and `tls/ca.key`, then the certificate it issues the listeners,
`tls/tls.crt` and `tls/tls.key`.

- **A CA and a short-lived certificate under it**, not a bare self-signed
  certificate. A client trusts the CA once: `mcpdef tls init` prints how, for
  each client. The certificate lasts thirty days, and a running gateway issues
  it again with ten left, without anyone trusting anything again.
- **It vouches for its names and no others.** The CA carries a name
  constraint, which clients check: `localhost`, `127.0.0.0/8`, `::1`, each
  listen address, and `hostnames`, each with the names under it. A
  certificate its key, stolen, signed for any other name would not check. A
  name added later needs a new CA, `mcpdef tls init --new-ca`, and every
  client to trust it instead: until then the gateway does not start, or
  reload, with that name, and says which name and what to run.
- It is valid for ten years; `mcpdef tls show` warns in its last thirty days.
- The directory is `0700` and the keys `0600`. Each pair is written beside
  where it goes and renamed into place: a failed write leaves the pair before
  it as it was.
- A running gateway never makes a CA to replace one that went missing: a
  reload or a renewal that finds none fails, and says to run `mcpdef tls
  init`.

**Reloads.** A reload (`SIGHUP`, or `watch_config`, which watches the `cert`
and `key` files) reads each listener's certificate again and serves it from
the next connection on. A connection keeps the certificate it was accepted
with. A certificate or key that does not read, or a name the local CA does not
vouch for, refuses the reload, and the certificate before it serves on.
Turning TLS on or off on either listener needs a restart: it changes the URL
every client has.

**The handshake.** TLS 1.2 and 1.3, on ring, offering HTTP/1.1. A client has
10 s to finish its handshake, and one that stalls holds up no other. A client
certificate is asked for only with [`client_auth`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity).

**Exposure.** A listener on an address other than a loopback one, with
neither `[gateway.tls]` nor `[gateway.auth]` on, is warned about at startup,
at each reload and by `mcpdef validate`, and is refused under
[strict](#strict-mode). A
[`[gateway.trusted_proxy]`](#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front)
terminating TLS in front of it counts as TLS only under `client_auth`'s
`mode = "required"`: the proxy does not stop a client connecting to the
listener directly, and under `optional` one that does is served as no one.

### `[gateway.tls.client_auth]` — mTLS: client certificates as identity

Struct: `ClientAuthConfig`. What the listener asks of a client's certificate.
Off by default. The admin listener asks what `[gateway.tls]` asks, unless
`[gateway.admin.tls]` sets its own table, and `[gateway.admin.tls.client_auth]`
with it.

```toml
[gateway.tls.client_auth]
mode = "required"                       # off (default) | optional | required
ca = ["/etc/mcpdef/tls/agents-ca.pem"]  # what a client's certificate chains to
crl = ["/etc/mcpdef/tls/agents.crl"]    # optional
identity = "spiffe"                     # spiffe | san-dns | san-email | subject-cn
trust_domains = ["prod.acme.internal"]  # spiffe only

[[identity.cert_map]]                   # the roles a certificate holds
identity = "spiffe://prod.acme.internal/ns/ci/*"
roles = ["ci"]
```

| Key | Type | Default | What it does |
|---|---|---|---|
| `mode` | `off` \| `optional` \| `required` | `off` | `off`: no certificate asked for. `optional`: one asked for, and checked when the client presents it; a client that presents none is served as no one. `required`: a client that presents none is refused at the handshake; behind a [trusted proxy](#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front), a request the proxy forwards none with is refused with `403`. |
| `ca` | array of paths | `[]` | Files of the CA certificates a client's certificate has to chain to, as PEM, each one that can be a root. With `identity = "spiffe"`, the trust bundle, as spiffe-helper writes it. `optional` and `required` need it. |
| `crl` | array of paths | `[]` | Files of CRLs, as PEM. A certificate they revoke is refused, and with any, so is one whose status none of them tells: every CA in a client's chain needs its CRL here. |
| `identity` | `spiffe` \| `san-dns` \| `san-email` \| `subject-cn` | unset | Which of a certificate's names is its client's identity (below). `optional` and `required` need it. |
| `trust_domains` | array of strings | `[]` | With `identity = "spiffe"`, which needs it, and with no other: the trust domains a SPIFFE ID may name, as `prod.acme.internal`, without `spiffe://`. Every CA in `ca` is trusted for each of them, as a spiffe-helper bundle with its federated domains is. |

A key `off` does not take is refused, and so is a `ca` or `crl` file that does
not read as an upstream's does, a trust domain that is not one, and
`client_auth` on a listener with no TLS, unless a
[`[gateway.trusted_proxy]`](#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front)
forwards its clients' certificates. There is no `max_depth`: rustls has no
setting for one, and caps a chain's length itself.

With no PKI of your own, the local CA issues clients their certificates:
`mcpdef tls issue --client <name>` writes one, and prints the `ca` and `crl`
that take it, `<state_dir>/tls/ca.crt` and `<state_dir>/tls/ca.crl`;
`mcpdef tls revoke` puts one in that CRL. They are read by `subject-cn`, or by
`spiffe` when issued with `--spiffe-id`, never by `san-dns`: the local CA
vouches for the listeners' names alone. See the [CLI](#cli-flags).

**At the handshake.** rustls checks the chain to `ca`, the dates, that the
certificate is for a TLS client if its extended key usage says what it is
for, and, with `crl`, revocation. A certificate that says it is a CA is
refused as a client's. A certificate refused at the handshake is logged, a
client that presents none is not:

```text
mcpdef: refused the client certificate 203.0.113.7:51234 presented: invalid peer certificate: Revoked
```

**Who the client is**: one of the certificate's names, as `identity` says.
- `spiffe`: its SPIFFE ID, under the X509-SVID rules. The certificate has
  exactly one URI name, DNS names beside it allowed, and it is a SPIFFE ID:
  `spiffe://`, a trust domain of lowercase letters, digits, `.`, `-` and `_`,
  then a path whose segments are letters, digits, `.`, `-` and `_`, none of
  them empty, `.` or `..`, 2048 bytes in all at most. Its trust domain is one
  of `trust_domains`.
- `san-dns`: its first DNS name.
- `san-email`: its first email address.
- `subject-cn`: its subject's common name.

A certificate that gives no identity this way, or one that is empty or holds
a control character, refuses the request it carries with `403`, saying why: a
client is never taken for no one when it presented someone.

```text
the client certificate names no identity MCPdef accepts: its SPIFFE ID is in trust domain "staging.acme.internal", which is not one of trust_domains
```

The identity is recorded as `cert:<identity>`: as the record's `agent` when
no token names the caller, and as its `actor` behind one that does (see
[`[gateway.auth]`](#gatewayauth--oauth-21-resource-server)). A
[`[[policy]]`](#policy--policy-as-code-rules) rule's `agents` matches it so:
`agents = ["cert:spiffe://prod.acme.internal/ns/ci/*"]`. Every record of a
request over HTTP carries the client's address, as `peer`.

**`[[identity.cert_map]]`**: a certificate's roles, which
[`[[role]]`](#role--rbac) grants are judged by. Each entry whose `identity`
matches gives its `roles`, and every entry that matches is counted. A
certificate no entry maps holds no role, never a default one: with any
`[[role]]` defined, it is granted nothing.

| Key | Type | What it does |
|---|---|---|
| `identity` | string | An identity as `identity` reads it: exactly, or as a glob whose `*` matches any run of characters, `/` included. Not empty. |
| `roles` | array of strings | The `[[role]]`s it holds: at least one. A role no `[[role]]` defines grants nothing, and is warned about. |

**Reloads.** Everything in `client_auth`, and the cert map, applies on a
reload, and `watch_config` watches the `ca` and `crl` files: a SPIFFE trust
bundle or a CRL refreshed in place applies within 30 s. A new connection's
handshake is checked against what the reload read, and so is the next request
on a connection already open: a certificate a new CRL revokes, or one a new
`ca` no longer covers, is refused with `403` from then on, on every
connection. A certificate that expires while its connection is open is
refused from its next request. A `ca` or `crl` file that does not read refuses
the reload, and what was in force stays.

### `[gateway.trusted_proxy]` — a proxy that terminates TLS in front

Struct: `TrustedProxyConfig`. A proxy in front of the MCP listener, such as
Envoy, or an Istio sidecar or gateway, that terminates its clients' TLS and
forwards each request with the client's certificate in a header.
Unset by default: no proxy is trusted, and no such header is read.

```toml
[gateway.trusted_proxy]
cidrs = ["10.0.0.0/8"]                          # the proxy's addresses
client_cert_header = "x-forwarded-client-cert"  # or "client-cert" (RFC 9440, the default)

[gateway.tls.client_auth]                       # checks and reads what it forwards
mode = "required"
ca = ["/etc/mcpdef/tls/agents-ca.pem"]
identity = "spiffe"
trust_domains = ["prod.acme.internal"]
```

| Key | Type | Default | What it does |
|---|---|---|---|
| `cidrs` | array of strings | (required) | The proxy's addresses: ranges such as `10.0.0.0/8` and `fd00::/8`, or addresses alone, as the listener sees the proxy connect. An IPv4 client of a dual-stack listener is matched as IPv4. |
| `client_cert_header` | `client-cert` \| `x-forwarded-client-cert` | `client-cert` | The header the proxy forwards the certificate in: RFC 9440's `Client-Cert`, its intermediates in `Client-Cert-Chain`; or the XFCC that Envoy and Istio write. |

`[gateway.tls.client_auth]` has to be on: it says how what the proxy forwards
is checked and read. An empty `cidrs`, an entry that is not an address or a
range, or one with bits set past its prefix length, is refused. A range that
holds every address (`0.0.0.0/0`, `::/0`) is warned about, and refused under
[strict](#strict-mode).

**From the proxy alone.** The header is read on a connection from an address
in `cidrs`, and on no other. A client's certificate is no secret: whoever may
send the header can be any client whose certificate they have seen. From
anyone else, the header is not read at all, so a forged one names no one; and
like every header a client sends, it is never forwarded to an upstream.

**Checked by MCPdef.** The proxy is trusted to say which certificate its
client presented, not that it checks out. MCPdef checks it as it checks one
presented at its own handshake, against `[gateway.tls.client_auth]`: the chain
to `ca`, through the intermediates the proxy forwards with it, the dates, that
it is for a TLS client and is not a CA, and, with `crl`, revocation. Then it
reads its identity and its roles by the same rules. It does so on every
request. A request from the proxy that:
- forwards a certificate that checks out is that client's, as if it had
  presented it at the handshake, and is recorded as `cert:<identity>`. The
  record's `peer` is the proxy's address: MCPdef does not read
  `X-Forwarded-For`.
- forwards none is no one's: `mode = "required"` refuses it with `403`, `a
  client certificate is required`.
- forwards one that does not check out, or a header that does not read, is
  refused with `403`, saying why. A header that does not read is never taken
  for no certificate.

**What it reads.**
- `client-cert` (RFC 9440): `Client-Cert` holds the certificate, one Byte
  Sequence, `:` base64 DER `:`, in one header. `Client-Cert-Chain` holds the
  intermediates, a list of them, in one header or more. A parameter, a second
  `Client-Cert`, or a chain without one is refused.
- `x-forwarded-client-cert` (Envoy, Istio): exactly one element, which the
  proxy in front of MCPdef set rather than appended to, as Envoy's
  `forward_client_cert_details = SANITIZE_SET` does. Of more, MCPdef cannot
  tell which proxy wrote which. Its `Cert`, the certificate as URL-encoded
  PEM, or else the first of its `Chain`, the rest of which are the
  intermediates. The proxy has to forward the certificate itself: Envoy's
  `set_current_client_cert_details` with `cert: true`, and `chain: true` for a
  certificate from an intermediate CA. Istio's default XFCC names the client
  and carries no certificate, and is refused: MCPdef takes no name it cannot
  check.
- At most 10 certificates in all.

```text
the client certificate the proxy forwarded does not read: x-forwarded-client-cert carries no Cert: MCPdef checks the client's certificate itself, so the proxy has to forward it (Envoy: set_current_client_cert_details { cert: true })
```

**TLS of its own.** The listener may serve plain HTTP, the proxy terminating
TLS in front: `[gateway.tls]` stays `off`, and `[gateway.tls.client_auth]`
checks forwarded certificates alone. The proxy does not stop a client
connecting to the listener directly, with no certificate: `mode = "required"`
refuses it, and `optional` serves it as no one, so with `[gateway.auth]` off a
listener other machines reach is warned about as
[exposed](#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners). With
`[gateway.tls]` on, the proxy connects over TLS, and a client that connects
directly presents its own certificate at the handshake, as without a proxy.
On a request from the proxy, the certificate the proxy presented at its
handshake, if any, is its own, and never taken for its client's. Under
`mode = "required"` the proxy has to present one from `ca`. To have every
request carry a client's certificate, forwarded or presented, without asking
the proxy for one, set `mode = "optional"` and
`[gateway.auth] methods = ["mtls"]`.

**Reloads.** `cidrs` and `client_cert_header` apply from the next request
after a reload. Setting `[gateway.trusted_proxy]`, or removing it, needs a
restart. The admin listener does not read the header.

## `[gateway.auth]` — OAuth 2.1 Resource Server

Struct: `AuthConfig`. Applies to the **HTTP listener only**: when `enabled`,
every `POST /mcp` must carry what `methods` and `require` ask, by default a
valid `Authorization: Bearer <JWT>`, validated
per request (signature against the JWKS, `aud == resource`, `iss == issuer`,
`exp`/`nbf`, each a number of seconds or the token is refused; asymmetric
algorithms only — `none`/HMAC are rejected). Running
`mcpdef run` *without* `--http` while auth is enabled prints a warning: stdio has
no per-request transport identity, so auth is not enforced there.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `false` | Turn auth on. When `true` and `bearer` is one of `methods`, `issuer`, `resource`, and one of `jwks`, `jwks_uri` and `discovery` are required (blank strings count as unset). |
| `methods` | array of `bearer` \| `mtls` \| `key` | `["bearer"]` | How a caller proves who it is: `bearer`, an access token; `mtls`, a client certificate, which [`[gateway.tls.client_auth]`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity) has to ask for; `key`, a [client key the gateway issued](#key--client-keys-the-gateway-issues); or several. `issuer`, `resource` and the keys are needed with `bearer` alone. |
| `require` | `any` \| `all` | `any` | With both methods: `any`, either credential will do; `all`, a request needs both. |
| `issuer` | string (URL) | unset | The authorization server's `iss` claim value. |
| `resource` | string (URL) | unset | This gateway's canonical URI — the audience tokens must carry (RFC 8707/9068). Also the origin used to build the `WWW-Authenticate` metadata URL (never derived from request headers). |
| `jwks` | inline JSON or path | unset | Pinned keys: inline JWKS JSON (a value starting with `{`) or a path to a JWKS file. Preferred for hardened deploys — no startup network dependency. |
| `jwks_uri` | string (URL) | unset | Fetch the JWKS at startup, and again on an unknown `kid`, through the egress/SSRF guard and with `[gateway.upstream_tls]`, so an IdP on a private CA works. `jwks` wins if both are set. |
| `discovery` | bool | `false` | Find `jwks_uri` from the issuer's metadata as the gateway starts: OpenID Connect Discovery's `<issuer>/.well-known/openid-configuration`, else RFC 8414's `/.well-known/oauth-authorization-server` before the issuer's path. The document must name `issuer` exactly, or it is refused, and the keys are then fetched, and re-fetched, as `jwks_uri`'s are. Not with `jwks` or `jwks_uri`. `mcpdef doctor` shows what it finds. |
| `audiences` | array of strings | `[]` | Audiences a token may carry besides `resource`: an API the identity provider names its own way, as Entra ID's application ID URI, `api://<app id>`. The protected resource metadata still names `resource` alone. Never the admin API's `api_audience`. |

**With a client certificate.** A token is the caller's subject when the request
carries one, and a certificate behind it is recorded as the `actor`: the
workload the token's subject called through. A certificate alone is the
subject, and its roles come from
[`[[identity.cert_map]]`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity).
- `methods = ["mtls"]`: a request without a certificate that gives an identity
  is refused with `403`, `a client certificate is required`; no token is read.
- `methods = ["bearer", "mtls"]`, `require = "any"`: either will do. With
  neither, the `401` challenge that says where to get a token.
- `require = "all"`: both. Without the token, the `401` challenge; without the
  certificate, `403`. The token's subject is the `agent`, and its roles are
  what RBAC judges.

A token that is presented and does not check out is refused with `401`, and a
certificate that gives no identity with `403`, whatever else the request
carries. With auth off, a certificate the listener asks for still names its
caller, and its roles are judged. `methods` that is empty or names a method
twice, `mtls` where the MCP listener asks for no certificate, and either key
set while auth is off are refused.

## `[gateway.admin]` — the admin listener: console, API and metrics

Struct: `AdminConfig`. The console, its JSON API, and Prometheus `/metrics` —
see [API.md § Admin listener](./API.md#admin-listener-gatewayadmin). Off by
default; runs on a **separate port** from the MCP data path so scraping it
never touches the governed hot path.

| Key | Type | Default | What it does |
|---|---|---|---|
| `enabled` | bool | `false` | Start the admin server alongside the gateway. |
| `listen` | string `host:port` | `"127.0.0.1:7879"` | Bind address for the admin server. Loopback by default, and a different port than `[gateway] listen`. The line after the ready line names the address taken, so port `0` works here too. One that cannot be bound stops the start. |
| `tls` | table | unset: `[gateway.tls]`'s | The admin listener's own TLS, `[gateway.admin.tls]`, with the keys of [`[gateway.tls]`](#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners). Unset, it serves what `[gateway.tls]` says: HTTPS with the MCP listener's certificate, when that is on. `mode = "off"` keeps it on plain HTTP beside a TLS listener, for a Prometheus scrape on loopback, say. |
| `public_url` | string (URL) | unset | The console's URL as its users reach it: `https://host[:port]`, an origin with no path. A browser's request that changes something may come from it, and a request may name its host. Signing in needs it: the identity provider sends people back to `<public_url>/callback`. `http` only to this machine. |
| `hosts` | array of strings | `[]` | Host names a request may name besides an IP literal, `localhost`, `listen`'s host and `public_url`'s: the name of a Kubernetes Service a scraper uses, say. A request naming any other is refused `421`, so a page cannot rebind its own name to this listener (DNS rebinding). A name alone, with no scheme or port. |
| `allow_unauthenticated` | bool | `false` | Serve a listener other machines reach with nothing to sign its callers in: for a proxy in front that authenticates them. Every caller then holds `console:admin`. |

**Who may use it.** Each request's caller holds one of three console roles,
each with those below it: `console:viewer` reads; `console:operator` also
acts (reload, restart, test, approve drift); `console:admin` also reads the
redacted config and the identity views.
- **Nothing signs callers in** (the default): a loopback listener is open to
  this machine. Whoever reaches it is `local` and holds `console:admin`, and
  the console says so. A listener other machines reach is refused by
  `mcpdef validate` unless `allow_unauthenticated = true`.
- **A client certificate it requires** (`client_auth` `mode = "required"` in
  `[gateway.admin.tls]`, or in the `[gateway.tls]` it serves): the certificate
  names its caller, `cert:<identity>`, and
  [`[[identity.cert_map]]`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity)
  gives its console role: `roles = ["console:viewer"]`, say. A certificate
  that maps to no console role is refused every route but
  `GET /api/v1/session`: **unmapped means no role**, never a default one. A
  console role names no `[[role]]`; one misspelt, such as `console:viewers`,
  is refused.
- **A bearer token**, `Authorization: Bearer <token>`, where the admin API
  takes one, names its caller before anything else the request carries:
  - one the identity provider issued for the admin API, its audience
    [`api_audience`](#gatewayadminoidc--signing-people-in-to-the-console):
    `token:<subject>`, with the console role its scopes and roles give;
  - the [break-glass token](#gatewayadminbreak_glass--when-no-one-can-sign-in):
    `break-glass`, which holds `console:admin`.

  Any other bearer token is refused `401`. Where the admin API takes none,
  an `Authorization` header is not read.
- **People signing in** at an identity provider,
  [`[gateway.admin.oidc]`](#gatewayadminoidc--signing-people-in-to-the-console):
  a session names its caller, `user:<subject>`, and the roles the provider
  gives, read by [`[identity]`](#identity--who-a-token-says-its-caller-is),
  give its console role. One not signed in is `anonymous`, and is refused
  `401` with where to sign in, `/login`, everywhere but the console's own
  files, `/health` and `GET /api/v1/session`. A client certificate, where the
  listener asks for one, still names its caller first.

**What every request passes.** A Host this listener answers to, as `hosts`
says, or `421`. A request that changes something (anything but GET, HEAD and
OPTIONS) from a browser must come from the console's own origin:
`Sec-Fetch-Site: same-origin`, or with no such header an `Origin` that is this
listener's or `public_url`'s; one with neither is not a browser's. It sends
JSON or no body: a form is refused `415`. Every answer carries a content
security policy (the console's own scripts, styles and API, no frames),
`nosniff`, `no-referrer` and `no-store`, and every refusal is an RFC 9457
`application/problem+json` document.

### `[gateway.admin.oidc]` — signing people in to the console

Struct: `OidcConfig`. The console signs people in at an OpenID Connect
provider, as a client of its authorization code flow with PKCE: Keycloak,
Entra ID, Okta, Google, Authentik, or any other that publishes a discovery
document. `mcpdef sso init --provider <name>` (`keycloak`, `entra`, `okta`,
`google`, `authentik`, `generic` or `saml-broker`) prints this table, the
`[identity]` that reads the provider's tokens, and what to set at the
provider; with `--issuer`, `--public-url` and `--write`, it merges them into
the config instead, keeping a `.bak` of it, and refuses rather than change a
sign-in or an `[identity]` already set, or, where `[gateway.auth]` is on, the
claims the MCP listener reads its callers' tokens by. A SAML provider signs people in through a broker in front of it
that speaks OpenID Connect: Keycloak, which MCPdef is tested with, authentik
or ZITADEL; not Dex, whose own documentation calls its SAML connector
unmaintained ([SAML.md](./SAML.md)). Provider by provider:
[SSO.md](./SSO.md). Register a client
with the provider whose redirect URI is `<public_url>/callback` and whose
post-logout redirect URI is `<public_url>/`; `public_url` is required.

| Key | Type | Default | What it does |
|---|---|---|---|
| `issuer` | string (URL) | — | The provider's issuer, exactly as its ID tokens' `iss` and its discovery document, `<issuer>/.well-known/openid-configuration`, write it: `https://keycloak.example/realms/ops`. `https`, or `http` to this machine. |
| `client_id` | string | — | The client registered with the provider. An ID token must name it as its audience. |
| `client_secret` | [secret](#secrets) | unset | The client's secret: `{ env = "MCPDEF_OIDC_SECRET" }`, say. Read at each sign-in. Unset, the client is a public one, which PKCE alone proves. |
| `client_auth` | `"client_secret_basic"` \| `"client_secret_post"` | `"client_secret_basic"` | How the secret reaches the token endpoint: HTTP basic authentication, or in the form. |
| `scopes` | array of strings | `["profile", "email"]` | The scopes asked for besides `openid`, which is always asked for, first. Add the one that puts groups in the ID token where the provider has one: `groups`. |
| `userinfo` | bool | `false` | Read the userinfo endpoint too, adding its claims to those of the ID token, which keeps its own: for a provider that sends groups or an e-mail address there alone. Its `sub` must be the ID token's, and its failure fails the sign-in. |
| `api_audience` | string | unset | Take the provider's access tokens on the admin API, for automation: those whose `aud` holds this, as the provider issues them for an API registered with it (a client credentials grant, say). Never `[gateway.auth] resource`, so a token for the MCP listener opens nothing here, nor `client_id`, so an ID token does not either; and the MCP listener refuses these. Unset, the admin API takes no token of the provider's. |

**How someone signs in.** The console sends them to `/login`, which sends
them to the provider with a state, a nonce and a PKCE challenge (S256), each
32 random bytes, sealed in a ten-minute `__Host-mcpdef-login` cookie. The
provider sends them back to `/callback`, where:
- the answer's `state` must be the cookie's, compared in constant time, and
  each sign-in is finished once: an answer replayed is refused, whatever the
  provider would make of its code;
- its `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) must be the
  issuer when it is sent, and must be sent when the provider says it sends it;
- the code is exchanged at the token endpoint, with the PKCE verifier and the
  client's secret, through the [egress guard](#gatewayegress) and
  [`[gateway.upstream_tls]`](#gatewayupstream_tls-and-servertls--tls-towards-upstreams);
- the ID token must be signed by a key of the provider's `jwks_uri`, with
  RS256, RS384, RS512, PS256, ES256 or ES384 (never `none` or HMAC), and must
  name the issuer, the client as its audience, the client as its `azp` when
  it has one or names several audiences, the sign-in's nonce, and an `iat`
  not in the future; it must not have expired;
- `[identity]` reads its subject and roles from its claims, with userinfo's
  when `userinfo` is set. One with a console role gets a session, and goes
  back to the console page they started from. One with none gets a page
  listing the claims MCPdef received, for them alone, to show whoever gives
  out roles; no session.

No token is kept: the session holds who signed in and their roles, which
last until it ends. A change to their roles at the provider counts at their
next sign-in. `POST /logout` signs them out (below), and answers
`{ "redirect": … }`, where the browser goes next: the provider's
`end_session_endpoint`, with `client_id` and `post_logout_redirect_uri`, to
sign out there too, or `/` where it has none.

The provider is found when the gateway starts. If it cannot be, the gateway
starts anyway, says why, and looks again at a sign-in, at most every 5
seconds, a sign-in before then being refused `503` with why: the data plane
never waits on the console's provider. An ID token signed by a key the
provider's keys did not hold has them read again, at most once a minute, so
a key it rotates in is taken at the first sign-in it signs. Signing in, each refusal of it, and
signing out are [audit records](./API.md#admin-listener-gatewayadmin) of kind
`admin`: `sign-in` and `sign-out` on `(console)`, by `user:<subject>`, or by
`anonymous` when the sign-in is refused before anyone is known. A refusal's
rule says why: `sign-in-state`, `sign-in-issuer`, `sign-in-provider`,
`sign-in-token`, `sign-in-userinfo`, or `no-console-role`. Past twenty refused in a minute, one more record, with the rule
`sign-in-refusals-unrecorded`, says the rest of that minute's are not
recorded: anyone who reaches the listener can be refused, so the ledger grows
by so much at most.

```toml
[gateway.admin]
enabled = true
listen = "0.0.0.0:7879"
public_url = "https://mcpdef.example.com:7879"

[gateway.admin.oidc]
issuer = "https://keycloak.example.com/realms/ops"
client_id = "mcpdef-console"
client_secret = { env = "MCPDEF_OIDC_SECRET" }

# Keycloak's client roles for this client, `console:viewer` and the others,
# defined on it and given to groups.
[identity]
roles_claims = ["resource_access.mcpdef-console.roles"]
```

**Automation** calls the admin API with a token the provider issues for
`api_audience`, verified as the MCP listener verifies its own: the
provider's keys (read again when it rotates them), its issuer, `exp`, and
an algorithm of those above. Its caller is `token:<subject>`, the subject
read by `[identity]` and else `sub`, and holds the highest console role
among those its scopes give, `mcpdef:admin:read` `console:viewer` and
`mcpdef:admin:write` `console:operator`, and those `[identity]` reads from
its claims, as a person's are. No scope gives `console:admin`: a role the
provider puts in the token, or `[[identity.role_map]]`, does. A request
with no browser's headers needs no origin, so a script sends just the
token: `curl -X POST -H "Authorization: Bearer $TOKEN" https://…/api/v1/reload`.

With Okta or Google, where membership of a group or a hosted domain says who
may do what, map it to a console role:

```toml
[[identity.role_map]]
claim = "groups"
value = "mcp-operators"
roles = ["console:operator"]
```

### `[gateway.admin.break_glass]` — when no one can sign in

Struct: `BreakGlassConfig`. One token that holds `console:admin` on the
admin API, for when the identity provider cannot sign anyone in: it is
down, or misconfigured, or the people who give out roles are locked out.
Off unless this table is set; with it, the listener counts as signing its
callers in, so one that other machines reach needs nothing else, and one
on loopback is no longer open to this machine.

| Key | Type | Default | What it does |
|---|---|---|---|
| `token_sha256` | string | — | The token's SHA-256, in hex: the config never holds the token. `mcpdef admin token` makes a token, prints it once, and prints this table. A reload takes a new one, and removing the table and reloading takes the token away. |

The token is sent as `Authorization: Bearer mcpdef_bg_…`, and compared by
its digest, in constant time. **Every request made with it is recorded**,
before it is served: an `admin` record by actor `break-glass`, action
`break-glass`, its `uri` the request's method and path, and what it does,
a reload say, recorded too as it always is. Keep the token offline, where
those who may use it in an emergency can reach it, and make a new one
after each use.

### `[gateway.admin.session]` — the console's sessions

Struct: `SessionConfig`. A session is sealed into the `__Host-mcpdef-session`
cookie with AES-256-GCM: `Secure`, `HttpOnly`, `SameSite=Lax`, for this
host alone. It ends 8 hours after it began, or after 30 minutes unused; one
in use is sealed again every 5 minutes or so. Signing out clears the cookie
and refuses the session from then on. The gateway remembers that in memory,
until the session would have ended: a restart forgets it, and another
replica behind the same `public_url` never knew it, so a copy of the cookie
taken before would open there until the session ends. It keeps nothing else
per session: sessions survive a reload, and a restart when the key does.

| Key | Type | Default | What it does |
|---|---|---|---|
| `key` | [secret](#secrets) | unset | 32 bytes, in base64 or hex: `openssl rand -base64 32`. Unset, the key in `<state_dir>/session.key`, 32 random bytes the gateway writes `0600` the first time it needs them. Give every replica behind one `public_url` the same key. |
| `previous_key` | [secret](#secrets) | unset | The key before `key`, which opens the sessions it sealed, so that changing the key signs no one out. Drop it once the sessions it sealed have ended: after 8 hours. |

A new key, or a deleted `session.key`, signs everyone out. A change to
`[gateway.admin.oidc]`, `[gateway.admin.session]` or `public_url` takes a
restart.

## `[gateway.inspect]` — injection / secret-exfil scanning

Struct: `InspectConfig`. Inline scanning of the two untrusted-content surfaces an
in-path gateway straddles. Tool **descriptions** are scanned at connect — a
"line-jumping" / tool-poisoning attempt hides the tool from `tools/list` and denies
its `tools/call`. Tool-call **results** are scanned per call — a response that
leaks a credential or carries injected instructions is refused before it reaches
the model. So is what a `resources/read` or a `prompts/get` returns, since it
flows into the model's context the same way. A finding is audited under an
`injection` or `secret-exfil` rule. The built-in pack is a curated,
high-precision starter set: prompt-injection phrasing
plus secret patterns (AWS, Slack, GitHub and Stripe keys, PEM private-key blocks).
It is opt-in — start with `warn` before `enforce` or `redact`.

| Key | Type | Default | What it does |
|---|---|---|---|
| `mode` | `"off"` \| `"warn"` \| `"enforce"` \| `"redact"` | `"off"` | `off`: no scanning. `warn`: log and audit findings only. `enforce`: hide poisoned tools and refuse results that leak a secret or carry injected instructions. `redact`: as `enforce`, but a secret in a result is redacted in place rather than the result refused (below). Any other value fails `mcpdef validate`. |
| `injection_phrases` | array of strings | `[]` | Extra prompt-injection phrases on top of the built-in pack, matched **case-insensitively** (e.g. `"exfiltrate the"`). |
| `secret_substrings` | array of strings | `[]` | Extra secret substrings, matched **case-sensitively** (e.g. an internal credential prefix such as `"acme_sk_"`). A transform rule's `redact` finds them too, whatever `mode` is. |

**`mode = "redact"`** rewrites where `enforce` refuses. Each secret in a tool
call's result, a read's contents, a prompt's messages or a completion's values
becomes `[REDACTED:<rule>]` (`[REDACTED:aws-access-key]`), each string on its
own and never the serialized result, so the result stays valid JSON, and a
`structuredContent`'s text mirror is written again from the redacted structure
([Transform rules](#edits-of-a-result)). The result then passes, and its record
is allowed, with `rule = "secret-redacted"`. What redaction cannot make safe is
refused as under `enforce`:
- an injection: no rewrite of the text makes an instruction safe;
- a secret in an interim result (an `InputRequiredResult`), which carries state
  the upstream needs back untouched;
- a secret whose redaction the tool's `outputSchema` may not allow, as the
  transform rules judge it: the refusal says why;
- a secret in an object's key: a key is not redacted;
- a secret where the redaction of strings does not reach: in the base64 of an
  image, an audio clip or a blob, in a number, or in a match the pack makes only
  across two strings. A redacted result is read again whole, as `enforce` reads
  it, and passes only if the pack finds nothing;
- a tool whose description trips the pack, which is hidden: a description is
  pinned as the server wrote it.

## `[identity]` — who a token says its caller is

Struct: `IdentityConfig`. How a bearer token's claims name its caller: the
claim that is its subject, which becomes the audit identity (`sub:<subject>`),
and the claims that hold its roles, which `[[role]]` matches with its scopes.
The console reads an ID token's claims the same way when someone
[signs in](#gatewayadminoidc--signing-people-in-to-the-console), to name
them `user:<subject>` and give their console role.
With none of these set, a token is read as it always was: the subject from
`sub`, the roles from `roles`. A claim is named by a dotted path into the
token's claims (`realm_access.roles`); a claim whose own name holds dots, as a
namespaced one does (`https://example.com/roles`), is taken by that name
first. A claim may be a string or an array of strings; anything else holds no
value. A change to any of them takes a restart, as `[gateway.auth]` does.

| Key | Type | What it does |
|---|---|---|
| `subject_claim` | string (default `"sub"`) | The claim naming the caller. A token without it, as a non-empty string, is refused (`401`). |
| `roles_claims` | array of strings (default `["roles"]`) | The claims holding the caller's roles. |
| `[[identity.role_map]]` | `{ claim, value, roles }` | Roles given to a caller whose `claim` holds `value` (or, as an array, has it among its strings): an Okta group, a Google hosted domain. A role no `[[role]]` defines is warned about, a console role (`console:viewer`, `console:operator`, `console:admin`) excepted, since the console reads those. |
| `[[identity.cert_map]]` | `{ identity, roles }` | A client certificate's roles: see [`[gateway.tls.client_auth]`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity). |

Scopes count as they always did: `scope`, a string of them separated by
spaces, or `scp`, an array of them or, as Entra sends it, one string.

```toml
# Keycloak: realm roles, and the user's name as the subject
[identity]
subject_claim = "preferred_username"
roles_claims = ["realm_access.roles"]

# Entra ID: app roles are `roles` already; name callers by their object id
[identity]
subject_claim = "oid"

# Okta: a group becomes a role
[identity]
roles_claims = []
[[identity.role_map]]
claim = "groups"
value = "mcp-admins"
roles = ["admin"]

# Google: everyone in the hosted domain reads
[identity]
subject_claim = "email"
[[identity.role_map]]
claim = "hd"
value = "example.com"
roles = ["reader"]
```

`mcpdef auth test --token <jwt>` (or `--token -` to read it from stdin, or
`--token-file`) verifies a token as the listener does, and prints its
subject, roles and scopes, and on each server what those roles grant.

## `[[key]]` — client keys the gateway issues

Struct: `KeyConfig`. For a client of the MCP listener and no identity
provider: a key the gateway issues, which the client sends as its bearer
token, `Authorization: Bearer mcpdef_key_…`. The listener takes keys where
`[gateway.auth] methods` names `key`; its caller is then `key:<name>` in
every record, and holds the key's roles, which `[[role]]` grants as it
grants a token's.

| Key | Type | What it does |
|---|---|---|
| `name` | string | Its caller's name: one word, of letters, digits, `.`, `_` and `-`, each key's its own. |
| `sha256` | string | The key's SHA-256, in hex. The config never holds the key. |
| `roles` | array of strings | The `[[role]]`s its caller holds; at least one. A role no `[[role]]` defines is warned about: it grants nothing. |

`mcpdef keys create --name ci-bot --role reader` makes a key from 32 random
bytes, prints it once, and prints the `[[key]]` table for it; put the table
in the config and reload. A key is matched by its SHA-256, in constant time.
**A reload takes keys:** one added opens from the next request, and one
removed opens nothing from then on, so removing its table and reloading
revokes it. `mcpdef auth test --token mcpdef_key_…` says whom a key names
and what its roles grant. With `key` among `methods` alongside `bearer`, a
request carries one or the other, so `require = "all"` cannot ask for both.

```toml
[gateway.auth]
enabled = true
methods = ["key"]

[[role]]
name = "reader"
grants = ["github:list_*", "github:get_*"]

[[key]]
name = "ci-bot"
sha256 = "d83c71766f2b5e3e631916842b7dfc5b31c944dcccf610dc33507ee809a99497"
roles = ["reader"]
```

## `[[role]]` — RBAC

Struct: `RoleConfig`. Layered over the allowlist for **authenticated** HTTP
callers; with no `[[role]]` defined the gate is off (the allowlist alone
decides). A caller holds a role when the role's `name` appears among the
token's scopes or the roles [`[identity]`](#identity--who-a-token-says-its-caller-is)
reads from it (the `roles` claim, unless it says otherwise), or, for a client
certificate with no token, among the roles
[`[[identity.cert_map]]`](#gatewaytlsclient_auth--mtls-client-certificates-as-identity)
gives it.

| Key | Type | What it does |
|---|---|---|
| `name` | string (non-empty) | The role name matched against token scopes/roles. |
| `grants` | array of strings | Grants as `"server-glob:tool-glob"`; a bare `"tool-glob"` (no colon) grants it on any server. |
| `resource_grants` | array of strings | Resource-read grants as `"server-glob:uri-pattern"`, such as `"fs:file:///srv/docs/**"`, with a [URI pattern](#resource-uri-patterns). The server part is required: a URI holds a `:` itself, so the grant splits at its first. A grant with no server part, or one whose URI pattern would be refused, fails `mcpdef validate`, and one whose server part names no `[[server]]` is warned about. |
| `prompt_grants` | array of strings | Prompt grants as `"server-glob:prompt-glob"`; a bare `"prompt-glob"` grants it on any server, as in `grants`. |

With any `[[role]]` defined, an authenticated caller reads a resource only if a
role it holds grants it in `resource_grants`, and gets a prompt only if one
grants it in `prompt_grants`, as it calls a tool only if one grants it in
`grants`. A grant of one kind grants nothing of another. A completion of a
prompt needs what a get of it needs; a completion of a resource template needs a
role that grants some resource on its server, since a template names no one URI
to match a grant against. A caller no credential names (stdio, or HTTP with
neither a token nor a client certificate) is not judged by roles.

## `[[policy]]` — policy-as-code rules

Struct: `PolicyRuleConfig`. A richer gate than the allowlist, evaluated **after**
it. Where the allowlist decides on the tool name alone, a rule matches on the
caller (agent), the server, the tool (all globs) and the tool-call **arguments**
(per field) — so it can express "deny `delete_*` on `github` when `args.name` is a
`prod-*` repo", or "only `agent:ci-*` may call `deploy`".

The same rules judge a `resources/read`, by the URI it names (`uris`), and a
`prompts/get`, by the prompt's name (`prompts`) and its arguments (`args`). A
rule that names `tools` is about tool calls only, one that names `uris` about
reads only, one that names `prompts` about prompt gets only, and one that names
none of them, such as an `agents`-only rule, is about all three. A read has no
arguments, so a rule with `args` matches no read. A rule naming two of `tools`,
`uris` and `prompts`, or both `uris` and `args`, fails `mcpdef validate`: it
could match nothing.

A `completion/complete` is judged as a request for what it completes: a
prompt's as a get of the prompt, whose `args` are the arguments resolved so far
(`context.arguments`); a resource template's only by a rule that names none of
`tools`, `uris` and `prompts`, since a template names no one URI.

Rules run top to bottom and **the first match wins**, so put a specific `allow`
before a broad `deny`. No match means allowed (the allowlist already gated). A
denial is audited under the rule's own `name`.

A rule with `effect = "transform"` decides nothing: it rewrites a tool call's
arguments, in a pass of its own after the allowlist and before the `allow` and
`deny` rules, which then judge what it made. See [Transform rules](#transform-rules).

| Key | Type | Default | What it does |
|---|---|---|---|
| `name` | string | required | Identifies the rule; it is the `rule` written to the audit record on a deny. |
| `effect` | `"allow"` \| `"deny"` \| `"transform"` | required | Case-insensitive. Anything else fails `mcpdef validate`. |
| `servers` | array of globs | omitted = any server | Match on the governed server id. |
| `tools` | array of globs | omitted = any tool | Match on the tool name. A rule with `tools` matches tool calls only. |
| `uris` | array of [URI patterns](#resource-uri-patterns) | omitted = any URI | Match on the URI a `resources/read` names, in normal form. A rule with `uris` matches reads only. |
| `prompts` | array of globs | omitted = any prompt | Match on the name a `prompts/get` asks for; `args` then match the prompt's arguments. A rule with `prompts` matches prompt gets only. |
| `agents` | array of globs | omitted = any caller | Match on the audit identity (e.g. `agent:ci-*`). |
| `args` | array of predicates | `[]` | Per-argument predicates, **AND-ed**. See below. |
| `set_args` | array of edits | `[]` | A transform rule's edits of the arguments, in order: see [Transform rules](#transform-rules). Only a transform rule takes it. |
| `result` | array of edits | `[]` | A transform rule's edits of a result, a tool call's or a read's, in order: see [Edits of a result](#edits-of-a-result). Only a transform rule takes it, and one takes `set_args` or `result`, or both. |
| `on_error` | `"deny"` \| `"skip"` | `"deny"` | What a transform rule does when an edit, of the arguments or of a result, cannot apply. Only a transform rule takes it. |

Match conditions are AND-ed. **Omit** a condition to match anything for that
dimension; an explicit empty list (`servers = []`) is rejected by `mcpdef
validate`, because it would silently match nothing — a fail-open for a `deny`.

Each `args` predicate is a table with a dotted `path` into the arguments (e.g.
`"target.env"`) and **exactly one** operator:

| Operator | Type | Matches when |
|---|---|---|
| `equals` | string | the value at `path` equals the string. |
| `glob` | string | the value at `path` matches the glob. |
| `contains` | string | the value at `path` contains the substring. |
| `exists` | `true` | the path is present and not null. `exists = false` names no operator, so on its own it fails `mcpdef validate`. |

A predicate with no operator, or with more than one, fails `mcpdef validate`
rather than silently matching nothing.

```toml
[[policy]]
name    = "no-delete-prod"
effect  = "deny"
servers = ["github"]
tools   = ["delete_*"]
args    = [ { path = "name", glob = "prod-*" } ]

[[policy]]
name    = "no-secret-files"
effect  = "deny"
servers = ["fs"]
uris    = ["file:///srv/**/secret/**"]

[[policy]]
name    = "no-prod-release-notes"
effect  = "deny"
prompts = ["release_*"]
args    = [ { path = "env", equals = "prod" } ]
```

### Transform rules

A rule with `effect = "transform"` rewrites a tool call's arguments
(`set_args`), and what an upstream answers (`result`): a tool call's result, or
a read's contents. The transform rules make two passes of their own: over the
arguments, after the allowlist and before the `allow` and `deny` rules (mutate,
then validate), and over the result, once the upstream answers and before
inspect sees it.

- **Every** transform rule that matches applies, in config order, and each
  matches (`agents`, `servers`, `tools`, `args`) against the arguments as the
  rules before it left them. The first match wins only among `allow` and `deny`.
- The `allow` and `deny` rules then judge the arguments the transforms made,
  and those are what the upstream gets. The tool's name is not an argument, and
  no rule can change it.
- A rule with `set_args` rewrites tool calls only: one that also names `uris`
  fails `mcpdef validate`, since a read has no arguments. One with `result`
  alone may name `uris`, and then edits the contents of the reads it matches.
  No transform rule may name `prompts`.

Each `set_args` entry is a table with a dotted `path` into the arguments and
**exactly one** operation:

| Operation | Type | What it does |
|---|---|---|
| `set` | any value | Puts the value at `path`, whatever is there. The objects on the way are made where they are missing. |
| `default` | any value | Puts the value at `path` when nothing is there: it is absent, or null. |
| `remove` | `true` | Takes `path` out, if it is there. `remove = false` names no operation. |
| `clamp` | `{ min = …, max = … }` | Holds the number at `path` within the bounds: below `min` it becomes `min`, and above `max` it becomes `max`, as the rule writes them. A path that holds nothing is left so. One bound at least, and `min` no higher than `max`. |

A value is any TOML value but a date, which JSON has no form for (quote it),
and a float must be finite.

**An edit that cannot apply** met arguments of a shape the rule was not
written for: a `clamp` of something that is not a number, or a path through
something that is not an object. The call is then denied under the rule's own
`name`, and the client is told why by type and path, never by value:

```text
MCPdef denied: transform rule 'cap-page-size' could not apply to 'list_issues' on 'github': `per_page` is a string, not a number
```

With `on_error = "skip"`, the rule is skipped instead: the call keeps the
arguments the rules before it left, the log names the rule and why, and the
rules after it run.

**Audit.** Each record of the call, from the pass on, names the transform rules
that fired as `transforms`, in order, and never a value: those that fired on
the arguments, then those that fired on the result, each once. A rule fires
when it matches the call and applies, whether or not it changed a value; one
that could not apply did not fire.

```toml
[[policy]]
name     = "cap-page-size"
effect   = "transform"
servers  = ["github"]
tools    = ["list_*"]
set_args = [
  { path = "per_page", default = 30 },
  { path = "per_page", clamp = { min = 1, max = 100 } },
]

[[policy]]
name     = "no-tokens-upstream"
effect   = "transform"
set_args = [{ path = "auth.token", remove = true }]
```

#### Edits of a result

`result` lists a transform rule's edits of what the upstream answers: a tool
call's result, matched by the call's arguments as the upstream got them, or a
read's contents. Every transform rule with `result` that matches applies, in
config order, each to what the rules before it left. Only a final result is
edited: an interim one (an `InputRequiredResult`) carries what the server needs
back, untouched. Each entry is a table with **exactly one** operation:

| Operation | Type | What it does |
|---|---|---|
| `redact` | `"secrets"` | Each secret that the inspect pack's secret rules, and `[gateway.inspect] secret_substrings`, find in a string of the result becomes `[REDACTED:<rule>]`, such as `[REDACTED:aws-access-key]`, whatever inspect's `mode`. Only secrets: an injection is inspect's to judge. The base64 of an image, an audio clip or a blob is passed over. A key is not redacted: a secret in an object's key cannot apply. |
| `mask` | path | The string at the path becomes `[REDACTED:<the rule's name>]`. A path that holds nothing is left so; one that holds anything but a string cannot apply: masked, it would change its type, and left, it would show. |
| `remove` | path | Takes the key at the path out. Its last step names a key, not `*`. |
| `truncate` | bytes, 1 or more | Each text block keeps that many bytes of its text, cut at a character boundary, and a line saying how long it was: `[MCPdef cut this text from 70000 bytes to 65536]`. |

**Where a path points.** A `mask` or `remove` path is keys joined by dots, `*`
standing for every element of an array or every value of an object
(`items.*.token`), into the JSON the result carries: a tool result's
`structuredContent`, and each text block, or text content of a read, that holds
a JSON object or array. Such a block is read, edited, and written back, on one
line or spread over several as it was.

**JSON values, never serialized text.** Every edit is made to JSON values, so
the result stays valid JSON, and so does each text block that held JSON,
unless `truncate` cuts it. A replacement holds no quote and no backslash.

**The mirror.** A text block that holds a tool result's `structuredContent` as
JSON, as the spec says a tool SHOULD send beside it, is not edited itself: when
the structure changes, the block is written again from it, so the two agree.
`truncate` passes it over.

**The `outputSchema`.** An edit of a `structuredContent` is checked against the
`outputSchema` the tool's listing gave, which its pin keeps. One the schema may
not allow cannot apply:
- a changed string the schema constrains beyond its type: an `enum`, a `const`,
  a `pattern`, a `format`, a content encoding, or a length the new value breaks;
- a removed key the schema requires, or one that leaves fewer keys than
  `minProperties`;
- a place the schema describes in a way MCPdef does not follow: `allOf`, `not`,
  `if`/`then`/`else`, `patternProperties`, a reference outside the schema, or a
  union with more than one branch that could hold the step. A union with one
  object branch beside `null`, as `Optional[Model]` writes it, is followed.

**An edit of a result that cannot apply** denies the call under the rule's
name, as one of the arguments does. The upstream did answer: the call ran, and
its result is withheld. The reason names a path, never a value: a key the
result holds and the rule's path did not name, one a `*` reached or a
redaction found, is shown as `*`, unless the tool's `outputSchema` names it.

```text
MCPdef denied: transform rule 'hide-state' could not apply to the result of 'report' on 'github': changing `structuredContent.state` would break the tool's outputSchema
```

With `on_error = "skip"`, the rule keeps none of its edits of the result, the
log names it and why, and the rules after it run.

```toml
[[policy]]
name   = "no-secrets-out"
effect = "transform"
result = [{ redact = "secrets" }, { truncate = 65536 }]

[[policy]]
name   = "pii"
effect = "transform"
tools  = ["get_user"]
result = [{ mask = "user.email" }, { remove = "user.ssn" }]

[[policy]]
name   = "config-files"
effect = "transform"
uris   = ["file:///etc/app/**"]
result = [{ mask = "database.password" }]
```

The separate top-level `policy` key under `[gateway]` is reserved and unused
(see above).

## `[profile.<name>]`

Struct: `ProfileConfig`. A named, reusable allow/deny set — referenced by a
server (`profile = "<name>"`) or applied gateway-wide (`[gateway] profile`).

| Key | Type | What it does |
|---|---|---|
| `tools` | array of globs | Allowlist (deny-by-default). Unset = allow all, subject to `deny`. |
| `deny` | array of globs | Denies; deny wins over allow. |

Resolution when a server references a profile: inline `tools` **replaces** the
profile's allowlist; inline `deny` is **appended** (denies accumulate).

A profile that lists fewer tools also costs every agent less context, since each
reads the whole `tools/list` answer. `mcpdef tools list --cost --profile <name>`
shows how much less, per server.

## `[[server]]` — the governed upstreams

Struct: `ServerConfig`. At least one is required.

| Key | Applies to | Type | Default | What it does |
|---|---|---|---|---|
| `id` | all | string (unique, non-empty) | — | The server's name in policy, audit records, and `servers list`. |
| `transport` | all | `"stdio"` \| `"streamable-http"` \| `"sse"` \| `"wasm"` \| `"wasm-component"` | — | How MCPdef reaches the upstream (`SUPPORTED_TRANSPORTS`). `streamable-http` auto-falls back to the legacy SSE bridge on a 400/404/405; `sse` forces it. MCPdef restarts an upstream that goes down; an HTTP one (`streamable-http`, `sse`) also counts as down after 5 calls in a row fail or time out. See [OPERATIONS.md § Upstream supervision](./OPERATIONS.md#upstream-supervision). |
| `spec` | all | `2025-11-25` \| `2026-07-28` \| `auto` | `2025-11-25` | Which MCP revision this server speaks. `2026-07-28` has no `initialize`, so MCPdef opens it with `server/discover` and puts the version, its identity and its capabilities on every request. `auto` asks the server for `initialize` and uses what the answer proves — on any transport, since that probe *is* the opening request rather than an extra one. Otherwise a fact about the server, not a preference — set it wrong and startup fails naming this knob. See [WIRE.md](./WIRE.md). |
| `command` | stdio | argv array | — (required) | The child process to spawn. |
| `env` | stdio | table of name → [secret](#secrets) | `{}` | Env vars injected into the child — the token-broker path: MCPdef holds the upstream's credential and the client's bearer is never passed through. A string is the value itself; `{ file = … }`, `{ env = … }` and `{ exec = […] }` are read each time the server starts, a restart included, so a rotated secret is picked up. A reload starts the server again when a file a value is read from changes. A name must not be empty or hold `=`. |
| `url` | streamable-http, sse | string (URL) | — (required) | The upstream endpoint. Goes through the egress/SSRF guard. |
| `tls` | streamable-http, sse (`https://`) | table | unset | This upstream's TLS profile, over `[gateway.upstream_tls]`: see [TLS towards upstreams](#gatewayupstream_tls-and-servertls--tls-towards-upstreams). |
| `auth` | streamable-http, sse | table | unset | How MCPdef proves itself to this upstream: see [`[server.auth]`](#serverauth--credentials-towards-an-http-upstream). |
| `tools` | all | array of globs | unset = all (subject to `deny`) | Allowlist: only these tools are exposed/callable (deny-by-default once set). A name another server offers too is listed and called from the first in config order: see [Tool names](#tool-names). |
| `deny` | all | array of globs | `[]` | Glob denies (e.g. `delete_*`); deny wins over allow. |
| `profile` | all | string | unset | Inherit allow/deny from `[profile.<name>]` (see resolution rule above). |
| `prefix` | all | string | the server's `id` | With `[gateway] tool_namespace = "prefix"`, what its tools' listed names start with, before `__`: letters, digits, `_`, `-` and `.`. Unused, and warned about, while `tool_namespace` is off. See [Tool names](#tool-names). |
| `max_inflight` | all | int ≥ 1 | `16`; `1` for `wasm` and `wasm-component` | The most calls that may wait on this upstream at once. A call over the cap waits for a slot, and the wait counts against `upstream_timeout_ms`; nothing is refused. (`[gateway] max_inflight` is different: it sheds excess HTTP requests with a `503`.) On a Streamable-HTTP upstream this many calls POST at once. On stdio and the SSE bridge they share the one connection: each goes out under its own request id, and each reply is routed back to its call, in whatever order replies arrive. A wasm module runs one call at a time whatever this says. |
| `resources` | all | array of [URI patterns](#resource-uri-patterns) | unset = none | Resource allowlist: the URIs a `resources/read` may name, and the resources `resources/list` shows. Unset or empty exposes none of this server's resources. |
| `resource_templates` | all | array of globs | unset = none | The URI templates `resources/templates/list` shows, matched against each template as the server writes it (`file:///{path}`). Showing one allows no read: a URI filled in from it is read only if `resources` allows it. A `completion/complete` for a template goes to the server that listed it, else the first whose `resource_templates` shows it. |
| `prompts` | all | array of globs | unset = none | Prompt allowlist: the prompts `prompts/list` shows and `prompts/get` may name. Unset or empty exposes none of this server's prompts, since a prompt is text the server writes into the model's context. A prompt two servers show is listed once, from the first in config order, and got from there; a `completion/complete` for a prompt goes where a get of it would. Two servers whose patterns overlap are warned about, and refused under [strict mode](#strict-mode). |
| `wasm` | wasm, wasm-component | path | — (required) | The `.wasm` core module / `wasm32-wasip2` component to run in-path under Wasmtime. |
| `wasm_fuel` | wasm, wasm-component | int | `200_000_000` (`SandboxLimits::default`, `mcpdef-sandbox`) | Fuel per call (≈ one unit per instruction); exceeding it traps `out of fuel`. |
| `wasm_max_memory_mb` | wasm, wasm-component | int (MiB) | `64` | Linear-memory ceiling for the module. |
| `wasm_deadline_ms` | wasm, wasm-component | int (ms) | unset / `0` = no bound | Per-call **wall-clock** deadline via epoch interruption (20 ms tick granularity), on top of the fuel (CPU) bound. |
| `wasm_allow_egress` | wasm-component | array of `"ip:port"` | `[]` = **deny all** | Outbound TCP allowlist for the sandboxed component. A connect is permitted only if listed **and** the IP passes the egress classification (metadata/special-use always blocked). Hostnames are not accepted. |

### `[server.auth]` — credentials towards an HTTP upstream

Struct: `ServerAuth`. A header MCPdef adds to every request it sends to a
`streamable-http` or `sse` upstream: each POST, and the legacy bridge's stream.
A client's own credentials are never passed through. Each secret is a
[secret reference](#secrets).

| `kind` | Also takes | Sends |
|---|---|---|
| `"bearer"` | `token` | `Authorization: Bearer <token>` |
| `"header"` | `name`, `value` | `<name>: <value>`, for an upstream that wants a header of its own, such as `X-Api-Key` |
| `"basic"` | `username` (a string), `password` | `Authorization: Basic <base64 of username:password>` |
| `"oauth2"` | `token_url`, `client_id`, `client_secret`; `client_auth`, `scopes`, `resource` | `Authorization: Bearer <token>`, a token MCPdef fetches by the client credentials grant: see [below](#kind--oauth2-a-token-by-the-client-credentials-grant) |

For `bearer`, `header` and `basic`, the same secret goes on every request:

```toml
[[server]]
id = "remote"
transport = "streamable-http"
url = "https://mcp.example.com/mcp"

[server.auth]
kind = "bearer"
token = { file = "/run/secrets/remote-token" }
```

- **The secret is read when the upstream is opened**, at startup and at each
  restart or reconnect, and held for its requests. One that cannot be read
  leaves the upstream down, with an error that names the setting and where it
  comes from.
- **A `401` has it read again, once.** If what it reads now differs from what
  the refused request carried, the request goes once more with it; many
  requests refused at once read it once between them. A `401` to that, or
  nothing new to send, fails the call closed: a tool error audited as
  `upstream-auth-failed`. So a token rotated in its file is picked up at the
  first request the upstream refuses, without a restart. A reload does not
  watch the file. If the secret cannot be read then, the call fails closed as
  `credentials-unavailable`.
- **Checked by `mcpdef validate`:** a field the kind needs and lacks, one it
  does not take, a `username` with a `:`, a header's `name` that HTTP, MCP's
  transport or a proxy sets (`Host`, `Accept`, `Content-*`, `Mcp-*`,
  `Proxy-*`, `Connection`, `Transfer-Encoding`, `Last-Event-ID` and the like),
  and `[server.auth]` on a server that is not an HTTP one.
- **Warned about:** a secret written in the config, and credentials sent over
  plain `http://` to a host other than this machine, where anyone on the path
  can read them.
- **Never shown:** the value goes out marked sensitive, so the HTTP library's
  debug output does not print it and HTTP/2 does not index it. `servers list`
  and `/api/v1/servers` show the kind and where the secret comes from.
- **Its health is shown:** `/api/v1/servers` gives the server a `credential`:
  when the upstream last took the credentials (`last_ok`), the last time it
  refused them or there were none to send, and why (`last_error`), and for
  `oauth2` when the token it is sent now expires (`expires_at`). `/metrics`
  counts the failures in `mcpdef_upstream_auth_failures_total`. See
  [API.md](./API.md#admin-listener-gatewayadmin).

#### `kind = "oauth2"`: a token by the client credentials grant

MCPdef asks an authorization server's token endpoint for an access token
(RFC 6749 §4.4), as a client of its own, and sends it as a bearer.

```toml
[server.auth]
kind = "oauth2"
token_url = "https://idp.internal/oauth2/token"
client_id = "mcpdef-github"
client_secret = { file = "/run/secrets/github-client-secret" }
scopes = ["mcp:tools"]
# resource = "https://github-mcp.internal/mcp"   # default: this server's url
# client_auth = "client_secret_post"             # default: client_secret_basic
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `token_url` | string (URL) | — (required) | The token endpoint: `https://`, or `http://` to a host the egress guard allows plain HTTP to. No user name, password or fragment. |
| `client_id` | string | — (required) | MCPdef's client id there. |
| `client_secret` | [secret](#secrets) | — (required) | Its secret there, read at each fetch, so a rotated one is used from the next. |
| `client_auth` | `"client_secret_basic"` \| `"client_secret_post"` | `"client_secret_basic"` | How the id and the secret go: HTTP Basic, each form-encoded first as RFC 6749 §2.3.1 has it, or in the request's body. |
| `scopes` | array of strings | `[]` | Sent space-separated as `scope`, and not at all when empty. |
| `resource` | string (absolute URI) | the server's `url`, less any user info, query and fragment | RFC 8707's `resource`: the upstream the token is for, which MCP's authorization spec has a client send. The credentials a `url` holds are never sent to the token endpoint. `""` sends none, for a server that refuses the parameter. |

- **Fetched when the first request needs one**, the opening's, and sent on
  every request until 30 s before it expires, as the answer's `expires_in`
  says, or for the first half of a life shorter than a minute. A token whose
  answer says nothing of when it expires is sent until the upstream refuses
  it.
- **One fetch at a time.** Requests that need a token while one is being
  fetched wait for it, and take what it gave: 50 calls at once fetch one
  token.
- **A `401` fetches a fresh one**, and the request goes once more with it;
  requests refused at once fetch one between them. A `401` to that, or the
  same token handed back, fails the call closed as `upstream-auth-failed`.
- **The token endpoint is reached as the gateway's other fetches are**, a
  `jwks_uri`'s: through the egress guard (`[gateway.egress]`), verified with
  `[gateway.upstream_tls]` and not the server's `[server.tls]`, its files read
  at each fetch, with no redirect followed and 10 s for the whole of it. A
  reload that changes `[gateway.upstream_tls]` or `[gateway.egress]`
  reconnects the servers that fetch tokens.
- **No token, no request.** When the token endpoint cannot be reached, answers
  with an error, or gives no bearer token, nothing is sent upstream: the call
  fails closed as a tool error, audited as `credentials-unavailable`. It names
  the endpoint, its status and its `error` code (`invalid_client`,
  `invalid_scope`, `unauthorized_client`, `invalid_target`, …), never its
  `error_description`, which a server may fill with anything. The next call
  fetches again. An upstream whose opening gets no token stays down, and
  MCPdef restarts it with the backoff.
- **Checked by `mcpdef validate`:** a missing `token_url`, `client_id` or
  `client_secret`; a `token_url` that is not an `http(s)://` URL, or holds a
  user name, a password or a fragment; an empty `client_id`; an unknown
  `client_auth`; a scope with a space, `"` or `\`; a `resource` that is not an
  absolute URI, or has a fragment.
- **Warned about:** a client secret written in the config, and a `token_url`
  over plain `http://` to a host other than this machine, where anyone on the
  path can read the secret.
- **Never shown:** the secret and the tokens go out marked sensitive, and the
  buffers MCPdef builds them in are wiped. `servers list` and
  `/api/v1/servers` show the token endpoint and where the secret comes from.

## CLI flags

Clap derive: `Cli`/`Cmd` in [`crates/mcpdef/src/main.rs`](../crates/mcpdef/src/main.rs).
Every subcommand that reads config takes `--config <file>` (default `mcpdef.toml`).

| Command | Flags beyond `--config` | What it does |
|---|---|---|
| `mcpdef run` | `--profile <name>`, `--http` | Run the gateway; serves the client over stdio, or over the Streamable HTTP listener with `--http`. `--profile` overrides `[gateway] profile` for this run. |
| `mcpdef up` | `--profile <name>` | Shorthand for `run --http`. |
| `mcpdef bridge <url>` | `--ca <pem>` (repeatable), `--cert <pem> --key <pem>` (together), `--token-file <file>`, `--spec auto\|2025-11-25\|2026-07-28` (default `auto`), `--audit <path>`, `--state-dir <dir>`, `--print-config` | Bridge a stdio client to a remote MCPdef, or to any Streamable-HTTP MCP endpoint, for a client that cannot use a private CA, a client certificate or a token itself: the client launches it as its stdio server. It is the gateway with that one upstream (`--print-config` prints the config it runs, which is a valid file for `run`), and governance passes through: every tool, resource, resource template and prompt the remote end offers is offered, and the remote end decides. The key and the token are read from their files when needed and never printed. The ledger and state default under `~/.mcpdef/bridge/`, never the working directory a client launched it from; with no `HOME`, give `--audit` and `--state-dir`. |
| `mcpdef connect <client>` | `--write`, `--file <path>`, `--url <url>`, `--name <name>` (default `mcpdef`), `--token-env <VAR>`, `--token-file <file>`, `--cert <pem> --key <pem>` (together) | Print the entry an MCP client needs to reach this gateway, in that client's own format: `claude-code` (`.mcp.json`, and the `claude mcp add` line for every project), `claude-desktop`, `cursor` (`~/.cursor/mcp.json`), `vscode` (`.vscode/mcp.json`, under `servers`), `codex` (`~/.codex/config.toml`) or `generic`. It carries the URL; a token by the variable that holds it, never its value; and how that client trusts the gateway's local CA. Claude Desktop, whose file runs only commands, and any client given `--cert`/`--key`, gets a `mcpdef bridge` entry instead. With `--write` it merges the entry into that file and keeps a `.bak` of what was there; run again, it writes nothing and the backup is kept. A file it cannot read as plain JSON, such as VS Code's with comments, is left as it is, and the entry is to be added by hand. JSON is written back with its keys in order; Codex's TOML keeps its comments and layout. |
| `mcpdef call <tool>` | `--args <json-object>` (default `{}`), `--json`, `--profile` | One-shot governed tool call: allowlist/profile/pin/rate-limit gates + audit apply; RBAC does not (no bearer on this trusted local path). Exits non-zero on a denial or tool error. |
| `mcpdef validate` | `--strict` | Validate the config, and the TLS files it names; exit non-zero listing every problem. Warnings (a secret written in the config, a secret file others can read, `insecure_skip_verify`, credentials in the clear) are printed and do not fail it, unless `--strict` or `[gateway] strict = true` makes each an error: see [Strict mode](#strict-mode). |
| `mcpdef doctor` | `--wait <secs>` (default `30`) | Check the gateway end to end and print what is wrong, or soon will be, each line marked ✓, ⚠ (works, but should not be left so) or ✗ (broken); exit non-zero if anything is broken. **config**: `validate`'s errors and warnings, a secret written in the config among them. **tls**: what `tls show` warns of, a certificate near its end among them. **sign-in**: for bearer tokens, whether the identity provider's keys can be had, fetched from `jwks_uri` as the gateway fetches them, and how far this machine's clock is from the provider's, read from its `Date`: further than the 60 s a token's `exp` and `nbf` are allowed, fresh tokens are refused as not valid yet, or every token expires early. **admin**: an admin listener other machines can reach, which asks no one who they are. **servers**: each upstream opened as `run` opens it, up or down and why, what it adds to `tools/list`, the resources and prompts it offers that no `resources` or `prompts` list exposes, a tool name two servers offer, and certificates near their end. It keeps nothing a running gateway keeps: no audit record, no pin, no state. An upstream may take `upstream_timeout_ms` to open, or `--wait` where that is unset. |
| `mcpdef servers list` | — | Static, config-level view of the governed servers and their *resolved* allow/deny (profiles applied), and under a server with `[server.env]`, where each variable's value comes from (`NAME=$VAR`, a path, `(exec PROGRAM)` or `(literal)`), never the value. Does not connect upstreams. |
| `mcpdef tools list` | `--profile <name>`, `--cost` | Open every upstream, as `run` does, and print each tool `tools/list` gives a client, with its server: what the allowlist, the profile, the pins and the scanner leave, by the name each is listed by. With `--cost`, print instead what each server adds to that list, which every agent that lists the tools reads into its context: how many of its tools are listed, of those it offers, the bytes they take up there, and bytes ÷ 4, an estimate of the tokens. See [OPERATIONS.md § What the tools cost each agent](./OPERATIONS.md#what-the-tools-cost-each-agent). `--profile` overrides `[gateway] profile`, as for `run`. A new tool is pinned on first use, as `run` pins it. |
| `mcpdef audit verify` | `--path <ledger>`, `--head <hash> --count <n>` (together) | Offline hash-chain check; with `--head`/`--count`, also checks against a seal recorded out-of-band (catches tail-truncation). Exit non-zero on a break. |
| `mcpdef audit tail` | `--path <ledger>`, `-n/--lines <n>` (default 20), `--format json\|ocsf\|cef\|syslog` | Print the last N records in a SIEM-ready format, one line per record. |
| `mcpdef egress show` | — | Print the effective SSRF/egress policy, and the TLS profile each HTTPS upstream is verified with: its `[server.tls]` over `[gateway.upstream_tls]`, and the gateway's own for a `jwks_uri`. It says how a certificate is checked (`ca`, `pin` or `disabled`), then the roots, CAs and CRLs that check it (or the pins), `min_version`, the client certificate and `connect_to`. A plain-HTTP or stdio upstream has no profile, and is not listed. |
| `mcpdef tls pin <url>` | `--connect-to <ip>`; `--config <file>`, optional, for its `[gateway.egress]` | Connect through the egress guard and print the SPKI pin of the certificate the server presents, as a `pin_sha256` line. The other lines (the address, the certificate's names, its SHA-256 fingerprint) are TOML comments, so the output pastes into `[server.tls]` as it is. The connection is not verified: check the fingerprint against the server's own before trusting the pin. A server that asks for a client certificate still gives its pin. |
| `mcpdef tls init` | `--new-ca` | Make the local CA and the certificate it issues the listeners, as [`mode = "self-signed"`](#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners) serves them, and print how each client trusts the CA: `NODE_EXTRA_CA_CERTS` (Claude Code), `CODEX_CA_CERTIFICATE` (Codex), `curl --cacert`, and the command that adds it to the system's store (VS Code, Cursor and the rest). A CA already there is kept, and so is a certificate that still does. `--new-ca` makes a new CA in its place, for a name the old one does not vouch for: every client has to trust it instead. Once the CA has issued client certificates (`tls issue`), it also writes the new CA's CRL, and from the next reload those the old CA issued are refused. Refused with `mode = "files"`. |
| `mcpdef tls show` | — | Print each listener's TLS: its mode, and its certificate's path, subject, names, issuer, expiry and SHA-256 fingerprint; the local CA's; each HTTPS upstream's profile, as `egress show` prints it; and warnings: a certificate that expired or soon will (from files, within 14 days; self-signed, past its renewal), a key others can read, `insecure_skip_verify`, a listener open with neither TLS nor auth. It reads certificates, never keys. |
| `mcpdef tls export-ca` | `--out <file>` | Print the local CA's certificate, or write it to `--out`, for a client to trust. Its key is not read. |
| `mcpdef tls issue` | `--client <name>`, `--spiffe-id <id>`, `--days <n>` (default `30`), `--out <dir>` (default `.`) | Issue a workload a client certificate from the local CA, for mTLS with no PKI of one's own: `<name>` as its subject's common name, which `identity = "subject-cn"` reads, and `--spiffe-id` in a URI name, which `identity = "spiffe"` reads; no DNS name, which the local CA keeps for the listeners. Writes `<name>.crt` and `<name>.key` in `--out`, the key `0600`, and never over a file there; prints its serial, and the `[gateway.tls.client_auth]` that takes it unless the config already does. It is checked, and its names read, as the gateway would before it is written. Makes the local CA if there is none, and writes its CRL, `<state_dir>/tls/ca.crl`, so that `crl` can name it from the start. |
| `mcpdef tls revoke <serial \| file>` | — | Revoke a certificate the local CA issued, by the serial `tls issue` printed (as `openssl x509 -noout -serial` prints it too) or by its file: it goes in `<state_dir>/tls/ca.crl`, written from `revoked.json` beside it. A gateway whose `crl` names it refuses the certificate from its next reload, on connections already open as well. Revoking it again changes nothing. |
| `mcpdef pin` | — | Pin the current tool definitions of all upstreams as approved (writes `[gateway] pins`; overwrites — this is the re-approval command). A running gateway reads it at its next reload (`kill -HUP`). |
| `mcpdef diff-tools` | — | Diff current tool definitions against the pin store (read-only); exit non-zero if any pinned tool changed (rug-pull). |
| `mcpdef version` | — | Print the version and the MCP revisions this build speaks. |

## Data formats & compatibility

There is no `format_version` field in any of these files yet (pre-1.0); the
shapes below are what `mcpdef 0.1.0` reads and writes.

- **Audit ledger** (`[gateway] audit`): JSON Lines, one `Record` per line
  (`mcpdef-audit::Record`): `seq`, `ts_unix_ms`, `agent`, `server`, `method?`,
  `tool?`, `decision` (`"allow"`/`"deny"`), `rule?`, `latency_ms`, `prev_hash`,
  `hash`. A `rule` on an allowed record says why it stands out:
  `input-required` for a request the server answered with an interim result
  ([WIRE.md](./WIRE.md#status)), `tls-verify-disabled` for a connection opened
  without checking the upstream's certificate. Later members are optional and
  absent from a plain governed call:
  - `kind?`: `admin`, `reload` or `upstream`; absent means a call;
  - `uri?`: the resource URI a request named;
  - `transforms?`: the transform rules that fired, by name;
  - `actor?`: a second identity besides `agent`, such as the console user behind
    an admin action, or a client certificate's identity (`cert:…`) behind a
    token's subject;
  - `peer?`: the network address the request came from, on the HTTP listener;
  - `config_from?` and `config_to?`: on a reload record, the digest
    (`sha256:<hex>`) of the configuration that ran before and of the one read;
  - `tool_changes?`: on an upstream's `tools-changed` record, how its tools
    changed, as `{ "added", "removed", "changed", "drifted" }`, each a count.
    A line whose `tool_changes` lacks one of the four, or holds another member,
    is corrupt.

  `hash = SHA-256` of the v1 encoding: `seq`, `ts_unix_ms`, `agent`, `server`,
  `method`, `tool`, `decision`, `rule`, `latency_ms` and `prev_hash`, joined by
  U+001F, with an absent field as the empty string. If the record has any later
  member, the encoding continues with U+001F and one JSON object holding all of
  them: compact, members sorted by name at every level, `null` members left out.
  For strings, integers, booleans, arrays and objects with ASCII names, that is
  the RFC 8785 (JCS) form. The rule covers members a future release adds, so a
  newer ledger still verifies with this release. The first record chains to 64
  hex zeros (`GENESIS`). Append-only; re-opening resumes the chain from the
  current head. The hash covers the fields, not the JSON text, so member order in
  a line does not matter. A member named twice in a line makes it corrupt.
  A U+001F inside a v1 field is stored as `␟` (U+241F); `mcpdef audit verify`
  warns about any record from an older gateway that still holds one.
  A ledger written by 0.2.1 verifies unchanged.
- **Pin store** (`[gateway] pins`): TOML, `[<server-id>]` tables mapping
  `tool = "<hex sha-256>"` (`mcpdef-pin::PinStore`, serde-transparent
  `BTreeMap<String, BTreeMap<String, String>>`). Sorted deterministically so it
  diffs cleanly in version control; written atomically (temp file + rename).
  The hash covers the tool's governed fields only: `name`, `description`,
  `inputSchema`, `outputSchema`, `annotations`, canonicalized with recursively
  sorted keys.
- **JWKS** (`[gateway.auth] jwks`): a standard JWKS JSON document; keys must
  carry `kid` and be RSA or EC (RS256/384/512, PS256, ES256/384).
