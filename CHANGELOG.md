# Changelog

All notable changes to MCPdef are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because MCPdef tracks a **moving protocol**, every release explicitly records the
MCP spec revision(s) it supports (see [docs/WIRE.md](./docs/WIRE.md)).

## [Unreleased]

## [0.4.0] - 2026-10-14

The console release, and the first since 0.2.2 on crates.io, Homebrew and the
`:latest` image. There is no 0.3.0.

The admin listener serves the console: an overview, the audit log (paged,
filtered, verified, exported and tailed live), the servers and their tools,
policy, inspect's findings, the connections and their certificates, who the
gateway takes its callers to be, and each client's entry, in a dark theme or a
light one, both WCAG 2.1 AA. It signs people in at your identity provider over
OpenID Connect, a SAML provider through a broker such as Keycloak, with three
console roles, tokens for automation and a break-glass token; an operator
reloads the config, restarts and tests upstreams and approves pin drift from
it; and every action is in the ledger as the person who took it.

Since 0.4.0-alpha.1 the gateway also serves HTTPS and mTLS on its own
listeners, a client certificate naming an agent and mapping to roles, behind a
TLS-terminating proxy too; governs resources, prompts and completions as it
governs tools; rewrites arguments and results with `transform` rules; issues
client keys; and brings `mcpdef bridge`, `connect`, `doctor`, `tls issue` and
`sso init`. From 0.2.x it brings everything 0.4.0-alpha.1 did besides: calls
run concurrently, upstreams supervised, the config reloaded without a restart,
TLS towards upstreams, credentials sent to them, secrets from files,
variables or commands, strict mode, and the 2026-07-28 wire beside 2025-11-25.

### Upgrading
Upgrading from 0.2.x, read [0.4.0-alpha.1](#040-alpha1---2026-09-26)'s
"Upgrading from 0.2.x" first; these came after it.

- **A method MCPdef does not serve is refused.** A request the gateway did not
  answer itself used to go to the first server. Now it answers or routes
  `initialize`, `ping`, `server/discover`, `tools/*`, `resources/*`,
  `prompts/*` and `completion/complete`, and refuses anything else with
  `-32601` (HTTP `404` on the modern wire), audited under `method-not-found`.
  A client that relied on the first server answering, say, `logging/setLevel`
  now gets that refusal.
- **Each tool in `tools/list` carries `_meta["mcpdef/server"]`.** A client that
  hashes or compares the tool definitions it lists sees each one change once,
  by that key; nothing else in a tool changes.
- **A tool name more than one server offers is listed once.** `tools/list`
  listed every server's copy. Now a name is listed once, from the first server
  in config order whose allowlist takes it, and a call goes there. The
  collision is a warning at `validate` and at startup, and is shown on the
  admin servers view. Under `strict` it is an error, so a strict gateway whose
  servers offer one name no longer starts: take the name off one server's
  allowlist, or set `[gateway] tool_namespace = "prefix"`.
- **A server exposes resources only through `[[server]] resources`.** Every
  `resources/*` request used to go to the first server, whatever its config
  said. Now a server with no `resources` list exposes none of its resources,
  and a read goes to the server that has the URI. List what each server may
  expose, as URI patterns: `resources = ["file:///srv/docs/**"]`.
  `mcpdef doctor` names each server that offers resources no list exposes.
- **A server exposes prompts only through `[[server]] prompts`.** Every
  `prompts/*` request used to go to the first server, whatever its config
  said. Now a server with no `prompts` list exposes none of its prompts, and a
  get goes to the server that has the prompt. List what each server may
  expose, by name: `prompts = ["summarize_*"]`. `mcpdef doctor` names each
  server that offers prompts no list exposes.
- **With `[[role]]` defined, an authenticated read or prompt get needs a
  grant.** A caller with a token reads a resource only if a role it holds
  lists it in `resource_grants`, as `"server-glob:uri-pattern"`, and gets a
  prompt only if one lists it in `prompt_grants`, the way `grants` lists
  tools.
- **A `[[policy]]` rule that names none of `tools`, `uris` and `prompts` judges
  reads and prompt gets too**, as an `agents`-only deny now does. Give it
  `tools = ["*"]` to keep it to tool calls.
- **A stdio client is sent `notifications/tools/list_changed`.** Its
  `initialize` is answered with `tools.listChanged: true`. Once it sends
  `notifications/initialized`, it is told each time what `tools/list` shows
  changes.
- **A listener other machines reach, with neither TLS nor auth, is warned
  about.** `[gateway] listen` on an address other than a loopback one or
  `localhost`, with `[gateway.tls]` and `[gateway.auth]` both off, is a
  warning at startup, at each reload and in `mcpdef validate`, so under
  `strict` such a gateway no longer starts. Set `[gateway.tls]` and
  `[gateway.auth]`, or listen on `127.0.0.1` behind a proxy that does both.
- **Each record of a request over HTTP names the client's address**, as
  `peer`: `"203.0.113.7:51234"`. A ledger reader, and an export to OCSF, CEF
  or syslog, sees the member it already knew of set.
- **A tool whose `x-mcp-header` annotations break the 2026-07-28 rules is not
  served.** It was listed and called like any other. Now it is hidden from
  `tools/list` and a call to it is refused, audited under `x-mcp-header`, and
  the log says why when its server lists it. Its server's other tools are
  served as before. Fixing the annotation upstream, and a re-list or restart,
  serves it again.
- **A modern request's `Mcp-Param-*` headers must agree with its body.** The
  listener ignored them. Now a 2026-07-28 `tools/call` whose headers disagree
  with the arguments its tool annotates is refused with `400` and `-32020`.
  A 2025-11-25 request, and a header no annotation names, are not checked.
- **An admin listener that cannot bind stops the start.** It used to be
  logged while the gateway ran on without it, its metrics and API out of
  reach.
- **An admin listener other machines reach needs a sign-in.** One bound off
  loopback with nothing to sign its callers in is refused by `mcpdef
  validate`, and so at the start. Require client certificates of it, or set
  `[gateway.admin] allow_unauthenticated = true` when a proxy in front
  authenticates its callers (or the port is published to loopback alone, as
  the Compose example's is).
- **A client certificate the admin listener requires needs a console role.**
  `[[identity.cert_map]]` gives it: `roles = ["console:viewer"]` to read,
  `console:operator` to act, `console:admin` for the config and identity
  views. A certificate that maps to none is refused `403`; it used to read
  everything.
- **The admin listener answers only to its own names.** A request whose Host
  is not an IP literal, `localhost`, the listener's or `public_url`'s host, or
  one of `[gateway.admin] hosts`, is refused `421`. Add the name a scraper
  uses, a Kubernetes Service's say, to `hosts`.
- **The admin listener's refusals are problem documents**, RFC 9457
  `application/problem+json`, where they were plain text.

### Security
- **The admin listener checks where a request comes from.** A page another
  site serves could reach a loopback admin listener by rebinding its own
  name to `127.0.0.1`, and read what it shows; and a request that changes
  something (the console's actions, to come) could be posted from any page.
  Now the Host must be the listener's, a browser's change must come from its
  own origin and send JSON, and every answer carries a content security
  policy and keeps out of frames and caches.
- **A bearer token with no `aud` claim was accepted.** `[gateway.auth]` checked
  a token's audience only when the token named one, so a token the issuer
  signed for no audience, minted for some other use, opened the gateway. A
  token now needs `aud`, `iss`, `sub` and `exp`, and its `aud` must hold
  `resource`, as RFC 9068 asks. 0.2.2 has the same flaw.
- **A resource request reached the first server ungoverned.** `resources/list`
  and `resources/read` went to the first configured server with no allowlist,
  and were audited as allowed with no URI. A client could read any resource of
  that server, and none of any other. Now:
  - each server's `resources` is an allowlist of URI patterns;
  - a read is judged on the URI in normal form, with dot segments resolved, and
    the server is sent that form, so `file:///srv/docs/%2e%2e/secret` is judged
    and read as `file:///srv/secret`;
  - a URI two readers could take two ways is refused: one with an encoded `/`
    or `\`, a backslash, a NUL, an empty segment inside the path, or an escape
    of an escape;
  - the `[[policy]]` rules, RBAC and the rate limit judge a read as they judge
    a tool call, in the same order, and what it returns is scanned for
    injected instructions and secrets;
  - every read is audited with its URI, allowed or denied.
- **A prompt request reached the first server ungoverned.** `prompts/list` and
  `prompts/get` went to the first configured server with no allowlist, were
  audited as allowed with no name, and what a prompt said was not scanned,
  though it is text a server writes into the model's context. Now each
  server's `prompts` is an allowlist; the `[[policy]]` rules, RBAC and the
  rate limit judge a get as they judge a tool call; what it returns is scanned
  for injected instructions and secrets; and every get is audited with the
  prompt's name.
- **Any other request reached the first server ungoverned.** A method the
  gateway did not know, such as `completion/complete`, `logging/setLevel` or
  `tasks/get`, went to the first configured server with no allowlist, and was
  audited as allowed with no name. `completion/complete` could so draw
  suggestions for any prompt or template of that server, which can disclose
  what it holds. Now every other method is refused and sent nowhere, and a
  completion is routed and judged as a request for what it completes.
- **TLS runs on rustls 0.23.46.** It was on 0.23.45, which four advisories
  published on 2026-10-14 cover:
  - RUSTSEC-2026-0346: the `Debug` output of a client's session values showed
    TLS secrets;
  - RUSTSEC-2026-0347: application data buffered before an ECH rejection was
    sent to the outer server;
  - RUSTSEC-2026-0348: brotli certificate decompression could allocate up to
    1 GiB before authentication;
  - RUSTSEC-2026-0349: an unauthenticated ServerHello could downgrade later
    connections to classical key exchange.

  It is a patch release, so neither the API nor the MSRV changes.
- **The WASM sandbox runs on Wasmtime 36.0.17.** It was on 36.0.16, which
  three `wasmtime-wasi` advisories cover:
  - RUSTSEC-2026-0321: WASI preview 0's `poll_oneoff` let a guest run past
    its fuel;
  - RUSTSEC-2026-0322: a guest with no stdio could make the host allocate
    excessive memory;
  - RUSTSEC-2026-0323: `fd_readdir` copied uninitialized struct padding into
    guest memory.

  The whole Wasmtime family moves to 36.0.17 together, on the 36 LTS line, so
  neither the API nor the MSRV changes.
- **The WASM sandbox runs on Wasmtime 36.0.16.** It was on `wasmtime` 36.0.15
  and `wasmtime-wasi` 36.0.13, which two advisories cover:
  - RUSTSEC-2026-0314: a guest could panic the host through a filesystem
    datetime overflow;
  - RUSTSEC-2026-0316: lifting a dynamic record could allocate past the
    hostcall fuel limit.

  The update stays on the 36 LTS line, so neither the API nor the MSRV
  changes.

### Added
- **SAML, through a broker.** A SAML identity provider signs people in to
  the console through a broker that checks its assertions and speaks OpenID
  Connect to MCPdef, which parses no SAML itself. `deploy/compose/sso-saml`
  runs it on one machine: Keycloak with a realm standing in for the SAML
  identity provider and a realm brokering it, and MCPdef signing in to that
  by the config `mcpdef sso init --provider saml-broker` writes.
  `docs/SAML.md` says why, and how ADFS, Entra ID, Okta or Shibboleth takes
  the stand-in's place.
- **Signing in at Keycloak, tested.** A test signs people in through
  Keycloak's own pages to `mcpdef run`, with the config `mcpdef sso init
  --provider keycloak` writes, then through the SAML broker with the
  `saml-broker` one: an admin, an operator whose reload is recorded as
  theirs, a viewer who may not reload, someone given no role, a request from
  another origin refused, a session's cookie that opens nothing once its
  owner signed out, signing out of every realm, and a SAML response altered
  on its way to the broker refused there. It runs where
  `MCPDEF_KEYCLOAK_URL` names a Keycloak with the kit's realms, as CI's
  `keycloak` job does; elsewhere it checks nothing, and says so.
- **The Helm chart's ServiceMonitor says how Prometheus authenticates.**
  Where the admin listener signs its callers in, `/metrics` answers only one
  it has signed in: `serviceMonitor.endpoint` is added to the endpoint as it
  is, for Prometheus's `oauth2` (a token the identity provider issues for the
  admin API) or a client certificate. `docs/SSO.md` signs people in to the
  console provider by provider; `docs/DEPLOY.md` puts the console behind
  single sign-on on Kubernetes.
- **The console's screens, live.** The audit log pages the ledger at the
  gateway, filtered, with each record's detail, the chain verified, an
  export in four formats and a live tail; servers show their tools and why
  each is hidden, their resources, prompts and connection; policy shows the
  transform pass apart; inspect shows how it is set and what it found. An
  operator restarts, tests and approves an upstream's drift, and reloads the
  config, each confirmed. Where the console signs people in, it sends them
  to sign in and back to the screen they were on, and signs them out. Three
  more screens: Connections (the listeners' TLS and client certificates, the
  local CA to download, each HTTPS upstream's certificate, the credentials
  sent upstream, and every expiry among them, soonest first), Identity (who
  you are; for an admin, how the console signs people in and whether its
  identity provider was found, the role map, certificates and client keys)
  and Connect (each client's entry, as `mcpdef connect` writes it, and a
  request to try from the client's machine). A light theme beside the dark
  one, as the system prefers or as the viewer chooses; both meet WCAG 2.1
  AA, checked in Chromium with axe-core on every screen, with keyboard
  focus shown, tables and dialogs that assistive technology reads as such,
  and allow and deny told by icon and word, not colour alone.
- **Client keys the gateway issues.** `mcpdef keys create --name <n> --role
  <r>` prints a key once, and the `[[key]]` that keeps its SHA-256 and roles.
  Where `[gateway.auth] methods` names `key`, a client sending it as its
  bearer token is `key:<n>`, its roles judged by RBAC; a reload takes keys
  added and removed, so removing one and reloading revokes it. `mcpdef auth
  test` says whom a key names.
- **`mcpdef sso init --provider <name>`.** For Keycloak, Entra ID, Okta,
  Google, authentik, any OpenID Connect provider, and a SAML provider behind
  a broker: what to set at the provider (the redirect URIs, the scopes, the
  claim that carries roles or groups) and the config that reads its tokens,
  printed as TOML, or merged into the config file with `--write`, which
  keeps everything else in it and a `.bak`, and refuses rather than change
  the claims the MCP listener reads its callers' tokens by.
- **`[gateway.auth] discovery` and `audiences`.** `discovery = true` finds the
  token keys' `jwks_uri` from the issuer's metadata, OpenID Connect's
  document or else RFC 8414's, which must name the issuer exactly; `mcpdef
  doctor` shows what it finds. `audiences` takes tokens for an API the
  identity provider names its own way, as Entra ID's `api://<app id>`,
  besides `resource`. The console's sign-in reads RFC 8414's metadata too.
- **Tokens for automation on the admin API, and break-glass.** With
  `[gateway.admin.oidc] api_audience`, the admin API takes the identity
  provider's access tokens for that audience: `mcpdef:admin:read` reads,
  `mcpdef:admin:write` reloads, restarts, tests and approves drift, and a
  role `[identity]` reads counts too. A token for the MCP listener opens
  nothing there, nor one for the admin API on the MCP listener.
  `mcpdef admin token` makes a break-glass token, for when no one can sign
  in: `[gateway.admin.break_glass] token_sha256` keeps its digest, never the
  token; it holds `console:admin`, and every request it makes is recorded
  before it is served.
- **Signing in to the console.** `[gateway.admin.oidc]` names an OpenID
  Connect provider (Keycloak, Entra ID, Okta, Google, Authentik, or a broker
  in front of a SAML one) and the client registered with it: `/login` sends
  people there with PKCE, a state and a nonce, and `/callback` checks the
  answer, its RFC 9207 `iss`, and the ID token's signature, issuer, audience,
  authorized party, nonce and times, before `[identity]` reads their subject
  and roles from its claims, and userinfo's when `userinfo` is set. Someone
  with a console role gets a session, sealed with AES-256-GCM into a
  `__Host-` cookie, that ends after 8 hours, or 30 minutes unused; someone
  with none is shown the claims MCPdef received, to ask for one. `POST
  /logout` signs them out, and on to the provider's `end_session_endpoint`.
  Signing in, its refusals (twenty a minute, then one record saying the
  rest are not), and signing out are recorded. The key is
  `[gateway.admin.session] key`, or one the gateway makes in `state_dir`;
  `previous_key` rotates it without signing anyone out. Where the console
  signs people in, an API route refuses one who has not with `401`, saying
  where to; `GET /api/v1/session` says `sign_in`, or `sign_out` and `name`.
- **`[identity]`: which claims name a token's caller.** `subject_claim` names
  the claim that is its subject (the audit identity), `roles_claims` the
  claims that hold its roles, as dotted paths (`realm_access.roles`), and
  `[[identity.role_map]]` gives roles for a claim's value, such as an Okta
  group or a Google hosted domain. A claim may be a string or an array of
  strings. With none of them set, a token is read as before: `sub`, and
  `roles`. The console reads an ID token's claims the same way.
  `mcpdef auth test --token <jwt>` verifies a token as the listener does and
  says whom it names and what its roles grant on each server.
- **An operator's actions on an upstream, from the admin API.**
  `POST /api/v1/servers/{id}/restart` opens a server again now, a stdio
  server as a new process, its old connection serving until the new one
  opens; `/test` pings it over its live connection; and `/pins` approves
  drift: each drifted tool, named with the hash of the definition the
  operator was shown, is taken as its pin, saved, and served again at once,
  surviving a reload and a restart; nothing is taken when one has changed
  since. Each needs `console:operator`, and each, refused or taken, is
  recorded with its caller.
- **The config and the gateway's connections through the admin API.**
  `GET /api/v1/config` shows an admin the config file with every secret it
  holds masked, by where it sits and by its shape, comments included, and
  `POST /api/v1/config/validate` checks a config without applying it,
  reading and running nothing it names. `GET /api/v1/tls` shows each
  listener's TLS and the certificates it serves, `GET /api/v1/ca.pem` the
  local CA's certificate and nothing else, `GET /api/v1/credentials` how each
  upstream's credentials fare, `GET /api/v1/clients/{client}/snippet` what
  `mcpdef connect` prints, and `GET /api/v1/identity` (admin) who the gateway
  takes its callers to be: how the console signs people in, the identity
  provider's settings but its secret, and how `[identity]` reads claims.
- **The gateway's state through the admin API.** `GET /health` answers a
  probe, for anyone. `GET /api/v1/info` says what the gateway is and how it
  is set up: its wire and revisions, listeners, auth, inspect mode and the
  ledger's length and head. `GET /api/v1/metrics` gives the calls in
  figures: totals, denials by rule, latency percentiles, the most-called
  tools and the last hour minute by minute. `GET /api/v1/servers/{id}` is
  one server, and `/api/v1/servers/{id}/tools` each tool its connection
  offers, with why `tools/list` hides it and its pin state;
  `/api/v1/servers` now also counts each server's drifted and poisoned tools
  and shows its resource and prompt allowlists. The `/api/v1/policy/rules`,
  `/rbac` and `/profiles` views show the policy as the gateway runs it, a
  transform's set values left out, and `/api/v1/inspect/config` and
  `/inspect/findings` how inspect is set up and the last 256 things it
  found, with no secret: an injection's own words, and for a secret only
  its rule.
- **The audit ledger through the admin API.** `GET /api/v1/audit` pages the
  ledger newest first, a cursor at a time, filtered by `decision`, `server`,
  `tool`, `agent`, `rule`, `kind`, `since` and `until`, and each page reads
  only its own records. `GET /api/v1/audit/{seq}` is one record.
  `GET /api/v1/audit/verify` checks the chain, and that the file still holds
  every record this gateway wrote (or a seal's `head` and `count`), so a
  ledger cut short or replaced fails though its own chain holds.
  `GET /api/v1/audit/export` streams the formats `mcpdef audit tail` writes,
  and `GET /api/v1/audit/stream` sends each record as it is appended, as
  Server-Sent Events that resume after `Last-Event-ID`. `?limit` alone still
  answers the bare list, now without reading the whole ledger for it.
- **A reload from the admin API.** `POST /api/v1/reload` reads the config
  again and applies it, as `SIGHUP` does, for a caller holding
  `console:operator`: `200` with what changed, or `409` with the rule and
  reasons when it is refused and the old config keeps serving. Its record
  names the caller as `actor` and where it called from as `peer`. An action
  refused for want of a role is recorded too, as `kind = "admin"` under
  `rule = "console-role"`.
- **The console.** The admin listener serves the MCPdef console at `/`: a
  React app on the MCPdef design system, embedded in the binary, its files
  brotli- or gzip-encoded as the browser asks, cached for good where their
  names change with their content. It asks who the caller is
  (`GET /api/v1/session`), says when nothing signs callers in, and shows
  each view whose data the admin API serves; the others say what they wait
  on. Its source is `console/`; the `mcpdef-console` crate carries the build,
  so building the gateway needs no Node. A build without the default
  `console` feature serves the built-in status page, as before. It is
  Apache-2.0, as the gateway is.
- **`mcpdef tls issue` and `mcpdef tls revoke`: client certificates from the
  local CA**, for mTLS with no PKI of one's own.
  - `tls issue --client <name> [--spiffe-id <id>] [--days 30] [--out <dir>]`
    writes `<name>.crt` and `<name>.key`, the key `0600`, never over a file
    there. The name is the subject's common name (`identity = "subject-cn"`)
    and the SPIFFE ID a URI name (`identity = "spiffe"`). Each certificate
    has a random serial, is for TLS clients alone, and is checked, its names
    read, as the gateway would before it is written.
  - It prints the serial, and the `[gateway.tls.client_auth]` that takes it:
    the local CA as `ca`, and its CRL, `<state_dir>/tls/ca.crl`, as `crl`,
    which the first `tls issue` writes so that `crl` can name it at once.
  - `tls revoke <serial | file>` puts a certificate in the CRL. A reload
    refuses it, on connections already open too.
  - `tls init --new-ca` writes the new CA's CRL once client certificates
    have been issued, so `crl` is never left naming the old CA's.
- **`mcpdef doctor`: what is wrong with a gateway, or soon will be, in one
  report.** Each line is ✓, ⚠ or ✗, and it exits non-zero on any ✗.
  - **config**: `validate`'s errors and warnings, a secret written in the
    config among them. **tls**: what `tls show` warns of. **admin**: an admin
    listener other machines can reach, which asks no one who they are.
  - **sign-in**: the identity provider's keys, fetched from `jwks_uri` as the
    gateway fetches them, and its clock against this machine's, read from its
    `Date`. Further apart than the 60 s a token's times are allowed, fresh
    tokens are refused as not valid yet, or every token expires early: a
    failure otherwise seen only as `401`s.
  - **servers**: each upstream, opened as `mcpdef run` opens it: up, or down
    and why; what it adds to `tools/list`; the resources and prompts it
    offers that no `resources` or `prompts` list exposes; a tool name two
    servers offer; and certificates near their end.
  - It keeps nothing a running gateway keeps: no audit record, no pin, no
    state.
- **`mcpdef connect <client>`: the entry a client needs, in its own format.**
  `claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex` or `generic`:
  each keeps its servers in a different file, under a different key
  (`mcpServers`, `servers`, `[mcp_servers]`), with a different way to name a
  secret. It carries the URL, a token by the variable that holds it (never its
  value), and how that client trusts the gateway's local CA; for Claude Code,
  the `claude mcp add` line too.
  - Claude Desktop's file runs only commands, so it gets a `mcpdef bridge`
    entry, and so does any client given `--cert`/`--key`.
  - `--write` merges the entry into the client's file and keeps a `.bak` of
    what was there. Run again, it writes nothing and leaves the backup alone. A
    file it cannot read as plain JSON, such as VS Code's with comments, is left
    as it is. Codex's TOML keeps its comments and layout.
  - `mcpdef tls init` ends by pointing at it.
- **`mcpdef bridge <url>`: a stdio client to a remote MCPdef** — or to any
  Streamable-HTTP MCP endpoint — with a private CA (`--ca`), a client
  certificate (`--cert`, `--key`) and a token file (`--token-file`), for a
  client that cannot use them itself. The client launches it as its stdio
  server. It stands in for Node shims such as `mcp-remote`: nothing the remote
  end sends chooses what it runs.
  - It is the gateway with that one upstream, not a second program: the config
    it runs is parsed and checked as a file's would be, and `--print-config`
    prints it, a valid file for `mcpdef run`.
  - Governance passes through: every tool, resource, resource template and
    prompt the remote end offers is offered, and the remote end decides. Each
    of those allowlists is opened, because an unset `resources` exposes
    nothing.
  - The key and the token are read from their files when needed, and never
    printed. `--spec` defaults to `auto`.
  - Its ledger and state default under `~/.mcpdef/bridge/`, never the working
    directory a client launched it from. With no `HOME`, `--audit` and
    `--state-dir` say where.
- **HTTPS on the gateway's own listeners (`[gateway.tls]`).** Off by default.
  - `mode = "files"` serves a certificate and key from files, as cert-manager
    or certbot writes them, read by the rules a client certificate is: PEM
    only, the key unencrypted and the certificate's own, from `{ file = … }`,
    `{ env = … }` or `{ exec = … }`.
  - `mode = "self-signed"` serves a certificate a local CA of MCPdef's own
    issues, kept under the new `[gateway] state_dir` (default
    `./mcpdef-state`), the keys `0600`. The CA is made once, and carries a
    name constraint: `localhost`, the loopback addresses, the listen
    addresses and `hostnames`, so clients refuse a certificate its key signs
    for any other name. The certificate lasts 30 days, and the running
    gateway issues it again with 10 left, under the same CA.
  - Each listener's `ServerConfig` is swapped whole at a reload: a
    certificate renewed in its files is served from the next connection on,
    with `watch_config` or a `SIGHUP`, and one that does not read refuses the
    reload. Turning TLS on or off needs a restart.
  - The handshake is TLS 1.2 or 1.3 on ring, offering HTTP/1.1, with 10 s to
    finish; one that stalls holds up no other. A client certificate is asked
    for only with `client_auth` (below).
  - The admin listener serves the same, unless `[gateway.admin.tls]` sets its
    own (`mode = "off"` keeps it plain).
  - `mcpdef tls init` makes the CA and the certificate, and prints how each
    client trusts the CA: `NODE_EXTRA_CA_CERTS` (Claude Code),
    `CODEX_CA_CERTIFICATE` (Codex), and the system store's command.
    `--new-ca` replaces the CA, for a name the old one does not vouch for.
  - `mcpdef tls show` prints each listener's certificate (names, issuer,
    expiry, fingerprint), the local CA, each HTTPS upstream's profile, and
    warnings. `mcpdef tls export-ca` prints the CA's certificate, for a
    client to trust.
- **mTLS: a client's certificate as who it is (`[gateway.tls.client_auth]`).**
  Off by default.
  - `mode = "optional"` asks each client for a certificate and checks one it
    presents; `"required"` refuses a client that presents none at the
    handshake. rustls checks the chain to `ca`, the dates, the client usage
    and, with `crl`, revocation, every CA in the chain included. A
    certificate refused at the handshake is logged.
  - `identity` says which name is the client's: `spiffe`, its one SPIFFE ID
    under the X509-SVID rules, in one of `trust_domains`; `san-dns`, its first
    DNS name; `san-email`, its first email address; `subject-cn`, its
    subject's common name. A certificate that gives none refuses its request
    with `403`, saying why.
  - The identity is recorded as `cert:<identity>`: the `agent` when no token
    names the caller, and the `actor` behind one that does. A `[[policy]]`
    rule's `agents` matches it so.
  - `[[identity.cert_map]]` gives a certificate its roles: each entry whose
    `identity`, exact or a glob, matches gives its `roles`. A certificate that
    matches no entry holds no roles, never a default one. A role no `[[role]]`
    defines is warned about.
  - `[gateway.auth] methods` (`bearer`, `mtls` or both; `bearer` alone by
    default) and `require` (`any` or `all`) say what a request needs. With
    `all`, the token's subject is the `agent` and its roles are judged, and
    the certificate is the `actor`.
  - A reload applies all of it, and `watch_config` watches the `ca` and `crl`
    files. The next request on a connection already open is checked against
    what the reload read: a certificate a new CRL revokes is refused from
    then on, on every connection. One that expires while its connection is
    open is refused from its next request.
  - The admin listener asks what its TLS says, `[gateway.tls]`'s unless it
    sets its own, and refuses a request for its certificate as the MCP
    listener does.
  - `mcpdef tls show` prints what each listener asks of a client's
    certificate; the ready line says `· client certificates <mode>`, and
    `mtls on`, `oauth or mtls on` or `oauth and mtls on`.
- **Behind a proxy that terminates TLS (`[gateway.trusted_proxy]`).** Off by
  default.
  - `cidrs` names the proxy's addresses, and `client_cert_header` the header
    it forwards each client's certificate in: `client-cert`, RFC 9440's (the
    default), or `x-forwarded-client-cert`, the XFCC of Envoy and Istio.
  - The header is read on a request from the proxy alone. From any other peer
    it is not read, so a forged one names no one.
  - MCPdef checks the forwarded certificate as `[gateway.tls.client_auth]`
    checks one presented at the handshake: its chain, through the
    intermediates forwarded with it, its dates, its usage and revocation. It
    is then that client, with its roles, recorded as `cert:<identity>`. A
    header that does not read is refused with `403`, saying why. The proxy's
    own certificate, if it presented one, is never its client's.
  - The listener can serve plain HTTP behind it: `[gateway.tls.client_auth]`
    then needs no TLS of its own.
  - XFCC is read when the proxy in front set it, as one element that carries
    the certificate (Envoy: `SANITIZE_SET`, `cert: true`). Istio's default,
    which names the client and carries no certificate, is refused.
  - A range of every address is warned about. So is a listener other
    machines reach with client certificates `optional` and auth off: the
    proxy does not stop a client connecting to it directly, and one that does
    is served as no one. `mcpdef tls show` prints the proxy, and the ready
    line says `· <header> from a trusted proxy`. A reload applies `cidrs` and
    the header; setting the table or removing it needs a restart.
- **Resources from every server, governed.**
  - `[[server]] resources` lists the URIs a server may expose, as patterns
    whose `*` stops at a `/` and whose `**` segment crosses them.
    `resource_templates` lists the templates it may show.
  - `resources/list` and `resources/templates/list` gather what every server
    may show, into one page. Each entry names its server in
    `_meta["mcpdef/server"]`, and one two servers show is listed once, from
    the first in config order.
  - A `resources/read` goes to the server that listed its URI, else the one
    whose tool result linked it, else the first whose allowlist takes it.
  - The gateway offers `resources` in `initialize` and `server/discover` only
    when some server exposes any. On the modern wire, the three results carry
    `ttlMs: 0` and `cacheScope: "private"`.
  - Two servers whose patterns overlap are warned about, and refused in strict
    mode.
  - A denied read gets `-32002`, the error for a resource that is not there.
    `resources/subscribe` gets `-32601`: the gateway has no stream to send
    updates on.
- **Resources judged like tools.**
  - `[[policy]]` rules take `uris`, URI patterns a read must name. A rule with
    `tools` is about tool calls, one with `uris` about reads, and one with
    neither about both. A read has no arguments, so a rule with `args` matches
    no read. `mcpdef validate` refuses a rule that names `uris` beside `tools`
    or `args`: it could match nothing.
  - `[[role]]` takes `resource_grants`, as `"server-glob:uri-pattern"`.
  - A server's reads share one rate-limit bucket at the per-tool rate, behind
    the global one.
  - `[gateway.inspect]` scans what a read returns, as it scans a tool result:
    `enforce` refuses it with `-32002 MCPdef blocked: …`.
- **Prompts from every server, governed.**
  - `[[server]] prompts` lists the prompts a server may expose, by name
    pattern.
  - `prompts/list` gathers what every server may show, into one page, each
    entry naming its server. A name two servers show is listed once, from the
    first in config order.
  - A `prompts/get` goes to the server that listed the name, else the first
    whose allowlist takes it. `[[policy]]` rules take `prompts`, and their
    `args` then match the prompt's arguments; `[[role]]` takes
    `prompt_grants`; a server's gets share a rate-limit bucket at the per-tool
    rate; and `[gateway.inspect]` scans what a get returns.
  - A denied or scanned-out get gets `-32602`, the error for a prompt name the
    server does not know. The gateway offers `prompts` only when some server
    exposes any.
  - Two servers whose `prompts` patterns overlap are warned about, and refused
    in strict mode.
- **Each tool names its server.** Every tool in `tools/list` carries the id of
  the server it came from in `_meta["mcpdef/server"]`, as resource and prompt
  entries do, on either wire. A value an upstream set there itself is
  overwritten, so no upstream can pass its tools off as another's; the rest of
  its `_meta` is kept.
- **Prefixed tool names.** `[gateway] tool_namespace = "prefix"` lists every
  tool as `<prefix>__<name>`, such as `gh__create_issue`. Each server's prefix
  is its `[[server]] prefix`, or else its id. A call by that name goes to that
  server, which is sent the name it knows. The allowlist, profiles, roles,
  rules, rate limits, pins and the audit keep naming the tool as its server
  does, so switching prefixes on, at startup or by a reload, moves no pin.
  `mcpdef validate` refuses a prefix a tool name may not start with, and warns
  about a listed name longer than 50 characters, two servers that share a
  prefix, and a `prefix` set while prefixes are off.
- **Tool collisions reported.** A tool name more than one server offers is
  reported with every server that offers it:
  - by `mcpdef validate`, when two allowlists name it outright;
  - at startup, when the servers turn out to offer it (said once, if the
    config showed it too), and under `strict` the start fails;
  - as `tool_collisions` on each of those servers in `/api/v1/servers`.
- **Tools kept current.** An upstream that sends
  `notifications/tools/list_changed` has its tools listed again, without a
  restart.
  - A burst of the word lists them once: when it has stopped for 100 ms, and
    at most 1 s after it began.
  - Each new or changed tool is judged as at connect. A new one is pinned on
    first use. One that no longer matches its pin is hidden and refused as a
    `rug-pull`. Each is scanned, and a tool that did not change keeps its
    verdict.
  - Calls are routed by the new list, and a collision it makes is printed as
    at startup.
  - A re-list reads every page, as an opening now does. A failed one, on any
    page, keeps the tools the upstream had.
  - Word the upstream sends while it opens is kept, and its tools are listed
    again once it is in place.
  - The ledger records the change: `kind = "upstream"`,
    `method = "tools-changed"`, and `tool_changes`, the counts of tools added,
    removed, changed and newly drifted. It is a denial under `rug-pull` when
    one drifted.
  - MCPdef hears the word from a stdio server, on a 2024-11-05 SSE bridge's
    stream, and in a Streamable HTTP server's answer to a request.
- **The client told.** Over stdio, each change to what `tools/list` shows is
  sent on as `notifications/tools/list_changed`: an upstream's tools changing,
  a reload, an upstream that started again with other tools. A burst of word
  from an upstream is one notification. An HTTP client, and a 2026-07-28 one, sees the change
  on its next `tools/list`.
- **A 2026-07-28 server may ask the client for something first.** A server
  that needs an elicitation, a sampling or the client's roots answers a
  `tools/call`, `resources/read` or `prompts/get` with an
  `InputRequiredResult`, and the client asks again with its answers
  (multi round-trip requests, SEP-2322). MCPdef:
  - tells a 2026-07-28 upstream the `elicitation`, `sampling` and `roots`
    capabilities of the 2026-07-28 client whose request it relays, and no
    others; it told it none before, so a compliant server never asked;
  - passes the interim result back as it came, after the scanner has read it,
    and records the request as allowed, with `rule = "input-required"`;
  - refuses it, audited as a deny under the same rule, to a 2025-11-25 client,
    which could not read it, and when it asks for what the client did not
    declare, or breaks the revision's rules for one;
  - governs the retry as a new request: every gate again, a rate-limit token of
    its own, a record of its own. Its `inputResponses` and `requestState` go
    upstream as the client sent them.
- **`x-mcp-header` on both sides (2026-07-28 `Mcp-Param-{Name}`).** A server
  may annotate a tool's parameters so their values go in headers too, and a
  client over Streamable HTTP must honour it. MCPdef:
  - sends a modern Streamable-HTTP upstream each annotated argument of a
    `tools/call` as its `Mcp-Param-{Name}` header, Base64 in the sentinel when
    a header cannot carry it as it is, and none when the argument is absent
    or `null`. A strict upstream rejected the call without them. The headers
    are made from the call as it goes upstream, after its `transform` rules;
  - checks a modern client's `Mcp-Param-*` headers against the body of its
    `tools/call`, by its tool's annotations: a header that disagrees, one
    missing for an argument the body carries, one for an argument it does not,
    and one a header cannot carry are refused with `400` and `-32020`. A
    number is compared as a number, so `42.0` and `42` agree. A header no
    annotation names is ignored, as the revision says;
  - hides and refuses a tool whose annotations break the revision's rules (an
    empty name, or one that is not an HTTP token, two names alike but for
    case, a parameter that is not a string, integer or boolean, or one not
    reached through `properties` alone), on any transport, one tool at a time;
  - goes by each tool's annotations as its server lists them now: they are
    judged with the tools, at an opening, a restart and a reload, and again
    each time the server says its tools changed.
- **`transform` rules rewrite a tool call's arguments.** A `[[policy]]` rule
  with `effect = "transform"` edits the arguments in `set_args`: `set` a value,
  `default` one where nothing is, `remove` a path, or `clamp` a number to
  `{ min, max }`.
  - The transform rules run after the allowlist and before the `allow` and
    `deny` rules. Every one that matches applies, in config order, each over
    the arguments as the rules before it left them. The `allow` and `deny`
    rules then judge what they made, and that is what the upstream gets. No
    rule can change the tool's name.
  - One that cannot apply (a `clamp` of something that is not a number, a
    path through something that is not an object) denies the call under its
    own name, saying why by type and path, never by value. With
    `on_error = "skip"` it is skipped and logged instead, and leaves nothing
    of its edits.
  - Each record of the call names the rules that fired, in order, as
    `transforms`, and no value.
  - `mcpdef validate` refuses a transform rule with no edits, one with
    `set_args` that names `uris`, one that names `prompts`, an edit with no
    operation or two, a date, a number that is not finite, and a `clamp` with
    no bound or with `min` above `max`.
- **`transform` rules edit a result too, and `[gateway.inspect] mode =
  "redact"`.** A transform rule's `result` lists edits of what the upstream
  answers: a tool call's result, or a read's contents.
  - `redact = "secrets"` puts `[REDACTED:<rule>]` in place of each secret the
    inspect pack's secret rules and `secret_substrings` find in a string of the
    result, whatever inspect's mode. `mask = "<path>"` puts
    `[REDACTED:<the rule's name>]` in place of a string, `remove = "<path>"`
    takes a key out, and `truncate = <bytes>` cuts each text block at a
    character boundary and says how long it was.
  - A path, `*` standing for every element or value, points into the JSON the
    result carries: its `structuredContent`, and each text block that holds a
    JSON object or array. Every edit is made to JSON values, never to
    serialized text, so the result stays valid JSON. A text block that mirrors
    the `structuredContent` is written again from it when the structure
    changes, so the two agree, and otherwise keeps the upstream's own text.
  - An edit of a `structuredContent` is checked against the tool's
    `outputSchema`, as its pin keeps it. A string the schema constrains beyond
    its type, a key it requires, or a place MCPdef does not follow (`allOf`, a
    union whose branch it cannot tell, a reference outside the schema) cannot
    be edited. Nor can a string that is not there to `mask`, or a secret in a
    key, which is never redacted. An edit that cannot apply denies the call
    under the rule's name, by path, never by value: a key the rule's path did
    not name shows as `*`, unless the schema names it. `on_error = "skip"`
    skips the rule instead.
  - Each record of the call names, in `transforms`, the rules that fired on the
    arguments and then on the result, each once, and no value.
  - Only a final result is edited: an interim one (`InputRequiredResult`) goes
    back as it came. A rule with `result` alone may name `uris`; no transform
    rule may name `prompts`.
  - `[gateway.inspect] mode = "redact"` redacts the secrets the pack finds in a
    tool call's result, a read's contents, a prompt's messages or a
    completion's values, as `redact` does, where `enforce` refuses them. The
    result passes, recorded as allowed with `rule = "secret-redacted"`. What
    redaction cannot make safe is refused as under `enforce`: an injection, and
    a secret in an interim result, in a key, where the redaction of strings
    does not reach (an image's base64, a match only across strings), or where
    the `outputSchema` does not let it change. A redacted result is read again whole, and passes only if
    the pack finds nothing in it. A tool whose description trips the pack is
    hidden, as under `enforce`.
- **What the tools cost: `mcpdef tools list --cost`.** Every agent that lists
  the tools reads the `tools/list` answer into its context. `--cost` prints,
  per server, how many of its tools are listed of those it offers, the bytes
  they take up in that answer, and bytes ÷ 4, labelled as an estimate of the
  tokens. It counts the tools as the gateway lists them: after the allowlist,
  the active profile, the pins and the scanner, by the name each is listed by,
  with its `_meta`. So a profile's cut shows, and `--profile` counts under
  another, as it lists for `run`. Without `--cost`, `mcpdef tools list` prints
  each listed tool and its server, and `servers list` now points to it for the
  live list. The admin servers view carries the counts as each server's
  `listing`: `{ offered, listed, bytes }`.
- **Completions, routed and governed.** `completion/complete` goes to the
  server that has the prompt or the resource template its `ref` names, as a
  get or a template list would. A prompt's completion meets a get's gates,
  with the arguments resolved so far as the rules' `args`; a template's meets
  the template allowlist, the rules that name no kind, and RBAC, which asks
  for a role granting some resource on that server. Completions spend a
  bucket of their own per server, and what comes back is scanned. The
  gateway offers `completions` when there is a prompt or a template to
  complete.
- **`mcpdef-policy` API: one glob engine, and URI normalization.**
  - `glob::names` is the matcher every allowlist, grant and rule already used.
  - `glob::UriGlob` matches resource URIs segment by segment: `*` within one
    segment, a `**` segment across any number of them.
  - `uri::normalize` puts a URI in normal form (RFC 3986). It refuses a URI
    that two readers could take two ways: one with an encoded `/` or `\`, a
    backslash, a NUL, an empty segment inside the path, or an escape of an
    escape.
  - `UriGlob::overlaps` says whether one URI could match two patterns, and
    `glob::names_overlap` whether one name could match two name patterns.
  - `ResourcePolicy`, `Policy::insert_resources`, `Policy::resources`,
    `Policy::exposes_resources` and `Policy::decide_resource` hold and judge
    each server's resource allowlists; `Policy::insert_prompts`,
    `Policy::prompts`, `Policy::shows_prompt`, `Policy::exposes_prompts` and
    `Policy::decide_prompt` its prompt allowlist. `Policy::exposes_templates`
    and `Policy::decide_template` judge a template's completion, and so does
    `Rbac::decide_template`.
- **`mcpdef-ratelimit` API:** `RateLimiter::check_read`, `LimitScope::Reads`,
  `RateLimiter::check_prompt`, `LimitScope::Prompts`,
  `RateLimiter::check_completion` and `LimitScope::Completions`.
- **`mcpdef-core` API:** `method::RESOURCES_TEMPLATES_LIST`,
  `method::RESOURCES_SUBSCRIBE`, `method::RESOURCES_UNSUBSCRIBE`,
  `method::COMPLETION_COMPLETE` and `wire::error_code::INVALID_PARAMS`. **`mcpdef` API:**
  `ServerConfig::resource_templates`, `ServerConfig::resource_policy` and
  `ServerConfig::prompts`; `GatewayConfig::tool_namespace`, `ToolNamespace`,
  `ServerConfig::prefix`, `Config::tool_prefixes`, `Gateway::with_tool_prefixes`,
  `Gateway::tool_warnings`, `connect::tool_findings`, `ToolCollision`,
  `TOOL_PREFIX_SEPARATOR`, `LISTED_NAME_WARN`, `Gateway::tool_list_changes`,
  and `Gateway::tool_costs` with `ToolCost`, what each upstream adds to
  `tools/list`.
  **`mcpdef-core` API:** `method::TOOLS_LIST_CHANGED`;
  `method::ELICITATION_CREATE`, `method::SAMPLING_CREATE_MESSAGE` and
  `method::ROOTS_LIST`; `wire::result_type`, `wire::input_required`,
  `wire::input_capabilities`, `wire::unanswerable_input` and
  `wire::stamp_request_offering`, for multi round-trip requests. **`mcpdef-transport`
  API:** `UpstreamHandle::spawn_listening`, a handle whose notifications are
  heard from the moment it takes the transport over, including those the
  transport already holds.
- **`mcpdef-policy` API:** `Effect::Transform` with `Transform`, `ArgEdit`,
  `EditOp` and `OnError`; `PolicyRules::transform`, which returns
  `Transformed`, and `PolicyRules::transforms`, whether a rule edits
  arguments. `Effect` is no longer `Copy`. For results: `Transform::result`, a
  list of `ResultEdit`; `PolicyRules::transform_result` and
  `PolicyRules::transforms_results`; `PolicyRules::with_secrets`, which keeps
  a `Detector`, what finds the secrets a `redact` replaces, as `Detected`; and
  `redact_result`, inspect's redaction, which returns the rules it redacted or
  why it could not, as `Unredacted`. **`mcpdef` API:**
  `PolicyRuleConfig::set_args`, `on_error` and `result`, a list of
  `ResultEditConfig`; `ArgEditConfig` and `ClampConfig`. **`mcpdef-inspect`
  API:** `Mode::Redact` and `Scanner::redacts`.
- **`mcpdef-audit` API: `tool_changes`.** `ToolChanges` holds the four counts,
  on `Record::tool_changes` and `Attrs::tool_changes`. The hash covers it as
  it covers every later member, so 0.4.0-alpha.1 verifies a ledger that holds
  one. OCSF exports it in `unmapped.tool_changes`, CEF as `cs6`
  (`toolChanges`) and syslog as a `tool_changes` parameter, each as a JSON
  object.
- **`mcpdef` API: listener TLS.** The `tls` module: `ListenerTls` (what the
  listeners serve, swapped at a reload), `Serving`, `TlsListener` (an
  `axum::serve` listener with a handshake timeout), `TlsSlot`, `build`,
  `self_signed_names`, and `tls::local_ca` with `LocalCa`, `Names`, `Paths`,
  `ensure` and `ca_cert_pem`. `serve_https`, `serve_https_on` and
  `serve_admin_with`; `Reloader::with_listener_tls` and
  `Reloader::renew_if_due`; `ListenerTlsConfig`, `ListenerTlsMode`,
  `GatewayConfig::admin_tls` and `listens_locally`. **`mcpdef-transport`
  API:** `read_served`, a certificate and key read as a listener serves them,
  and `CertificateNames`, a certificate's subject, issuer and alternative
  names, read by the DER walk `PeerCertificate` uses.
- **`mcpdef` API: the bridge, clients, doctor and client certificates.**
  `bridge::Bridge`, the config a bridge runs (`config_text`, `config`), and
  `bridge::default_home`; `clients`, each client's entry (`Client`, `Target`,
  `Ask`, `Entry`, `entry`, `write`, `Wrote`, `listener_url`, `system_store`);
  `doctor`, the report and its checks (`Section`, `Finding`, `Mark`, `admin`,
  `clock`, `upstream`); `connect::examine`, the gateway `mcpdef doctor` opens;
  `tls::issued` (`issue`, `revoke`, `refresh_crl`, `parse_serial`,
  `serial_hex`), with `LocalCa::sign_client`, `LocalCa::crl`,
  `Leaf::write_to`, `Paths::crl` and `Paths::revoked`; `UpstreamStatus::offers`
  and `Offers`, what an upstream declared when it opened; `ToolCost::tokens`;
  `AdminConfig::listens_locally`. **`mcpdef-transport` API:** `fetch_dated` and
  `Dated`, a guarded `GET` that keeps the answer's `Date` and the request's
  timing, and `certificate_serial`. **`mcpdef-auth` API:** `clock_leeway`, the
  skew `Verifier::verify` allows a token's times.
- **`mcpdef` API: the admin listener's envelope and the console.**
  `serve_admin_on`, the admin server on a listener already bound;
  `AdminState::new` and `AdminState::reconfigure`, and its `guard`;
  `admin::guard`: `Caller`, `ConsoleRole`, `Guard`, `problem`, and
  `CONTENT_SECURITY_POLICY`; `GatewayConfig::admin_signs_in`;
  `AdminConfig`'s `public_url`, `hosts` and `allow_unauthenticated`; the
  default `console` feature; `AdminState::with_reloads`; `Gateway::audit_admin`;
  and in `reload`, `channel`, `Reloads`, `Requests`,
  `Reloader::with_requests`, and `Trigger::Admin` (`Trigger` is no longer
  `Copy`, and `as_str` is now `actor`). **New crate `mcpdef-console`:** `Asset`, `get`
  and `index`, the console's built files. **`mcpdef-testkit` API:**
  `listening_port` and `listening_ports`, the ports a gateway's lines name.
- **`mcpdef-inspect` API: where each match is.** `Scanner::find_all` returns
  every match in a text as a `Match`: its category, its rule and its byte
  range, for a caller that rewrites what matched instead of refusing the text.
  - The ranges fall on character boundaries, come in the order of the text and
    never overlap. Where two rules' spans do, each character goes to the rule
    `scan` tries first, so `scan`'s finding is always the match with the
    earliest rule. Every character some rule matched is in a match.
  - A token's span is its prefix and its whole body. A private key's is its PEM
    block through the trailer, or up to the next block or the end of the text
    when it is cut short. An operator's secret substring's runs on over the
    letters, digits and `-_.+/=` after it, which hold the rest of a credential
    it is the prefix of.
  - `scan` and `secret_pattern` answer as they did, now from the same rules,
    and a little faster on text with no finding.
- **`x-mcp-header` API.** `mcpdef-core`: `wire::ParamHeader`,
  `wire::param_headers`, which reads a tool's annotations or says why it
  cannot be served as `wire::SchemaError`, `wire::param_header_values` and
  `wire::validate_param_headers`. `mcpdef-transport`: `ParamHeaders`, what a
  transport sends each `tools/call` by, and `Transport::param_headers`, a
  transport's own, `None` by default. `mcpdef`: `Gateway::check_param_headers`.

### Changed
- **A token's `scp` may be one string of scopes**, separated by spaces, as
  Entra sends it, and a `roles` claim may be one string. Either was refused,
  and the whole token with it; an array of each still reads as before.
- **`mcpdef version`** reads its spec line from the revisions the build speaks
  instead of carrying a hand-written copy of them, which went stale once already.
  It prints the same line today; a revision added to the build now reaches it
  without anyone editing it. The `phase 1.5` line is gone, and so is the
  "(Phase 1.5)" in `mcpdef --help`'s header: both predate the 0.4.0 work.
- **The crates' Rust API.** `mcpdef-policy`: `PolicyContext`'s `tool` becomes
  `target`, a `Target`: the tool a call names, the URI a read names in normal
  form, the prompt a get names, or the template a completion names. `Rule` gains `uris` and `prompts`, so a
  struct literal must set them; `Rbac` gains `insert_resource_grants`,
  `decide_resource`, `insert_prompt_grants` and `decide_prompt`. `mcpdef`:
  `RoleConfig::resource_grants` and `prompt_grants`, and
  `PolicyRuleConfig::uris` and `prompts`. `GatewayConfig` gains `tls` and
  `state_dir`, and `AdminConfig` gains `tls`. `UpstreamStatus` gains
  `tool_collisions` and `Reconfig` gains `tool_prefixes`. `mcpdef-audit`:
  `Record` and `Attrs` gain `tool_changes`, so a struct literal must set it.
  `mcpdef-ratelimit`: `RateLimiter::check` takes the server as well as the
  tool, and keeps a bucket per server and tool, so two servers' tools of one
  name spend apart. For mTLS: `Gateway::handle_from` takes a `Caller` (a
  token, a certificate's identity, an address), which `handle_authed` now
  wraps; `AuthState::certificate` and `or_certificate`; a `TlsSlot` holds a
  `tls::Served`, a configuration and its `tls::client_auth::ClientCerts`, and
  a `TlsListener` yields a `TlsConnection`; `Config` gains `identity`,
  `ListenerTlsConfig` gains `client_auth`, and `AuthConfig` gains `methods` and
  `require`, so a struct literal must set them; `Rbac` gains
  `map_certificates` and `certificate_roles`. `mcpdef-transport`:
  `read_client_trust`. `mcpdef-testkit`: `LeafBuilder::ca`. Behind a trusted
  proxy: `tls::Served`'s `config` is an `Option`, `None` on a listener that
  serves plain HTTP behind one, and it gains `proxy`, a
  `tls::forwarded::TrustedProxy`; `Serving::mcp` holds for such a listener
  too; `serve_proxied` and `listener::serve_proxied_on` serve it;
  `Presented::forwarded`; `GatewayConfig` gains `trusted_proxy`, a
  `TrustedProxyConfig` with its `ClientCertHeader`.

### Fixed
- **The Compose example's gateway could not write its ledger.** It mounts a
  named volume at `/var/lib/mcpdef`, where the example config keeps the ledger
  and the state, but the image had no such directory, so Docker made the new
  volume root's. The gateway, which runs as user 65532, stopped at "opening
  audit ledger … Permission denied" and restarted in a loop. The image now has
  `/var/lib/mcpdef`, belonging to that user, and a new volume mounted there
  takes its owner. A volume that loop left empty is put right when the
  container is next created (`docker compose pull && docker compose up -d`);
  one that already holds files is left as it is. The Docker Hub page's
  `docker run` example offered a named volume where the image has no
  directory, which fails the same way, and ran the stdio gateway with no
  input, so it exited at once: it now serves HTTP, with its volume at
  `/var/lib/mcpdef`.
- **The ready line came before the listeners were bound.** A client that
  connected as it appeared could be refused, or, on a port another process
  took first, reach that process. The listeners are now bound before the
  upstreams start, and the ready line names the addresses they took: with
  `listen = "127.0.0.1:0"` the system gives a port, and the line says which.
  The admin listener's is in the line after it.
- **A call hung when its server asked the client for something.** A
  2025-11-25 server asks its client for an elicitation, a sampling or its roots
  with a JSON-RPC request of its own, and waits for the answer. MCPdef dropped
  such a request, so the call the server was making waited until
  `upstream_timeout_ms`, or for good. Now it answers each at once with
  `-32601`, saying it does not relay it, and a `ping` with `{}`: on stdio, on a
  2024-11-05 SSE bridge's stream, and in the middle of a Streamable HTTP
  answer, which it now reads as it comes. The log names the upstream and what
  it asked.
- **Only the first page of an upstream's tools was read.** An upstream that
  splits `tools/list` into pages had its later tools unknown to the gateway,
  and to `mcpdef pin` and `mcpdef diff-tools`. Now each follows `nextCursor`,
  up to 20 pages and 10,000 tools, as the resource and prompt lists do. A
  later page refused fails the opening, as a refused first page does.
- **A tool call could go to a server that hid the tool.** A name two servers
  listed went to the first that listed it, even when that server's allowlist
  hid it. The call was refused, while `tools/list` showed the other server's
  copy. Now it goes to the first server whose allowlist takes it, which is the
  copy listed.
- **`mcpdef.example.toml` offered `search` from two servers.** Its
  `remote-tools` server now offers `web_search`.

### Spec support
- Built against MCP spec **2025-11-25**, still the default on both sides, and
  serves and speaks **2026-07-28** beside it, now with `Mcp-Param-{Name}` on
  both sides and a 2026-07-28 server's `InputRequiredResult` relayed to a
  2026-07-28 client; the resource and prompt lists carry the caching hints the
  tool list does. Not yet implemented from 2026-07-28: forwarding a
  `Mcp-Param-*` header no annotation names, SSE responses,
  `subscriptions/listen` (and an upstream's own notification stream), relaying a
  2025-11-25 server's own requests to its client, and `resultType` on results
  relayed from a 2025-11-25 upstream and on the `tools/call` errors MCPdef
  writes itself. See `docs/WIRE.md`.

## [0.4.0-alpha.1] - 2026-09-26

The first pre-release of 0.4.0. Calls run concurrently, each upstream is
supervised, and the config reloads without a restart. HTTPS upstreams take TLS
profiles, pins and client certificates. Every secret the config names can come
from a file, a variable or a command, and upstreams can be sent credentials, an
OAuth token among them. Strict mode refuses a config there is anything to warn
about. It also brings the 2026-07-28 wire, which no release had carried: there
is no 0.3.0.

This pre-release is published on GitHub and on Docker Hub, as
`mancube/mcpdef:v0.4.0-alpha.1`, and nowhere else: crates.io, Homebrew and the
`:latest` image stay on 0.2.2.

### Upgrading from 0.2.x
- **An upstream that cannot open no longer stops the gateway.** It starts down,
  is named on the ready line, and is retried. So is one that refuses the
  handshake, which used to come up offering no tools. To know every upstream is
  up, watch `mcpdef_upstream_up` or `/api/v1/servers`, or set `[gateway] strict
  = true`, under which one that does not open fails the start.
- **Upstreams get calls at once**, up to `[[server]] max_inflight`, 16 by
  default, where the gateway sent them one at a time. Set it to `1` for an
  upstream that cannot take more.
- **A call to an upstream that is down, or that fails the call, is a tool
  error**, `MCPdef error: …`, and is audited. It was an HTTP `500` or a JSON-RPC
  error, with no record.
- **`SIGHUP` reloads the config** instead of ending the process. Stop the
  gateway with `SIGTERM` or `SIGINT`.
- **New warnings at startup and in `mcpdef validate`**: a secret written in the
  config, such as a `[server.env]` string named like `TOKEN` or shaped like a
  known credential, and a secret in a server's `url` or `command`. They stop
  nothing unless strict mode is on. Move each secret to a file, a variable or a
  command.
- **A `*` inside a pattern now matches.** A deny pattern such as `*delete*`
  denied nothing, and an allow pattern like it allowed nothing: each now
  matches what it names. Review deny lists, grants and rules. 0.2.2 already
  does this.
- **A bearer token must give `exp` and `nbf` as numbers**, or it gets `401`.
  0.2.2 already does this.
- **On the default `wire = "legacy"`, a 2026-07-28 request is refused** with
  `400` + `-32022`. Set `wire = "dual"` to serve it.
- **`upstream_timeout_ms`, when set, bounds every call**: it never timed out a
  Streamable-HTTP or wasm one.
- **The ledger.** A 0.2.1 ledger verifies unchanged. New records can carry new
  members (`kind`, `actor`, `peer`, …), which a reader of the raw lines must
  accept, and a call an upstream refuses with `401` is `upstream-auth-failed`,
  where it was `upstream-error`.
- **The crates' Rust API** changed: see "Changed".

### Added
- **Serve the stateless 2026-07-28 wire — `[gateway] wire`** (`"legacy"` |
  `"dual"` | `"modern"`, default `"legacy"`). Picks which MCP revisions the HTTP
  listener serves: `legacy` is 2025-11-25 only, `modern` the stateless 2026-07-28
  only, and `dual` both on the one endpoint. The listener keeps no session state,
  so the era is read off each request: `io.modelcontextprotocol/protocolVersion`
  in `params._meta` means modern, `initialize` means legacy, and anything else is
  served as legacy (refused on `modern`). On the modern wire:
  - **Mirrored headers are checked, never trusted.** `MCP-Protocol-Version`,
    `Mcp-Method` and — on `tools/call`, `prompts/get` and `resources/read` —
    `Mcp-Name` are required and must match the body (`=?base64?…?=` values are
    decoded first) before anything routes; a missing or mismatched header gets
    `400` + JSON-RPC `-32020`. The allowlist, argument policy, pin and rate limit
    still key on the body alone, and a header that disagrees with it (say,
    `Mcp-Name: safe_tool` on a body calling another tool) is refused rather than
    believed.
  - A revision the listener does not serve gets `400` + `-32022`, whose
    `data.supported` lists what it does serve; `modern` refuses `initialize` with
    a message naming the `_meta` field and header to send instead.

  `server/discover`, which 2026-07-28 requires of every server, is now answered
  by MCPdef itself — on stdio as well as HTTP — with the revisions `wire` serves;
  on stdio, that list is all `wire` changes. The governance path (allowlist,
  argument policy, tool-definition pin, rate limit, audit ledger) is identical
  for both eras.
- **Front 2026-07-28 servers — `[[server]] spec`** (`"2025-11-25"` |
  `"2026-07-28"` | `"auto"`, default `"2025-11-25"`): which revision each fronted
  server speaks. A `"2026-07-28"` upstream gets no `initialize` — the revision
  removed it. MCPdef opens it with `server/discover`, checks the configured
  revision is one it lists, then puts the protocol version, its own `clientInfo`
  and empty capabilities in the `_meta` of every request it sends — over
  Streamable HTTP with the mirrored `MCP-Protocol-Version` / `Mcp-Method` /
  `Mcp-Name` headers, derived from the same message so the two cannot disagree;
  a 2025-11-25 upstream is sent no `Mcp-Method` or `Mcp-Name`, as before. A
  `spec` that does not match the server fails its opening, naming the knob, and
  `mcpdef pin` / `mcpdef diff-tools` open each upstream per its `spec` too. One
  gateway can front both eras at once, in either direction: each request's
  `_meta` is rewritten for the revision its upstream speaks, so a 2026-07-28
  client can reach a 2025-11-25 server through it, and the reverse.
- **Era detection — `spec = "auto"`.** MCPdef asks for `initialize` and reads the
  answer: a result means 2025-11-25, and the handshake is then already done, so
  the upstream opens in the same round trips as a pinned one; a `-32601` (no such
  method), `-32020` or `-32022` refusal means 2026-07-28, confirmed with
  `server/discover`. The probe *is* the opening request, so `auto` works over
  stdio, Streamable HTTP and the 2024-11-05 SSE bridge alike. An upstream that
  answers it with an error status such as `401` or `503`, or not at all within
  5s, fails its opening, naming the status or `spec`, rather than being
  assigned an era. The probe's 5s are added to `upstream_timeout_ms` for that
  upstream's opening, not taken out of it.
- **`docs/WIRE.md`** — what each era gets, what 2026-07-28 changed, how era
  detection and the `auto` probe decide, and which parts of 2026-07-28 are not
  implemented yet.
- **`mcpdef-core::wire`** — the wire-model seam both ends are built on: the
  `WireModel` era split, the `_meta` accessors and `stamp_request`,
  `mirrored_headers`, `validate_headers` (its `Routing` is read entirely from the
  body, so a header can only be checked, never trusted), the `=?base64?…?=`
  codec, and the `-32020` / `-32022` error shapes. The `mcpdef` crate adds
  `Gateway::add_upstream_speaking`, `Gateway::with_wire` and
  `list_tools_speaking`; `HttpConfig` gains a `wire` field, so struct literals of
  it must now set one.
- **`mcpdef-bench`, a load harness** (`crates/mcpdef-bench`, never published). It
  runs the release binary in front of mock MCP upstreams and reports four things:
  - what the gateway adds to an allowed call, measured against calling the same
    upstream directly in the same run;
  - what a denied call costs;
  - whether one slow upstream holds up calls to the others, over HTTP and over
    stdio, from 8 clients or as many as `--neighbour-concurrency` asks for;
  - the gateway's memory, idle and after a burst of calls. It reports the
    anonymous part (heap and stacks) beside the resident set, because the
    resident set also counts the executable's own pages, which follow the
    kernel's page cache: between runs of one binary it moves by up to 16 %,
    where idle anonymous memory moves by 2.5 %.

  `compare` checks a report against a committed baseline using ratios measured
  within one run. It will not compare runs from different machines or with
  different parameters, and names the parameters that differ. It judges idle
  anonymous memory within 5 %, where the resident set needs 20 %, and skips a
  metric an older baseline lacks. `make bench` runs it. The baselines recorded
  for this release show calls to 19 fast upstreams waiting behind one slow one,
  at 8 clients and at 200.
- **`mcpdef-testkit`, support for testing TLS** (`crates/mcpdef-testkit`, never
  published, and never a dependency of the gateway). A test makes its own PKI
  when it runs:
  - certificate authorities, intermediates included, and the server and client
    certificates they issue, with DNS, IP, URI (SPIFFE) or email identities;
  - CRLs that revoke those certificates;
  - files to point a config at, keys readable by their owner alone.

  It also serves an MCP upstream over HTTPS, which can require a client
  certificate and records what it accepted and refused, and gives a client that
  trusts a test PKI. No certificate or key is ever committed.
- **Audit records can carry more than a governed call.** Seven optional members:
  - `kind`: `admin`, `reload` or `upstream`, and a call when absent;
  - `uri`: the resource a request named;
  - `transforms`: the transform rules that fired;
  - `actor`: a second identity beside `agent`;
  - `peer`: the network address the request came from;
  - `config_from` and `config_to`: a reload's config digests, before and after.

  Upstream events and reloads write the ones they need; the features that need
  the rest fill them in. A record
  without them is written and hashed exactly as before, and a 0.2.1 ledger
  verifies unchanged. The hash covers every member beyond the original ten as
  one canonical JSON object. That includes members a later release adds, so
  today's `mcpdef audit verify` will still check tomorrow's ledger. A line that
  names a member twice is refused as corrupt. The OCSF, CEF and syslog exports
  carry the new members, with the same CR/LF stripping as the rest.
- **Each upstream connection is shared by the calls to it**, through a new
  `UpstreamHandle` in `mcpdef-transport`. Every request goes out under a
  private id, and its reply comes back under the caller's own, so replies may
  arrive in any order. A reply that arrives after its call timed out is
  dropped, never taken as another call's. Upstream notifications are kept for
  subscribers, which the coming `list_changed` support uses.
  - A Streamable-HTTP upstream takes each call's POST directly, many at once.
  - A stdio, SSE-bridge or wasm upstream has one connection, so a task owns it
    and passes calls through in turn. That hand-off costs about 30–65 µs per
    call in the benchmark.
- **Upstreams are supervised.** Each has a health: `starting`, `up`, `degraded`
  (open, but its last call failed) or `down`. One that goes down is started
  again, 0.5 s later at first and every 10 s at the slowest. Down means a stdio
  server's process exited, an SSE stream ended, a Streamable-HTTP server ended
  the session (`404` on its `Mcp-Session-Id`), or 5 calls in a row to an HTTP
  upstream failed or timed out. A restart runs the handshake, lists the tools,
  checks them against the pins and routes calls to them, all again. Each time an
  upstream goes down or comes back, the ledger records it (`kind = "upstream"`,
  `method` `down` or `up`, `agent` `mcpdef`). `/api/v1/servers` gains each
  server's `health`, `restarts` and `last_error`, `/api/v1/status` gains
  `upstreams_up`, `/metrics` gains `mcpdef_upstream_up{server}` and
  `mcpdef_upstream_restarts_total{server}`, and the status UI shows them.
- **Hot reload.** `kill -HUP` makes a running gateway read its config again and
  apply it. With `[gateway] watch_config = true` it also does so whenever the
  config, or a file it names (a `jwks` file, a wasm module), changes. It checks
  every 30 s and compares content, so it also sees a Kubernetes ConfigMap
  update, which swaps a symlink rather than writing the file.
  - **Whole or not at all.** A config that does not parse or validate is
    refused as `invalid-config`. One that changes `listen`, `allowed_origins`,
    `max_inflight`, `wire`, the ledger path, `[gateway.admin]` or
    `[gateway.auth]` is refused as `restart-required`. Either way the gateway
    keeps serving the config it had.
  - **What applies.** Everything else, as one step for every call that starts
    after it: allowlists, profiles, rules, roles, rate limits, the timeout,
    inspection, egress and the pin store. Upstreams are matched by `id`. An
    added one opens before the new config takes effect. A removed one finishes
    its calls, then closes. A changed one opens a new connection before its old
    one drains, and keeps serving on the old one if its new settings do not
    start.
  - **No call in flight is dropped.** Each finishes under the config it started
    with.
  - **Audited.** Every reload, applied or refused, is a ledger record:
    `kind = "reload"`, `actor` `sighup` or `watch`, and the digests of the
    config before and after.
  - The admin API and `mcpdef_upstreams` follow the reload. After `mcpdef pin`
    re-approves a tool, a `SIGHUP` lets it back in without a restart.
- **`[[server]] max_inflight`**: the most calls that may wait on an upstream at
  once. The default is 16, or 1 for `wasm` and `wasm-component`. A call over
  the cap waits for a slot, and the wait counts against `upstream_timeout_ms`.
  `mcpdef validate` rejects `0`.
- **TLS profiles for HTTPS upstreams and the `jwks_uri`.**
  `[gateway.upstream_tls]` is the profile of every HTTPS upstream and of the
  gateway's own fetches; a server's `[server.tls]` goes over it key by key.
  With neither, nothing changes: an upstream is verified against Mozilla's
  roots, bundled into the binary. A profile sets:
  - `roots`: `bundled`, `system` (the host's store, which honours
    `SSL_CERT_FILE` and `SSL_CERT_DIR`) or `both`; and `ca`, more roots, for a
    private CA;
  - `crl`: CRLs, checked for every certificate in the upstream's chain;
  - `min_version`: `"1.2"` or `"1.3"`;
  - `client_cert` and `client_key`: a client certificate for mTLS, presented
    whichever roots verified the server. The key is a secret, from a file, a
    variable, a command or the config (see "Secret references" below);
  - `connect_to`, for one server: an address to dial for the URL's host. The
    egress guard judges it like a resolved address, so `169.254.169.254` is
    refused, and the certificate is still checked against the host's name;
  - `insecure_skip_verify`, for one server: warned about at startup and by
    `mcpdef validate`, and every connection opened with it is audited as
    `kind = "upstream"`, `method = "connect"`, `rule = "tls-verify-disabled"`.

  Every file is PEM. A PKCS#12 or DER file, or an encrypted key, is refused
  with the `openssl` command that fixes it, and `mcpdef validate` reads every
  file a table names. An unknown key in either table fails the config. The
  files are read at each connection, and a reload reconnects the upstreams
  whose files changed, so a certificate renewed in place is picked up without
  a restart. The binary grows by 87,648 bytes (0.8 %).
- **SPKI pins, for a self-signed upstream.** `[server.tls] pin_sha256 = ["…"]`
  trusts an upstream by its key alone. The certificate's issuer, names and
  dates are not checked, and a certificate renewed on the same key keeps its
  pin. The server still has to sign the handshake with the pinned key, so a
  copy of its certificate is refused. `mcpdef tls pin <url>` prints the pin
  of the certificate a server presents, fetched through the egress guard, as
  a line to paste into `[server.tls]`, with the certificate's SHA-256
  fingerprint to check it by. A pin is refused in `[gateway.upstream_tls]`,
  and beside `roots`, `ca`, `crl` or `insecure_skip_verify` in a server's
  table.
- **Each HTTPS upstream's certificate, on the admin API and in `/metrics`.**
  `/api/v1/servers` gives an HTTPS upstream that has opened a `tls` object:
  - `verify`: how its certificate was checked, `ca`, `pin` or `disabled`;
  - `fingerprint`: the SHA-256 of the certificate its server presented last,
    as `openssl x509 -fingerprint -sha256` prints it;
  - `not_after`: when that certificate expires, in RFC 3339.

  `/metrics` gains `mcpdef_upstream_cert_expiry_seconds{server}`, the same
  expiry as a Unix time, for an alert on
  `mcpdef_upstream_cert_expiry_seconds - time()`. A plain-HTTP, stdio or
  sandboxed upstream has neither. The certificate is taken from each response,
  so a renewed one shows once a new connection makes a full handshake.
  `mcpdef egress show` now also prints the TLS profile each HTTPS upstream is
  verified with, and the gateway's own. The binary grows by 13,680 bytes
  (0.1 %).
- **Secret references.** A setting that takes a secret, `client_key` and each
  value of a stdio server's `[server.env]`, takes it from a file,
  `{ file = "…" }`, from a variable of MCPdef's own
  environment, `{ env = "NAME" }`, from what a command writes,
  `{ exec = ["command", "argument", …] }`, or as the value itself, written as a
  string. `docs/CONFIG.md` has a section on them, with SOPS, 1Password and
  Vault commands.
  - A secret is read when it is needed: a client key at each connection, and a
    `[server.env]` value each time its server starts, a restart included. So a
    file rotated in place is read afresh. A file has to be a regular file of
    UTF-8 text of at most 64 KiB. One line ending at its end is not part of the
    value.
  - `[server.env]` strings still work: a string is the value itself. A reload
    that finds a file a value is read from changed starts that server again. A
    value that cannot be read leaves its server down, with an error that names
    the variable and where its value comes from. A name that is empty or holds
    `=` is refused.
  - A secret written in the config is warned about at startup and by
    `mcpdef validate`: a client key written as a string, and a `[server.env]`
    string whose name ends like `TOKEN`, `PASSWORD` or `KEY`, or whose value has
    the shape of a known credential.
  - A secret file that users other than its owner can read is warned about at
    startup and by `mcpdef validate`. A file root owns may be readable by its
    group when, on Linux, MCPdef does not run as root, since that group is how
    MCPdef reads it: a Kubernetes Secret volume with `defaultMode: 0400` under
    the pod's `fsGroup`, or a key in Debian's `ssl-cert` group, much as
    PostgreSQL judges its key file.
  - A variable a secret is read from is withheld from every stdio upstream,
    which otherwise inherits MCPdef's environment, unless its `[server.env]`
    sets it.
  - A command runs with no shell, and with nothing on its standard input. Its
    error output is thrown away. It has 5 s to write at most 64 KiB and exit
    with status 0, and is killed if it runs over. An error names its program
    alone, never its arguments or what it wrote. MCPdef reads the key it writes
    on a thread kept for blocking work, so a slow command holds up nothing
    else.
  - No error, warning or debug output prints a secret's value: each names where
    the value comes from. So do `mcpdef servers list` and `/api/v1/servers`,
    which now show where each `[server.env]` value comes from. The memory MCPdef
    reads a secret into is wiped when it is done with it. For a client key, that
    is the key as read, the PEM handed to the HTTP client, and the key kept for
    new connections.

  The new `mcpdef-secrets` crate does the reading. It adds one package,
  `secrecy`; `zeroize` was linked already. The binary grows by 12,768 bytes
  (0.1 %) for secrets, by 24,368 (0.2 %) more for commands, and by 32,320
  (0.3 %) more for `[server.env]`.
- **Credentials towards an HTTP upstream: `[server.auth]`.** MCPdef adds a
  header to every request it sends to a `streamable-http` or `sse` upstream:
  `kind = "bearer"` with a `token`, `"header"` with a `name` and a `value`, or
  `"basic"` with a `username` and a `password`. Each secret is a secret
  reference. The client's own credentials are still never passed through.
  - The secret is read when the upstream is opened. When the upstream answers
    `401`, it is read again, once for however many requests were refused at
    once, and a request goes once more only if that changed it. A second `401`
    fails the call closed, audited as `upstream-auth-failed`. So a token
    rotated in its file is picked up without a restart.
  - The header goes out marked sensitive. `servers list` and `/api/v1/servers`
    show the kind and where the secret comes from, never the secret.
  - `mcpdef validate` refuses a field the kind lacks or does not take, a
    header HTTP, MCP's transport or a proxy sets (`Host`, `Content-*`,
    `Mcp-*`, `Proxy-*` and the like), and `[server.auth]` on a server that is
    not an HTTP one. Credentials over plain `http://` to another machine are
    warned about.
  - Any `401` from an upstream is now an error of its own: before, a call got
    `upstream-error`, and now `upstream-auth-failed`. The binary grows by
    41,248 bytes (0.4 %).
- **A token by the OAuth client credentials grant: `[server.auth] kind =
  "oauth2"`.** MCPdef asks an authorization server's `token_url` for an access
  token, as the client `client_id` with its `client_secret` (a secret
  reference), and sends it to the upstream as a bearer. `scopes` go as the
  `scope`, and RFC 8707's `resource` is the upstream's `url`, less any user
  info, query and fragment, unless `resource` names another, or none with
  `""`: the credentials a `url` holds never go to the token endpoint. The
  secret goes by HTTP Basic, or in the body with
  `client_auth = "client_secret_post"`.
  - A token is fetched when the first request needs one, and sent until 30 s
    before it expires, or for the first half of a life shorter than a minute.
    Requests that need one at once share one fetch: 50 calls fetch one token.
  - A `401` fetches a fresh token, once for however many requests were
    refused at once, and the request goes once more with it. A second `401`
    fails the call closed as `upstream-auth-failed`.
  - The token endpoint is reached as a `jwks_uri` is: through the egress
    guard, verified with `[gateway.upstream_tls]`, with no redirect followed
    and 10 s for the whole of it. The client secret is read at each fetch.
  - With no token to send, nothing is sent upstream: the call fails closed,
    audited under a new rule, `credentials-unavailable`, with the token
    endpoint's status and `error` code, never its `error_description`. So does
    a `bearer`, `header` or `basic` secret that cannot be read again after a
    `401`, which was `upstream-error`.
  - `mcpdef validate` checks the fields: a `token_url` with a user name, a
    password or a fragment, an unknown `client_auth`, a scope with a space, a
    `resource` that is not an absolute URI. A client secret written in the
    config, and one sent over plain `http://` to another machine, are warned
    about. `servers list` and `/api/v1/servers` show the token endpoint and
    where the secret comes from.

  The binary grows by 24,672 bytes (0.2 %), and no package is added.
- **Strict mode: `[gateway] strict = true`, and `mcpdef validate --strict`.**
  Every warning becomes an error, reported as `strict: <the warning>`: a secret
  written in the config, a secret file others can read,
  `insecure_skip_verify = true`, and credentials sent over plain `http://` to
  another machine.
  - `mcpdef validate` fails on such a config. `--strict` checks a config so
    whatever its `strict` says: a CI gate. It reads no `[server.env]` or
    `[server.auth]` secret, so CI needs none of those. It reads the TLS files
    and client keys, as `validate` does.
  - The gateway does not start with it, and a reload to it is refused as
    `invalid-config` while the gateway keeps serving the config it had.
  - An upstream that does not open at startup fails the start, where the
    gateway would otherwise start without it and keep trying it.
  - The ready line says ` · strict`.

  A test runs a strict gateway in front of two stdio servers given API keys, one
  from a variable and one from a file, and an `oauth2` upstream reached over
  mTLS on a private CA, and finds none of their secrets in the ledger, the log,
  the admin API, `/metrics` or `servers list`. The example config,
  `mcpdef.example.toml`, passes `mcpdef validate --strict`, and a test keeps it
  so. The binary grows by 2,384 bytes, and by 5,440 more for the checks of a
  server's `url` and `command` below: 7,824 together (0.07 %).
- **How the credentials sent to each upstream fare, on the admin API and in
  `/metrics`.** For a server with `[server.auth]`, `/api/v1/servers` gains
  `credential`:
  - `last_ok`, `{ at_unix_ms }`: the last time the upstream answered a request
    that carried them;
  - `last_error`, `{ message, at_unix_ms }`: the last time it refused them, or
    MCPdef had none to send, and why;
  - `expires_at`: when the credentials it is sent now expire, in RFC 3339, an
    `oauth2` token's. A token is fetched when a request needs one, so an
    upstream no one calls holds one that has expired.

  An HTTPS upstream's `tls` gains `client_not_after`: when the certificate
  MCPdef presents to it (`client_cert`) expires. `/metrics` gains
  `mcpdef_upstream_auth_failures_total{server}`, the refusals and the times
  there was nothing to send, and `mcpdef_credential_expiry_seconds{server,credential}`,
  with `credential="token"` or `"client_cert"`, for an alert on
  `mcpdef_credential_expiry_seconds{credential="client_cert"} - time()`. The
  status page shows how each upstream's credentials fare under its health.
  A call answered by an upstream sent credentials costs a clock read, 27 ns.
  The binary grows by 13,696 bytes (0.13 %), 5,376 of them for masking URLs
  (below).
- **The Helm chart mounts secrets and certificates, and can leave config changes
  to the gateway.** New values:
  - `extraVolumes` and `extraVolumeMounts`: a Kubernetes Secret whose files the
    config reads with `{ file = … }`, or the CA, client certificate and key of a
    TLS profile;
  - `env` and `envFrom`: variables for the gateway, such as a secret the
    config reads with `{ env = … }`;
  - `rolloutOnConfigChange`, `true` by default: the `checksum/config`
    annotation that rolls the pods when `config` changes, as before. `false`
    leaves a change to `[gateway] watch_config`, which applies it without a
    restart.

  `docs/DEPLOY.md` gains sections on secrets from mounted files, TLS towards
  upstreams, and changing the config, and the Compose file shows how to mount
  secrets and certificates.

### Security
- **A secret a URL holds is masked wherever the URL is shown**: the log, the
  text of a call's error, the error a command exits with, `last_error` and
  `url` on `/api/v1/servers`, an `oauth2` token endpoint in `servers list`
  and `/api/v1/servers`, `egress show`, `validate`'s errors, and a reload
  refused for a config that does not parse, whose error quotes the line.
  Its user name and password, a path segment with a known credential's
  shape, and a query or fragment parameter that is a secret by its name or
  its shape show as `***`: `https://***:***@mcp.internal/mcp?api_key=***`.
  A credential's shape anywhere else leaves only the URL's scheme shown.
  Before, an error that named an upstream's URL, such as a refusal or a
  connection error, showed whatever it held.
- **A secret in a server's `url` or `command` is warned about**, and refused
  in strict mode: a URL that holds a password, a query parameter that is a
  secret by its name (`?api_key=`, `?access_token=`) or its shape, or a known
  credential's shape anywhere; and a command argument with a known
  credential's shape, which any user of the machine can read in the process
  list. The warning never repeats the secret.
- **An HTTP client that disconnected mid-call left no audit record.** The
  listener dropped the call when the client went away, after the upstream had
  already been asked to run the tool, so the tool ran and the ledger never
  said so. A call now runs to its end even when its client leaves first: its
  record is written once the upstream answers, and it keeps its
  `[gateway] max_inflight` slot until then. 0.2.2 has the same fix.
- **A crafted name could hide an edit to its own ledger record.** A record's
  hash joins its fields with U+001F. When a caller put that character in a tool
  or method name, someone able to edit the ledger could re-split that one
  record, turning a denied call into an allowed one, without breaking the chain.
  Other records were never exposed. The ledger now stores U+001F as `␟`
  (U+241F), and `mcpdef audit verify` names any existing record that holds one.
  0.2.2 has the same fix.
- **A crafted method could forge a syslog record's structured data.** The syslog
  export used the JSON-RPC method, which the client chooses, as the RFC 5424
  MSGID with only CR/LF removed. A method holding a space and a bracketed element
  became the structured data a SIEM parses, and the real `mcpdef@0` element fell
  into the message text. The MSGID is now at most 32 printable US-ASCII
  characters, with anything else as `_`; the full method stays in the message.
  0.2.2 has the same fix.
- **A deny pattern with a `*` inside it or at both ends denied nothing.** Glob
  patterns honoured `*` only as their first or last character.
  `deny = ["*delete*"]` compared each tool name against the literal prefix
  `*delete`, which no tool has, so on a server with no `tools` allowlist every
  delete tool stayed callable. `mcpdef validate` accepted the pattern. The same
  matcher serves profiles, `[[role]]` grants and `[[policy]]` rules, so a deny
  rule such as `tools = ["*admin*"]` never fired either.

  `*` now matches any run of characters, anywhere in a pattern, any number of
  times. `?` and `[` still match only themselves. Allow-side patterns change
  too: an allowlist entry, grant or `allow` rule written this way used to match
  nothing and now matches what it names. Review deny lists, grants and rules
  written for 0.2.1 or earlier. `docs/CONFIG.md` now documents the syntax.
  0.2.2 has the same fix.
- **A bearer token whose `nbf` was not a number was accepted before its
  time.** jsonwebtoken 9, the JWT library, reads a time claim of the wrong JSON
  type as absent, and skips the check of an absent `nbf` (CVE-2026-25537,
  GHSA-h395-gr6q-cpjc). A token not valid until tomorrow that gave its `nbf` as
  a string was accepted today. Only the configured issuer could sign one. A
  string `exp` was refused already, as a missing one is.

  `exp` and `nbf` must now be JSON numbers: a token that gives either as a
  string, `null` or anything else gets `401`, as does one whose `nbf` is too
  large for the library to read, which it passed over the same way. A time may
  still carry a fraction of a second, as RFC 7519 allows. An identity provider
  that writes either claim as a string must write a number instead. 0.2.2 has
  the same fix.

### Changed
- **The HTTP listener checks which revision a request speaks.** On the default
  `wire = "legacy"`, a request carrying `io.modelcontextprotocol/protocolVersion`
  in `params._meta` — as every 2026-07-28 request does — is now refused with
  `400` + `-32022` (`data.supported: ["2025-11-25"]`); earlier releases passed it
  to the gateway without looking at its `_meta` or headers. Set `wire = "dual"` to
  serve it. Other requests are handled as before, except `server/discover`, which
  is no longer forwarded to the first upstream.
- **An upstream that refuses the handshake is reported, not read as empty.** A
  JSON-RPC error in reply to `initialize` or `tools/list` fails the upstream's
  opening, naming its error code and message: the upstream starts down and is
  retried (see below), and `mcpdef pin` and `mcpdef diff-tools` fail.
  Previously the `initialize` reply was ignored and a refused `tools/list` read
  as an empty tool list, so the gateway could come up offering nothing from
  that server without saying why.
- **`transport = "streamable-http"` reads the JSON-RPC body of a `400`, `404` or
  `405` instead of dropping it.** On the opening request, such a reply carrying
  `-32601`, `-32020` or `-32022` identifies a Streamable HTTP endpoint, so MCPdef
  no longer falls back to the 2024-11-05 SSE bridge for it and reports what the
  server said; a reply with no JSON-RPC body (a framework's HTML `404`, say) still
  falls back as before. Once connected, a JSON-RPC error in such a reply reaches
  the client as the upstream's answer instead of becoming a transport error (a
  `500` "gateway error" on the HTTP listener).
- **`mcpdef version`** no longer says MCPdef is "planning the stateless
  2026-07-28 RC": it reports 2025-11-25 as the default and 2026-07-28 as
  available via `[gateway] wire` / `[[server]] spec`. The README drops the
  release-candidate wording the same way.
- **`SIGHUP` reloads the config** instead of ending the process. Stop the
  gateway with `SIGTERM` or `SIGINT`.
- **A `jwks_uri` refresh follows a reload.** It goes out with the
  `[gateway.egress]` and `[gateway.upstream_tls]` in force when it runs. It
  used to keep the egress policy the gateway started with.
- **API for TLS profiles.** `mcpdef-transport`: `TlsSettings`, read with `load`
  or checked with `check`, the `TlsProfile` it makes, `Roots`, `MinVersion`,
  `IdentityFiles`, `HttpClient::with_tls` and `with_connect_to`,
  `check_connect_to` and `TransportError::Tls`. `fetch_text` takes a
  `&TlsProfile`: `TlsProfile::default()` is the bundled roots it always used.
  `mcpdef`: `Config::upstream_tls` and `warnings`, `GatewayConfig::upstream_tls`
  and `fetch_tls`, `ServerConfig::tls`, `is_https` and `connect_to`,
  `UpstreamOptions::tls_verify_disabled`, `listener::Fetching` and
  `JwksRefresher::following`. `connect::supervised` takes the `Config`, and
  `build_transport` a `&TlsSettings`. `mcpdef-audit`: `Attrs::rule`, the rule
  of an allowed record. For pins, `mcpdef-transport` adds `Pin`,
  `presented_certificate` with `PresentedCertificate`,
  `TlsSettings::pin_sha256` and `TlsProfile::is_pinned`.
- **API for upstream certificates.** `mcpdef-transport`: `Transport::tls`, a
  provided method that returns `None`, and for an HTTPS `HttpClient` the
  `TlsWatch` its responses keep; `PeerCertificate`; `Verification`, which
  `TlsSettings::verification` and `TlsProfile::verification` return.
  `mcpdef`: `UpstreamStatus` gains a `tls` field, a `TlsStatus`, so code that
  builds one with a struct literal must set it.
- **API for secrets.** `mcpdef-secrets` is new: `SecretRef`, `SecretError`
  with `ExecProblem`, `MAX_FILE_BYTES`, `MAX_OUTPUT_BYTES`, `EXEC_TIMEOUT`,
  and `secrecy`'s `SecretString` and `ExposeSecret`.
  `mcpdef-transport`: `IdentityFiles::key` is a `SecretRef`, which a `PathBuf`
  converts into; `StdioChild::spawn_withholding` spawns a child with secret
  values, `SecretString`s, and without the variables it is given;
  `TlsSettings::load_async` loads a profile on a thread kept for blocking work.
  `mcpdef`: `TlsConfig::client_key` is an `Option<SecretRef>`;
  `ServerConfig::env` is a `BTreeMap<String, SecretRef>`, where it was a
  `HashMap<String, String>`, and `ServerConfig::env_files` lists the files it
  reads; `Config::secret_vars`; `connect::opener`, how to open a server as the
  config describes it; `build_transport` takes the variables to withhold;
  `ServerView::env`, where each variable's value comes from, as JSON.
  `mcpdef-inspect`: `secret_pattern`, the
  rule pack's credential shapes for text that is no tool's.
- **API for upstream credentials.** `mcpdef-transport`: `RequestAuth` gains
  `refresh`, which a `401` calls, with a default that refreshes nothing;
  `Credential` and `StaticAuth`, the static kinds; `ClientCredentials`,
  `ClientAuth` and `TokenAuth`, the `oauth2` kind; `read_secret`, a secret
  read on the blocking pool; `TransportError` gains
  `Unauthorized` and `Credentials`, and `CallError` gains `Unauthorized` and
  `NoCredentials`, so code that matches either exhaustively must name them.
  `mcpdef`: `ServerConfig::auth`, a `ServerAuth` of a `ServerAuthKind`, whose
  `credential` gives an `UpstreamAuth`; `ServerConfig::credentials`, with the
  server's `resource` filled in, `ServerConfig::cleartext_host` and
  `ServerConfig::fetches_tokens`; `ServerView::auth`; `build_transport`
  takes a `listener::Fetching`, how the gateway's own fetches go out, in
  place of the egress policy.
- **API for strict mode.** `mcpdef`: `GatewayConfig::strict`, and
  `Config::check`, which gives a `Checked`: what stops a config from running,
  and the warnings left to print.
- **API for credential health.** `mcpdef-transport`: `RequestAuth` gains
  `expires_at`, with a default of none, and `TokenAuth`'s says when its token
  expires; `Transport` gains `auth`; `TlsWatch::client_not_after`; `rfc3339`.
  `mcpdef`: `UpstreamStatus` gains `credential`, a `CredentialStatus` with a
  `LastOk`, and `auth_failures`; `TlsStatus` gains `client_not_after` and
  `client_not_after_unix`; `UpstreamOptions` gains `credentials`; and the
  `redact` module has `redact_url` and `redact_urls`. Code that builds any of
  these structs whole must set the new fields.
- **A reload prints the warnings of the config it applied**, as a start does.
- **One TLS stack: rustls on ring.** The binary installs ring as rustls' crypto
  provider when it starts, so every TLS connection it makes (to an HTTP
  upstream, to a `jwks_uri`) runs on ring whatever else a build contains. The
  dependency policy refuses `aws-lc-rs`, `aws-lc-sys`, `openssl-sys` and
  `native-tls`, and a second version of `rustls`. Nothing changes on the wire:
  the HTTP client already used ring.
- **reqwest 0.12.28 → 0.13.5**, the HTTP client that reaches HTTP upstreams and a
  `jwks_uri`. 0.12.28 was the last 0.12 release. Nothing changes on the wire:
  - an HTTPS upstream is still verified against Mozilla's root certificates,
    bundled into the binary, and never against the host's store (reqwest 0.13
    defaults to the host's store, and on a host that has none it cannot build a
    client at all, even for a plain-HTTP upstream);
  - TLS is still rustls on ring, over HTTP/1.1, with TLS 1.2 and 1.3.

  The binary grows by about 104 KB.
- **The crates declare their minimum Rust version, 1.88.** `cargo` refuses an
  older toolchain up front by naming MCPdef's own crates, where it used to name
  whichever dependency needed a newer Rust, and the published crates carry the
  floor. The workspace uses resolver 3, so `cargo update` passes over a
  dependency release that needs a newer Rust.
- **Calls run concurrently.** A slow upstream no longer holds up calls to the
  others. The HTTP listener no longer puts every request through one lock, and
  a stdio client's requests run at once too, up to 64, each answered as soon as
  it is done. In the benchmark, 19 fast upstreams beside one that answers in
  5 s keep their p99 (a ratio of about 1.0×, where it was 1,515× over HTTP and
  2,190× over stdio; at 200 clients, 0.95–1.03×, where it was 88× and 161×),
  and 16 concurrent clients add 0.7 ms to a call instead of 3.2 ms. One client
  alone sees no change. Large requests and replies to a stdio upstream can no
  longer deadlock its pipes: the gateway reads the upstream's replies while it
  writes.
- **An upstream that cannot start no longer stops the gateway.** Upstreams open
  at once, so startup takes about as long as the slowest rather than the sum.
  One that fails to open (a bad command, a refused connection, a rejected
  handshake, or longer than `upstream_timeout_ms`) starts down, is named in the
  log and on the ready line (`⚠ 1 down, retrying: '<id>'`), and is retried in
  the background. Startup used to fail. To be sure every upstream is up, watch
  `/api/v1/servers` or `mcpdef_upstream_up`.
- **A call to an upstream that is down, or that fails the call, is a tool error,
  and it is audited.** A call to an upstream that is down fails at once with
  `MCPdef error: upstream '<id>' is down (<why>); MCPdef is restarting it —
  retry shortly`, audited as `upstream-down`. A call the upstream could not take
  or answer (an HTTP error status with no JSON-RPC body, a refused connection, a
  sandbox trap) gets `MCPdef error: upstream '<id>' failed the call: <why>`,
  audited as `upstream-error`. Both used to be an HTTP `500` or a JSON-RPC error,
  with no audit record. A tool named in the `tools` of an upstream that has not
  started is that upstream's to fail, rather than an unknown tool.
- **On stdio, a request that fails at the gateway gets an error reply.** It is
  answered with JSON-RPC error `-32603` (`gateway error: …`), and the session
  goes on. The session used to end.
- **HTTP errors name their cause.** `error sending request for url (…)` now goes
  on to say why, such as a refused connection.
- **axum 0.7.9 → 0.8.9** under the HTTP listener and the admin server. No change
  on the MCP listener. One admin response changed: a malformed
  `/api/v1/audit?limit=` still gets a `400`, and its message now names the field
  (`limit: invalid digit found in string`).
- **`mcpdef-audit` API:** `Entry` gains `attrs: Attrs` (`Attrs::default()` for a
  plain call), `Record` gains the members above plus `extra`, and
  `VerifyReport` gains `ambiguous`. Code that builds these structs by name
  needs the new field.
- **The gateway appends audit records through a `LedgerHandle`.** This is a new
  `mcpdef-audit` type: a cloneable handle that many tasks can append through at
  once. Appends take turns on a first-in, first-out lock, so each record is
  still written before its call returns, in strict chain order, and a waiting
  append is never dropped. An append that has its turn always writes its
  record, even if its caller stops waiting. It adds no measurable latency to a
  call. `Gateway::audit_head` now returns a `String`.
- **`upstream_timeout_ms` covers the whole upstream call.** The bound used to
  start once the request was sent. Sending a Streamable-HTTP request waits for
  the whole reply, and sending to a wasm module runs it, so neither kind of
  call was ever timed out. The bound now covers waiting for a slot, sending,
  and waiting for the reply, and a slow call ends as an audited
  `upstream-timeout`.
- **A non-JSON-RPC line on a stdio upstream's stdout no longer fails a call.**
  It is dropped, with a warning on stderr. It used to fail whichever call was
  reading at the time.
- **A Streamable-HTTP answer is judged on its own.** Each POST carries one
  request, so the reply in its body can only be that request's:
  - an error reply under a null id, which is how a server answers a request it
    could not parse, now reaches the call instead of leaving it to time out;
  - an answer with no reply in it (a `202` for a request) fails the call at
    once, where before it waited out its timeout.
- **`mcpdef-transport` API:** `Transport` gains `replies_inline()`, `false` by
  default and `true` for the wasm transports, and `concurrent()`, which
  `HttpClient` answers with its Streamable-HTTP endpoint once opened. `recv`
  must now be cancel-safe; every transport in the workspace is. New:
  `UpstreamHandle` (with `spawn_with`, `HandleOptions`, `watch` and
  `DownWatch`, and `failures`), `CallError`, `DEFAULT_MAX_INFLIGHT`, the
  `Exchange` trait, `TransportError::SessionExpired`, and `RequestAuth` with
  `HttpClient::with_auth`, the hook upstream credentials will use, and
  `install_crypto_provider`. The transport's HTTP clients install ring as
  rustls' provider when no provider is installed, since reqwest 0.13 panics
  building a client without one; a process that builds a reqwest client of
  its own must install one first. **`mcpdef`
  API:** `Gateway` is a cheap cloneable handle, and `handle` and
  `handle_authed` take `&self`; the builder methods are unchanged.
  `serve_stdio` takes `&Gateway`. New: `Gateway::add_upstream_with`,
  `UpstreamOptions` (with `trip_after`), `Gateway::start_supervised` with
  `Supervised`, `Connect` and `Startup`, `Gateway::upstream_status` with
  `UpstreamStatus`, `HealthState` and `LastError`, `serve_stdio_on` and
  `STDIO_INFLIGHT`. `AdminState` gains `gateway`. For reloads:
  `Gateway::reconfigure` with `Reconfig`, `Planned`, `RateScope` and
  `Reconfigured`; the `reload` module (`Reloader`, `Snapshot`, `Trigger`,
  `Outcome`, `WATCH_INTERVAL`); and the `connect` module, which holds
  `build_gateway`, `build_transport` and `supervised`, formerly private to the
  binary. `Config` and its tables derive `Clone` and `PartialEq`, and gain
  `Config::load_text`, `Config::referenced_files`, `AuthConfig::jwks_file`,
  `ServerConfig::connection` and `ServerConfig::is_http`. `admin::server_views`
  is public, `AdminState::servers` is an `ArcSwap`, and `Metrics` gains
  `set_upstreams`. **`mcpdef-audit` API:** `Attrs` gains `config_from` and
  `config_to`. CEF carries them as `oldFileHash` and `fileHash`, OCSF in
  `unmapped`, syslog as SD params. **`mcpdef-policy` API:**
  `Policy::lists_tool`. The workspace gains the `arc-swap` crate.

### Fixed
- **The Compose file and the Helm chart name an image that exists.** Both named
  `mancube/mcpdef:0.2.1`, but a release's image is tagged as the release is,
  `v0.2.1`, so neither could pull it. The chart's image now defaults to `v` and
  its `appVersion`, and the Compose file names `v0.4.0-alpha.1`. 0.2.2 has the
  same fix.
- **`server/discover` and `tools/list` carry the caching hints 2026-07-28
  requires.** That revision makes `ttlMs` and `cacheScope` mandatory on a
  complete `server/discover` or `tools/list` result, and MCPdef sent neither.
  Both now say `ttlMs: 0`, which marks the result immediately stale: a governed
  tool surface can change at any moment (a pin drifts, an upstream goes away), so
  MCPdef promises no lifetime it cannot keep. Both also say
  `cacheScope: "private"`, so a shared cache never hands one caller's list to
  another. A `tools/list` gets the hints, plus the `resultType: "complete"` that
  revision requires on every result, only when it was sent on the 2026-07-28
  wire. A 2025-11-25 client's `tools/list` result is unchanged, byte for byte.
- **`transport = "streamable-http"` sends a 2025-11-25 upstream the
  `MCP-Protocol-Version` header.** That revision requires a client to send it on
  every request after `initialize`, naming the revision the handshake settled on.
  Earlier releases never did, which left the upstream to assume `2025-03-26`
  unless it could tell otherwise. MCPdef now repeats the version the server
  answered `initialize` with. `initialize` itself carries none, and the
  2024-11-05 SSE bridge, which predates the header, is unchanged.

### Spec support
- Built against MCP spec **2025-11-25**, still the default on both sides, and now
  also serves (`[gateway] wire`) and speaks (`[[server]] spec`) the stateless
  **2026-07-28** revision — published, no longer a release candidate. Not yet
  implemented from 2026-07-28: `Mcp-Param-{Name}` validation (inbound
  `Mcp-Param-*` headers are dropped, not forwarded), SSE responses,
  `subscriptions/listen`, MRTR (`InputRequiredResult`), caching hints and
  `resultType` on results relayed from a 2025-11-25 upstream, and `resultType` on
  the `tools/call` errors MCPdef writes itself. See `docs/WIRE.md`.

## [0.2.2] - 2026-09-28

Security release: fixes for five bugs in 0.2.1. Nothing is added, and the config
schema is unchanged.

### Upgrading from 0.2.1
- **A `*` inside a pattern now matches.** Review deny lists, `[[role]]` grants and
  `[[policy]]` rules written with one: a deny that denied nothing now denies, and
  an allow that allowed nothing now allows.
- **A bearer token must give `exp` and `nbf` as numbers**, or it gets `401`.
- **The ledger stores U+001F as `␟`.** A ledger written by 0.2.1 verifies
  unchanged.

### Security
- **An HTTP client that disconnected mid-call left no audit record.** The
  listener dropped the call when the client went away, after the upstream had
  already been asked to run the tool, so the tool ran and the ledger never
  said so. A call now runs to its end even when its client leaves first: its
  record is written once the upstream answers, and it keeps its
  `[gateway] max_inflight` slot until then.
- **A crafted name could hide an edit to its own ledger record.** A record's
  hash joins its fields with U+001F. When a caller put that character in a tool
  or method name, someone able to edit the ledger could re-split that one
  record, turning a denied call into an allowed one, without breaking the chain.
  Other records were never exposed. The ledger now stores U+001F as `␟`
  (U+241F), and `mcpdef audit verify` names any existing record that holds one.
- **A crafted method could forge a syslog record's structured data.** The syslog
  export used the JSON-RPC method, which the client chooses, as the RFC 5424
  MSGID with only CR/LF removed. A method holding a space and a bracketed element
  became the structured data a SIEM parses, and the real `mcpdef@0` element fell
  into the message text. The MSGID is now at most 32 printable US-ASCII
  characters, with anything else as `_`; the full method stays in the message.
- **A deny pattern with a `*` inside it or at both ends denied nothing.** Glob
  patterns honoured `*` only as their first or last character.
  `deny = ["*delete*"]` compared each tool name against the literal prefix
  `*delete`, which no tool has, so on a server with no `tools` allowlist every
  delete tool stayed callable. `mcpdef validate` accepted the pattern. The same
  matcher serves profiles, `[[role]]` grants and `[[policy]]` rules, so a deny
  rule such as `tools = ["*admin*"]` never fired either.

  `*` now matches any run of characters, anywhere in a pattern, any number of
  times. `?` and `[` still match only themselves. Allow-side patterns change
  too: an allowlist entry, grant or `allow` rule written this way used to match
  nothing and now matches what it names. Review deny lists, grants and rules
  written for 0.2.1 or earlier. `docs/CONFIG.md` now documents the syntax.
- **A bearer token whose `nbf` was not a number was accepted before its
  time.** jsonwebtoken 9, the JWT library, reads a time claim of the wrong JSON
  type as absent, and skips the check of an absent `nbf` (CVE-2026-25537,
  GHSA-h395-gr6q-cpjc). A token not valid until tomorrow that gave its `nbf` as
  a string was accepted today. Only the configured issuer could sign one. A
  string `exp` was refused already, as a missing one is.

  `exp` and `nbf` must now be JSON numbers: a token that gives either as a
  string, `null` or anything else gets `401`, as does one whose `nbf` is too
  large for the library to read, which it passed over the same way. A time may
  still carry a fraction of a second, as RFC 7519 allows. An identity provider
  that writes either claim as a string must write a number instead.

### Fixed
- **The Compose file and the Helm chart name an image that exists.** Both named
  `mancube/mcpdef:0.2.1`, but a release's image is tagged as the release is,
  `v0.2.1`, so neither could pull it. The chart's image now defaults to `v` and
  its `appVersion`, and the Compose file and the Makefile name `v0.2.2`.

### Changed
- **Dev and test builds carry line tables, not full debug info**
  (`[profile.dev]`), so each test binary is under half the size and the suite
  fits a CI runner's disk. `CARGO_PROFILE_DEV_DEBUG=true` brings full debug info
  back. Release builds are unchanged.

### Spec support
- Unchanged from 0.2.1: built against MCP spec **2025-11-25**.

## [0.2.1] - 2026-09-24

Maintenance release — **no engine source changes** since 0.2.0. The gateway's
behaviour, config schema, and audit format are unchanged.

### Added
- **Deployment assets**: a Helm chart (`deploy/helm/mcpdef`, with an optional
  `ServiceMonitor`), a Docker Compose stack (`deploy/compose`), a Grafana dashboard
  for the `/metrics` surface, and `docs/DEPLOY.md` deployment guidance.
- A developer `Makefile` (build / test / lint / image targets).

### Security
- Refreshed the dependency lockfile: Wasmtime/Cranelift `36.0.12` → `36.0.15`,
  `rustls` `0.23.41` → `0.23.45`, `rustls-webpki` `0.103.13` → `0.103.15`.

### Spec support
- Unchanged from 0.1.0: built against MCP spec **2025-11-25**, forward-planning the
  stateless **2026-07-28** RC.

## [0.2.0] - 2026-07-19

### Added
- **Native observability — `[gateway.admin]`** (off by default, a separate port
  from the MCP data path, no auth of its own). A read-only, self-served view of a
  running gateway:
  - `GET /metrics` — Prometheus: `mcpdef_tools_calls_total{server,tool,decision,rule}`,
    a call-latency histogram, `mcpdef_upstreams`, `mcpdef_uptime_seconds`. Native
    in-process counters incremented at the single audit chokepoint — every governed
    `tools/call` counted once, no log parsing.
  - `GET /api/v1/{status,servers,stats,audit}` — read-only JSON.
  - `GET /` — a built-in single-file status UI (embedded, no build step): fronted
    servers + effective allowlists, a live audit tail (allow/deny), and counters.

  This is the OSS "view it yourself" surface; the `ee/` dashboard remains the
  richer control plane. Zero new dependencies (reuses the axum/serde stack).

### Spec support
- Unchanged from 0.1.0: built against MCP spec **2025-11-25**, forward-planning the
  stateless **2026-07-28** RC.

## [0.1.0] - 2026-07-19

### Added
- **Policy-as-code rule engine** (`[[policy]]`, in `mcpdef-policy`). A richer gate
  than the static allowlist, evaluated *after* it: where the allowlist decides on
  the tool name alone, a policy rule matches on the **caller** (agent), **server**,
  **tool** (all globs), and the tool-call **arguments** (per-field predicates —
  `equals`/`glob`/`contains`/`exists`, over dotted paths). So a policy can express
  "deny `delete_*` on `github` when `args.name` is a `prod-*` repo" or "only
  `agent:ci-*` may call `deploy`". Rules are **first-match-wins** (a specific
  `allow` can precede a broad `deny`); no match is allow (the allowlist already
  gated). A denial is audited under the rule's own `name`, and a mis-typed effect
  or an argument predicate with no operator fails `mcpdef validate` (no silent
  fail-open). *(A `transform` effect — argument/result mutation — remains a
  follow-up.)*
- **Inline injection / secret-exfil scanning** (`[gateway.inspect]`, new
  `mcpdef-inspect` crate). A curated, dependency-free rule pack scans the two
  untrusted-content surfaces an in-path gateway straddles: tool **descriptions**
  (at connect — a "line-jumping" / tool-poisoning attempt hides the tool from
  `tools/list` and denies its `tools/call`) and tool-call **results** (per call —
  a response that leaks a credential or carries injected instructions is refused
  before it reaches the model). Detects prompt-injection phrasing and secret
  patterns (AWS/Slack/GitHub/Stripe keys, PEM private-key blocks). Three modes:
  `off` (default), `warn` (audit/log findings only), `enforce` (hide/deny); a
  finding is audited under a new `injection` / `secret-exfil` rule. Opt-in and
  high-precision to keep false positives low. Operators can extend the built-in
  pack via `[gateway.inspect]` — `injection_phrases` (case-insensitive) and
  `secret_substrings` (case-sensitive, e.g. an internal token prefix). *(Regex-based
  rule packs remain a follow-up.)*

### Security / hardening
- **JWKS rotation without a restart.** The OAuth 2.1 Resource Server loaded the
  authorization server's signing keys once at startup, so a key rotation rejected
  every bearer until `mcpdef` was restarted. The verifier now holds the JWKS behind
  an `RwLock`, and on a token whose `kid` isn't cached the HTTP listener re-fetches
  the configured `jwks_uri` **once** (through the egress/SSRF guard), swaps in the
  rotated keys, and retries. Fail-closed throughout — a static (inline/file) JWKS,
  a rate-limited attempt, a failed fetch, or a malformed document all leave the
  request denied — and rate-limited to one re-fetch per 60s so a flood of
  bogus-`kid` tokens can't hammer the IdP. Inline/file JWKS stay static.
- **WASM sandbox runtime moved to the Wasmtime 36 LTS line (from 27).** Clears 18
  outstanding RustSec advisories against `wasmtime` / `wasmtime-wasi` 27 — several
  sandbox-relevant, notably a Winch sandbox-escape (RUSTSEC-2026-0095) and a
  shared-linear-memory unsoundness (RUSTSEC-2025-0118) — none of which had an
  in-place v27 patch. The component path is updated for the `wasmtime-wasi` 36 API
  (single-accessor `WasiView` → `WasiCtxView`, `p2::add_to_linker_async`,
  per-function async `bindgen!`); the capability-scoped WASI and the per-destination
  egress allowlist are unchanged, and the committed `wasm32-wasip2` fixture still
  loads. Declared **MSRV rises to 1.88** — the dependency-tree floor (Wasmtime 36
  needs 1.86, but `time` 0.3.x requires 1.88).
- **Core-module WASM sandbox calls run off the async worker.** `WasmUpstream` (the
  `transport = "wasm"` path) previously ran the synchronous `handle` inline on the
  Tokio worker, so a non-yielding, fuel/deadline-bound call could pin an executor
  thread and stall unrelated traffic. Each call now moves the (reused, stateful)
  instance onto the blocking pool and restores it afterward, so guest session state
  still persists across calls (consistent with the component path) while the
  synchronous execution no longer blocks an async worker. Guest memory growth from an
  `alloc`-only ABI remains bounded by the configured memory cap (`wasm_max_memory_mb`)
  — a guest that never reuses its buffer fails its own calls at the cap, never harming
  the host; a guest-side reset/free hook is a documented follow-up.
- **No HTTP-redirect SSRF bypass.** The egress-guarded HTTP clients now use
  `redirect(none)`, so a validated upstream (or a `jwks_uri`) cannot `3xx` to an
  unvalidated host (e.g. `169.254.169.254`) and have it dialed outside the guard.
- **JWT verification is pinned to the key family, not the header `alg`.** The
  verifier now explicitly rejects a token whose header algorithm doesn't match the
  selected JWK's key type (RSA vs EC), so the algorithm-confusion defense no longer
  depends implicitly on the JWT library's internal family check (the `none`/HMAC
  allow-list pre-check already stood).
- **Per-request audit identity.** The gateway computes the audit subject per
  request and threads it through, instead of storing it on the shared, long-lived
  `Gateway` — removing a latent path where one caller's identity could be recorded
  against a later request.
- **Explicit request-body cap** on the HTTP listener (`DefaultBodyLimit`, 2 MiB),
  so an unauthenticated client can't force a large allocation before auth/policy.
- **`servers list` no longer panics** on a multi-byte UTF-8 server/tool id
  (`truncate` now counts/splits by `char`, not byte).
- **SIEM export is injection-safe.** CEF/syslog renderers strip CR/LF from
  caller-controlled fields (e.g. a crafted tool name), so one audit record can't
  forge a second SIEM line (CWE-117).
- **Hardened egress blocks special-use IPs.** Multicast, documentation
  (`192.0.2/24`, `2001:db8::/32`), benchmarking (`198.18/15`), IETF-protocol, and
  reserved (`240/4`, `ff00::/8`) ranges are now always blocked — never valid
  upstreams — closing a gap where `hardened()` could dial them.
- **PRM challenge URL is trusted.** The `WWW-Authenticate` Protected Resource
  Metadata URL is now built from the configured `[gateway.auth] resource` origin,
  not the client-supplied `Host`/`X-Forwarded-Proto`, so a `401` can't advertise
  attacker-chosen metadata.
- **Atomic pin-store writes.** `PinStore::save` writes a temp file and renames
  over the target, so a crash mid-write can't corrupt the trust baseline.
- **`jwks_uri` fetch is time-bounded** (10s), so a silent server can't hang
  startup; the connect handshake honors the upstream timeout too.
- **Stricter config validation.** A sub-1 rate limit with no explicit burst (a
  bucket that admits no calls) and blank/whitespace `[gateway.auth]` fields are
  now rejected instead of silently accepted.
- **Rate limiting runs after authorization.** The `tools/call` rate-limit gate
  now sits after the allowlist/RBAC/rug-pull checks, so a flood of *denied* calls
  can't drain the per-tool/global buckets and starve authorized callers (the
  expensive upstream dispatch is still rate-bounded).
- **Unauthenticated HTTP can't rename audit identity.** On the shared HTTP
  listener, a client's `initialize`-supplied name no longer sets the audit
  identity used for other clients' records (it remains a stdio-only convenience).
- **JWKS fetch is fully bounded** — DNS resolution is now inside the fetch
  deadline, and the response body is read under a 2 MiB cap (no unbounded buffer).
- **Hardened egress blocks more IPv6 special-use ranges** — documentation
  (`3fff::/20`), benchmarking (`2001:2::/48`), SRv6 (`5f00::/16`), discard/dummy
  (`100::/48`), and local-use NAT64 (`64:ff9b:1::/48`); the global NAT64 prefix
  stays reachable.

### Added
- **In-path WASM sandbox** (Phase 4; new `mcpdef-sandbox` crate). An upstream can now
  be an **untrusted `.wasm` MCP server run in-process under Wasmtime** —
  `transport = "wasm"`, `wasm = "./server.wasm"` — behind the same `Transport`
  seam as a stdio or HTTP upstream, so the full governance path (allowlist, RBAC,
  rug-pull pinning, rate limiting, audit) applies unchanged. The module runs with
  **zero ambient capability**: it is instantiated against an **empty linker**, so
  it cannot touch the filesystem, network, or clock — a module that imports
  anything (e.g. WASI) fails to load, by design. Each call is bounded by a **fuel**
  budget (CPU; a runaway module traps `out of fuel` instead of spinning) and a
  **linear-memory ceiling** (`StoreLimits`), plus an **optional per-call wall-clock
  deadline** (Wasmtime **epoch interruption** + a background ticker — a call that
  runs too long traps even with fuel to spare; off by default, defense-in-depth on
  top of the fuel/CPU bound). All three are tunable per server via `wasm_fuel` /
  `wasm_max_memory_mb` / `wasm_deadline_ms`. The module speaks the gateway's normal
  MCP envelope over a deliberately tiny, no-WASI `alloc`/`handle` ABI (documented on
  the crate).
- **WASI component-model sandbox + egress allowlist** (Phase 4, the component path).
  An upstream can now be a **`wasm32-wasip2` component** (`transport = "wasm-component"`)
  that exports the new **`mcpdef:server` WIT world** (`handle(string) -> string`) — a
  typed MCP-over-component interface, so a sandboxed server can be written in any
  language that targets `wasm32-wasip2` (no hand-rolled memory ABI). It runs under a
  **capability-scoped WASI** (`wasmtime-wasi`) that grants **nothing by default**: no
  preopened directories (no filesystem), no inherited stdio. Its only possible host
  capability is **outbound TCP**, gated by a **per-destination egress allowlist**
  (`wasm_allow_egress = ["ip:port", …]`, default **deny-all**): a connection is
  permitted only if its resolved address is explicitly listed **and** passes the same
  IP classification as the HTTP egress guard (cloud-metadata / link-local /
  special-use are **always** blocked, even if mis-listed) — a host-fn networking gate
  via `WasiCtxBuilder::socket_addr_check`, reusing `mcpdef-transport`'s classifier
  (now exported as `check_socket_ip`). The same fuel / memory / epoch caps apply, and
  the full governance path (allowlist, RBAC, pinning, rate-limit, audit) is unchanged.
  *(WASI filesystem/clock grants and hostname egress with DNS-pinning are follow-ups;
  the allowlist is by resolved IP today, with DNS name lookup off.)*
- **CLI ergonomics: `mcpdef up` + `mcpdef call`.** `mcpdef up` is shorthand for
  `mcpdef run --http` (bring the gateway up on the Streamable HTTP listener — the
  shared-gateway shape). `mcpdef call <tool> [--args JSON] [--json]` is a one-shot
  client: it builds the same governed gateway, issues a single `tools/call`
  through it, prints the tool's text content (or the raw result with `--json`),
  and exits non-zero if a governance gate or the upstream returns an error. The
  allowlist/profile/pinning/rate-limit gates apply and the call is audited, so
  the output is what a live client would see — handy for demos and scripts. (RBAC
  is not enforced on this local path: it gates authenticated callers by token
  role, and `mcpdef call` carries no bearer.)
- **OAuth 2.1 termination + token broker + RBAC** (Phase 2; new `mcpdef-auth` crate).
  The HTTP listener can now require auth: with `[gateway.auth] enabled`, every
  `POST /mcp` must carry a valid `Authorization: Bearer <JWT>`, validated **per
  request** as an OAuth 2.1 **Resource Server** (MCP forbids session-based auth) —
  signature against the configured **JWKS** (inline/file `jwks` or an
  egress-guarded `jwks_uri` fetch), `aud == resource` (RFC 8707/9068),
  `iss == issuer`, and `exp`/`nbf`. Only **asymmetric** algorithms are accepted
  (RS/PS/ES); `none` and HMAC are refused to defeat the classic algorithm-confusion
  forgery. A missing/invalid token gets **`401`** with a `WWW-Authenticate`
  challenge pointing at the **RFC 9728 Protected Resource Metadata** document, now
  served at `GET /.well-known/oauth-protected-resource`, so a client can discover
  the authorization server. The validated subject (`sub`) becomes the **audit
  identity**. **RBAC** (`[[role]]`, new `mcpdef_policy::Rbac`) layers over the
  allowlist: a caller "holds" a role when its name is in the token's scopes/`roles`,
  and a `tools/call` is allowed only if a held role grants `"server:tool"` (glob);
  an RBAC denial is a tool-error result audited under rule `rbac`. **Token
  brokering**: a stdio upstream's credential is injected into the child process
  env via `[server.env]` (`StdioChild::spawn_with_env`) — MCPdef holds the upstream
  cred, and the client's bearer is never passed through. Auth applies to the HTTP
  listener only (stdio has no per-request transport identity; enabling it for a
  stdio run warns and is a no-op).
- **Downstream Streamable HTTP listener** (`mcpdef run --http`) — clients now reach
  the gateway over HTTP, not just stdio (the shared-gateway shape: point every
  agent at one endpoint, govern centrally). A `POST` to `/mcp` carries one
  JSON-RPC message; the gateway replies with a single `application/json` response
  or `202 Accepted` for a notification. Built **stateless-first** (no required
  `Mcp-Session-Id`), so it serves both the 2025-11-25 and 2026-07-28 wire models.
  Defenses: **Origin validation** (cross-site `Origin` → `403`, DNS-rebinding
  defense; loopback + no-Origin clients pass; extra origins via
  `[gateway] allowed_origins`), **loopback bind** by default, and an opt-in
  **in-flight load-shedding cap** (`[gateway] max_inflight` → `503` + `Retry-After`,
  the §5b connection-cap piece). `GET /mcp` → `405` (no server→client stream yet).
- **Availability controls** (ARCHITECTURE §5b — the in-path single-point-of-failure
  posture). A **token-bucket rate limiter** (new `mcpdef-ratelimit` crate) caps
  `tools/call` per-tool and gateway-wide; an over-limit call is shed with a
  tool-error result and a `rate-limited` audit event (the stdio analog of a `429`),
  before any policy/dispatch work. A **per-call upstream timeout**
  (`[gateway] upstream_timeout_ms`) fails a wedged upstream — audited as
  `upstream-timeout` — instead of letting it hang the gateway. Configured via
  `[gateway.rate_limit]` (`per_tool_per_sec`/`_burst`, `global_per_sec`/`_burst`).
  *(Connection caps + backpressure arrive with the downstream HTTP listener.)*
- **Signed release pipeline** ([`ops/release.yml`](./ops/release.yml), synced to the
  public mirror's `.github/workflows/release.yml`). A `v*` tag builds static-musl
  (`x86_64`/`aarch64`) + macOS (`x86_64`/`arm64`) `mcpdef` binaries, each with a
  `.sha256`, a **cosign** keyless signature, and a **SLSA build-provenance**
  attestation; generates a **CycloneDX SBOM**; publishes the GitHub release;
  publishes the OSS engine crates to crates.io **in dependency order** (`ee/` never
  published); bumps the Homebrew formula; and pushes a cosign-signed, SLSA-attested
  multi-arch distroless image. Pre-release (`-rc.N`) tags build + sign but skip
  crates.io / brew / `:latest`. Adds `Dockerfile`(.release), `RELEASING.md`,
  `docs/DOCKERHUB.md`, a `Formula/mcpdef.rb` placeholder, and version-pins the
  internal workspace deps so the workspace is crates.io-publishable.
- **Tool-definition pinning + rug-pull detection** (new `mcpdef-pin` crate). On
  connect, MCPdef hashes each tool's governed fields (name, description,
  inputSchema, outputSchema, **annotations** — pinned, not trusted, per spec) and
  compares against a persistent TOML pin store. Trust-on-first-use records unseen
  tools; a tool whose definition **drifts** after approval is hidden from
  `tools/list`, **denied** on `tools/call`, and audited with rule `rug-pull`.
  Enabled by `[gateway] pins = "…"`. New CLI: `mcpdef pin` (approve current defs)
  and `mcpdef diff-tools` (read-only drift report, exits non-zero on a rug-pull).
  The hash is canonical (recursively sorted keys), so benign field-order changes
  don't false-positive.
- **Egress / SSRF guard for HTTP upstreams** (`mcpdef-transport::egress`). Before
  dialing any HTTP upstream — and before POSTing to the URL a legacy HTTP+SSE
  server names in its `endpoint` event (an untrusted, server-controlled value) —
  MCPdef resolves the host and classifies every resolved IP. Cloud-metadata /
  link-local (`169.254/16`, `fe80::/10`) and the unspecified address are
  **always blocked**; private/loopback are allowed by default (MCPdef fronts
  internal servers) but can be blocked via `[gateway.egress] allow_private`;
  public destinations must use HTTPS by default (`require_https`). Validated IPs
  are **DNS-pinned** to defeat TOCTOU rebinding. Closes the standing SSRF TODO.
- `mcpdef egress show` — print the effective egress policy (OSS-ROLLOUT.md §6
  self-verification).
- **Named allowlist profiles** (`[profile.<name>]`). Define a reusable glob
  allow/deny set once and reference it from a server (`profile = "readonly"`;
  inline `tools` replaces, inline `deny` appends), or apply one gateway-wide as
  the **active profile** (`[gateway] profile` / `mcpdef run --profile <name>`) to
  scope the whole tool surface an agent sees — directly cutting the multi-server
  context/token tax. `servers list` now shows the resolved profile + active note.
- **Allowlist entries are now globs** (e.g. `get_*`, `list_*`), not just exact
  names — so a profile can scope a whole tool family in one line. (Exact names
  still match exactly; backward-compatible.)
- `mcpdef audit verify` — offline tamper-evidence check of the hash-linked audit
  ledger. Exits non-zero on a broken chain. With `--head` + `--count` it also
  checks against a seal recorded out-of-band, catching tail-truncation and
  wholesale-replacement that a plain chain check cannot.
- `mcpdef audit tail` — print the last N audit records in a SIEM-ready format:
  `json` (default), `ocsf` (OCSF "API Activity", class 6003), `cef`
  (ArcSight CEF:0), or `syslog` (RFC 5424). Local SIEM export ships in the OSS
  binary — it is never paywalled.
- `mcpdef servers list` — a config-level view of the governed servers and each
  server's configured allowlist / deny globs.
- `mcpdef-audit`: public `read_all` / `tail` read API over the ledger, an
  `ExportFormat` enum, and a `Record::export` formatter; a dependency-free
  RFC 3339 UTC timestamp formatter for the syslog shape.
- Phase-0 release scaffolding: root `LICENSE` (Apache-2.0), `ee/LICENSE`
  (BSL 1.1), `NOTICE`, `CONTRIBUTING.md` (DCO), `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, and SPDX headers on engine sources.

### Spec support
- Built against MCP spec revision **2025-11-25**; forward-planning the stateless
  **2026-07-28** release candidate behind a single transport abstraction.

## [0.1.0-alpha] — Phase 1 + 1.5 (internal pre-release)

### Added
- Transport-multiplexing reverse proxy fronting upstream MCP servers over
  **stdio**, **Streamable HTTP**, and the **legacy 2024-11-05 HTTP+SSE** bridge,
  including the dual-transport probe/fallback and `Last-Event-ID` resumption.
- Initialize / `tools/list` handshake; `tools/list` aggregation + allowlist
  filtering; deny-by-default allowlist enforcement on `tools/call` (a denial
  returns an `isError` tool result so the model can self-correct, and is audited).
- Append-only, hash-linked, tamper-evident **audit ledger** with offline
  `verify` / `verify_against`.
- Single declarative `mcpdef.toml` config; `mcpdef run` / `mcpdef validate` /
  `mcpdef version`.

[Unreleased]: https://github.com/lucheeseng827/mcpdef/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lucheeseng827/mcpdef/compare/v0.4.0-alpha.1...v0.4.0
[0.4.0-alpha.1]: https://github.com/lucheeseng827/mcpdef/compare/v0.2.1...v0.4.0-alpha.1
[0.2.2]: https://github.com/lucheeseng827/mcpdef/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/lucheeseng827/mcpdef/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/lucheeseng827/mcpdef/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lucheeseng827/mcpdef/releases/tag/v0.1.0
