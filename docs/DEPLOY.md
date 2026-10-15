<!-- SPDX-License-Identifier: Apache-2.0 -->
# Deploying mcpdef

`mcpdef` is one static binary. Run it on a VM with Docker/Podman, or on
Kubernetes with the bundled Helm chart. In both cases you provide one
`mcpdef.toml` declaring the MCP servers to front (see [CONFIG.md](./CONFIG.md)),
and the gateway serves clients over Streamable HTTP on `:7878` while the optional
admin listener (the console, its JSON API, and Prometheus `/metrics`) runs on
`:7879`.

> **Security defaults.** The admin listener signs people in only once you say
> how: at your identity provider ([SSO.md](./SSO.md)), by client certificate, or
> by a proxy in front that authenticates them. Until then it is never reachable
> off-host: compose binds it to loopback (`127.0.0.1`) only, the Helm chart
> leaves it **off** (`admin.enabled=false`), and a listener other machines reach
> with nothing to sign people in is refused unless `allow_unauthenticated =
> true` says a proxy does. Turn it on in the chart with `admin.enabled=true`
> **and** `[gateway.admin] enabled = true` in `config`. The gateway's
> listener is plain HTTP unless `[gateway.tls]` is set: serve TLS from it (see
> [HTTPS on the listener](#https-on-the-listener)) or from a proxy in front,
> and set `[gateway.auth]`, before exposing `:7878` beyond the host. A listener
> other machines reach with neither is warned about, and refused under
> `strict`. (Towards its upstreams it speaks TLS itself: see
> [TLS towards upstreams](#tls-towards-upstreams).)
> The audit ledger persists only if you give it a durable volume.

## On a cloud VM (Docker or Podman)

Files: [`deploy/compose/`](../deploy/compose).

```sh
cd deploy/compose
cp mcpdef.example.toml mcpdef.toml      # declare your MCP servers
docker compose up -d                    # or: podman-compose up -d
docker compose logs -f mcpdef           # "mcpdef X.Y.Z ready · N upstream(s) · audit … · listening …"
```

- Clients: `https://<vm-name>:7878/mcp` with `[gateway.tls]` set (see
  [HTTPS on the listener](#https-on-the-listener)), or `http://<vm-ip>:7878/mcp`
  behind your own TLS proxy.
- Admin UI / metrics: published to `127.0.0.1:7879` only — reach it over an SSH
  tunnel: `ssh -L 7879:127.0.0.1:7879 user@vm`, then open `http://localhost:7879`.
- The audit ledger lives in the `mcpdef-audit` named volume (persists across
  restarts). Back it up; it is your tamper-evident record. The volume belongs to
  the user the image runs as (65532), because `/var/lib/mcpdef` in the image
  does: mount a host directory there instead only once you have given it to
  that user (`sudo chown 65532:65532 <dir>`).

Upgrade: bump the `image:` tag in `compose.yaml` (a release's tag is its version
with a `v`: `v0.4.0`), `docker compose pull && docker compose up -d`.
State (the ledger) survives.

Secrets and certificates on a VM:

- **A secret** goes in a file, mounted with Compose's `secrets:` at
  `/run/secrets/<name>` (`compose.yaml` shows how), and `mcpdef.toml` reads it
  with `{ file = "/run/secrets/<name>" }`. The image runs as user 65532, so give
  the file to that user, readable by it alone: `sudo chown 65532:65532
  secrets/github-token && sudo chmod 600 secrets/github-token`. A variable
  (`environment:`, read with `{ env = "NAME" }`) works too.
- **Certificates** for [TLS towards upstreams](#tls-towards-upstreams) go in a
  directory mounted read-only, `./tls:/etc/mcpdef-tls:ro`, the key with the
  same owner and mode as a secret. So does the listener's own, for
  `[gateway.tls] mode = "files"`.
- **The local CA**, for `[gateway.tls] mode = "self-signed"`, is kept under
  `[gateway] state_dir`: point it at a volume (`state_dir =
  "/var/lib/mcpdef/state"`, on the `mcpdef-audit` volume) so that it outlives
  the container. A new container with no CA makes a new one, which every
  client then has to trust.
- **A config change** applies without a restart: `docker compose kill -s HUP
  mcpdef`, or `[gateway] watch_config = true` to have the gateway notice within
  30 s. A changed secret or certificate file is noticed the same way, and the
  upstream that reads it reconnects.

**The console behind single sign-on**, on one machine to try it:
[`deploy/compose/sso-saml/`](../deploy/compose/sso-saml) runs MCPdef with
Keycloak, its console signing people in at a Keycloak realm that brokers a
SAML identity provider ([SAML.md](./SAML.md)). `docker compose up -d` there,
and open `http://localhost:7879`.

## On Kubernetes (Helm)

Chart: [`deploy/helm/mcpdef`](../deploy/helm/mcpdef).

```sh
# from the repository root
helm install mcpdef ./deploy/helm/mcpdef \
  --namespace mcpdef --create-namespace \
  --set-file config=./my-mcpdef.toml      # your config (declares the upstreams)
```

Or edit `values.yaml`'s inline `config` and `helm install mcpdef ./deploy/helm/mcpdef -n mcpdef --create-namespace`.

Key values (`values.yaml`):

| Value | Default | Purpose |
|---|---|---|
| `image.repository` / `image.tag` | `mancube/mcpdef` / chart appVersion | the image |
| `config` | admin-disabled stub | the full `mcpdef.toml` (declare your servers here) |
| `admin.enabled` | `false` | publish the admin port (`:7879`: the console, its API, `/metrics`); also set `[gateway.admin] enabled = true` in `config`, and how people sign in ([below](#the-console-behind-single-sign-on)) |
| `persistence.enabled` | `false` | give the audit ledger a PVC (else emptyDir, lost on restart); requires `replicaCount: 1` (RWO, single-writer) |
| `serviceMonitor.enabled` | `false` | create a Prometheus-Operator ServiceMonitor for `/metrics` (requires `admin.enabled=true`) |
| `serviceMonitor.endpoint` | `{}` | added to the ServiceMonitor's endpoint as is: how Prometheus authenticates where the admin listener signs its callers in (`oauth2`, `tlsConfig`) |
| `service.type` | `ClusterIP` | expose via your own Ingress/LoadBalancer + TLS, or `[gateway.tls]` in `config` |
| `resources`, `replicaCount` | 1 replica | note: each replica keeps its **own** ledger; `persistence.enabled` pins this to 1 |
| `extraVolumes`, `extraVolumeMounts` | none | mount Kubernetes Secrets: files `config` reads with `{ file = … }`, and certificates for TLS towards upstreams |
| `env`, `envFrom` | none | variables for the gateway, such as secrets `config` reads with `{ env = … }` |
| `rolloutOnConfigChange` | `true` | roll the pods when `config` changes; `false` leaves a change to `[gateway] watch_config` |

Reach it:

```sh
# MCP endpoint (in-cluster): http://mcpdef.mcpdef.svc:7878/mcp
# the console + /metrics (only when admin.enabled=true):
kubectl -n mcpdef port-forward svc/mcpdef 7879:7879
#   → http://localhost:7879
```

### The console behind single sign-on

For people to reach the console from their browsers, sign them in at your
identity provider ([SSO.md](./SSO.md)) and serve it over https: an Ingress that
terminates TLS for the console's host, say, in front of the `admin` port.
`mcpdef sso init --provider <name> --issuer … --public-url https://<console host>`
prints the tables to add to `config`; the client's secret and the session key
come from a Secret:

```sh
kubectl -n mcpdef create secret generic mcpdef-console \
  --from-literal=client-secret='<from the identity provider>' \
  --from-literal=session-key="$(openssl rand -base64 32)"
```

```yaml
# values.yaml
admin:
  enabled: true
env:
  - name: MCPDEF_OIDC_CLIENT_SECRET
    valueFrom: { secretKeyRef: { name: mcpdef-console, key: client-secret } }
extraVolumes:
  - name: console
    secret: { secretName: mcpdef-console, defaultMode: 0400 }
extraVolumeMounts:
  - { name: console, mountPath: /run/secrets/mcpdef-console, readOnly: true }
config: |
  [gateway]
  listen = "0.0.0.0:7878"
  audit  = "/var/lib/mcpdef/audit.log"

  [gateway.admin]
  enabled = true
  listen = "0.0.0.0:7879"
  public_url = "https://mcpdef.example.com"    # the Ingress's host, as people reach it
  hosts = ["mcpdef"]                           # in-cluster scrapes by the Service's name

  [gateway.admin.session]
  key = { file = "/run/secrets/mcpdef-console/session-key" }

  # [gateway.admin.oidc] and [identity]: as `mcpdef sso init` prints them, with
  # client_secret = { env = "MCPDEF_OIDC_CLIENT_SECRET" }

  # [[server]] ...
```

The session key from the Secret keeps people signed in across a pod's
restart; a key the gateway makes for itself lives in its container and goes
with it. Behind an Ingress, the console takes the `public_url` origin as its
own: the browser's requests from it pass the cross-origin check though the
gateway itself speaks plain http to the Ingress. Give the Ingress the console's
host alone, not `/metrics`'s scrapers, and keep a break-glass token
([OPERATIONS.md](./OPERATIONS.md)) for when the identity provider is down.

### Secrets from mounted files

Keep every secret out of `config`, in a Kubernetes Secret, and have `config`
say where to read it. `mcpdef validate --strict` refuses a config that holds one
itself, and needs none of the secrets its servers are given to check that
(though it reads the TLS files and client keys the config names), so run it in
the pipeline that ships the chart.

```sh
kubectl -n mcpdef create secret generic mcpdef-secrets \
  --from-file=github-token=./github-token --from-file=client-secret=./client-secret
```

```yaml
# values.yaml
extraVolumes:
  - name: secrets
    secret:
      secretName: mcpdef-secrets
      defaultMode: 0400
extraVolumeMounts:
  - { name: secrets, mountPath: /run/secrets/mcpdef, readOnly: true }
config: |
  [gateway]
  strict = true
  # ...
  [[server]]
  id = "remote"
  transport = "streamable-http"
  url = "https://mcp.internal.example/mcp"
  [server.auth]
  kind = "oauth2"
  token_url = "https://idp.internal.example/oauth2/token"
  client_id = "mcpdef"
  client_secret = { file = "/run/secrets/mcpdef/client-secret" }
```

- **Mount the directory, not a `subPath`.** The kubelet replaces a Secret's
  files in place when the Secret changes; a `subPath` mount never sees that.
- **Set `defaultMode: 0400`.** The kubelet gives a Secret's files to root, and
  lets the pod's `fsGroup` (65532 here) read them too, so they end up `0440`.
  MCPdef reads them through that group, and accepts that: a file root owns may
  be readable by its group when MCPdef does not run as root. The default mode,
  `0644`, lets every user read them, which MCPdef warns about and strict mode
  refuses.
- **A variable** instead: `env` with a `secretKeyRef`, read with
  `{ env = "MCPDEF_GITHUB_TOKEN" }`. No stdio server the gateway starts
  inherits it. A variable is fixed for the pod's life, so a rotated secret
  needs the pods restarted; a file does not.
- **A command** (`{ exec = […] }`) needs its program in the image. The
  published image is distroless, with no shell and no tools: build on it to
  add one.
- **When each is read again.** A `[server.env]` value at each start of its
  server; a `[server.auth]` secret when the upstream answers `401`; an `oauth2`
  client secret at each token fetch. With `[gateway] watch_config = true`, a
  changed `[server.env]` file starts the server that reads it again, on its new
  value, within 30 s of the kubelet's update.

### TLS towards upstreams

An upstream on a private CA, or one that wants a client certificate, takes a
TLS profile: `[gateway.upstream_tls]` for every HTTPS upstream (and the
`jwks_uri` and OAuth token endpoint fetches), `[server.tls]` for one alone
(see [CONFIG.md](./CONFIG.md)). Its files come from a Secret like any other,
such as the one cert-manager keeps for a `Certificate`:

```yaml
extraVolumes:
  - name: upstream-tls
    secret:
      secretName: mcpdef-client-cert        # ca.crt, tls.crt, tls.key
      defaultMode: 0400
extraVolumeMounts:
  - { name: upstream-tls, mountPath: /etc/mcpdef-tls, readOnly: true }
config: |
  [gateway]
  watch_config = true                       # pick up a renewed certificate
  [gateway.upstream_tls]
  ca = ["/etc/mcpdef-tls/ca.crt"]
  # ...
  [[server]]
  id = "remote"
  transport = "streamable-http"
  url = "https://mcp.internal.example/mcp"
  [server.tls]
  client_cert = "/etc/mcpdef-tls/tls.crt"
  client_key = { file = "/etc/mcpdef-tls/tls.key" }
```

- **Renewal.** With `watch_config = true`, a certificate or key renewed in
  place is picked up within 30 s of the kubelet's update: the upstream opens a
  connection with it, and the old one closes after its last call. Without it,
  the next restart of the upstream, or of the pod, reads it.
- **Watch the expiries:** `mcpdef_credential_expiry_seconds{credential="client_cert"}`
  for the certificate MCPdef presents, and `mcpdef_upstream_cert_expiry_seconds`
  for the upstream's own, both Unix times. Alert on either less `time()`, as
  [OPERATIONS.md](./OPERATIONS.md#monitoring) shows.
- `kubectl -n mcpdef exec deploy/mcpdef -- mcpdef egress show --config
  /etc/mcpdef/mcpdef.toml` prints the profile each upstream is verified with.
- A self-signed upstream is pinned by its key (`pin_sha256`, which `mcpdef tls
  pin <url>` prints), never trusted by turning verification off:
  `insecure_skip_verify` is warned about, audited on every connection, and
  refused by strict mode.

### Changing the config

`helm upgrade` with a changed `config` rolls the pods by default
(`rolloutOnConfigChange: true`, a `checksum/config` annotation), so every change
applies, one only a restart can apply included.

To apply changes without a restart, and without dropping a call in flight, set
`rolloutOnConfigChange: false` and `[gateway] watch_config = true`: the gateway
reads the mounted ConfigMap within 30 s of the kubelet updating it, which can
itself take a minute or so, and applies it. A change only a restart can apply
(`listen`, `[gateway.auth]`, …) is refused, logged and audited, and the gateway
keeps serving the config it had until the pods next restart. See
[OPERATIONS.md](./OPERATIONS.md#reloading-the-config).

### Metrics & Grafana

Metrics live on the admin listener, so enable it first: `--set admin.enabled=true`
(and `[gateway.admin] enabled = true` in `config`). Keep it private.

- **Prometheus Operator**: `--set serviceMonitor.enabled=true` and Prometheus
  scrapes `mcpdef` `/metrics` automatically.
- **Plain Prometheus**: scrape the `admin` port —
  `static_configs: [{ targets: ["mcpdef.mcpdef.svc:7879"] }]`.
- **Where the admin listener signs its callers in**, `/metrics` answers only
  a caller it has signed in, Prometheus too: with a token your identity
  provider issues for `[gateway.admin.oidc] api_audience` with the
  `mcpdef:admin:read` scope, which Prometheus fetches itself by the client
  credentials grant (its `oauth2` scrape setting; in the chart,
  `serviceMonitor.endpoint.oauth2`, an example in `values.yaml`), or with a
  client certificate the listener maps to `console:viewer`.
- **Grafana**: import [`deploy/grafana/mcpdef-dashboard.json`](../deploy/grafana/mcpdef-dashboard.json)
  ("mcpdef — gateway governance": call rate by decision, denies by rule, calls by
  server, latency p50/p95, upstreams/uptime). It prompts for your Prometheus
  data source on import.

### Notes

- **Single replica by default.** Each replica keeps its own audit ledger and pin
  store (no cross-replica coordination in OSS), so scale out only if you
  aggregate the ledgers downstream. One replica serves calls concurrently: a
  slow upstream holds up no call to another.
- **Exposing it.** For traffic from outside the cluster, front `:7878` with an
  Ingress that terminates TLS, or have the gateway serve it with
  `[gateway.tls] mode = "files"` from a cert-manager Secret mounted with
  `extraVolumes` (a `LoadBalancer` Service passing TCP through), and enable
  `[gateway.auth]` (OAuth 2.1) in `config`. Do **not** expose `:7879` without
  a sign-in: the identity provider's (above), or an auth proxy's.

## HTTPS on the listener

`[gateway.tls]` puts the gateway's own listener on TLS, and the admin listener
with it unless `[gateway.admin.tls]` says otherwise. Two ways, detailed in
[CONFIG.md](./CONFIG.md#gatewaytls-and-gatewayadmintls--tls-on-mcpdefs-own-listeners)
and [OPERATIONS.md § Serving HTTPS](./OPERATIONS.md#serving-https):

- **`files`**: a certificate and key that cert-manager, certbot or your PKI
  writes, mounted read-only. With `[gateway] watch_config = true` the gateway
  serves a renewed pair within 30 s, with no restart.

  ```toml
  [gateway.tls]
  mode = "files"
  cert = "/etc/mcpdef-tls/tls.crt"
  key  = { file = "/etc/mcpdef-tls/tls.key" }
  ```

- **`self-signed`**: a local CA of MCPdef's own, for private networks. Run
  `mcpdef tls init` where the gateway runs (`docker compose run --rm mcpdef
  tls init --config /etc/mcpdef/mcpdef.toml`, with `state_dir` on a volume),
  and give each client the CA `mcpdef tls export-ca` prints. Clients that
  reach the gateway from the internet, such as Claude's custom connectors,
  need a publicly trusted certificate instead: `files`.

### Client certificates (mTLS)

`[gateway.tls.client_auth]` asks each client for a certificate and takes one
of its names as who the client is
([OPERATIONS.md § Client certificates](./OPERATIONS.md#client-certificates-mtls)).
Three shapes:

- **Your PKI or SPIRE.** Mount the CA bundle, or the trust bundle
  spiffe-helper writes, and the CRLs, read-only, and name them in `ca` and
  `crl`. With `watch_config`, a bundle or CRL written over in place applies
  within 30 s.
- **No PKI.** The local CA issues workloads their certificates, on the state
  volume: `docker compose run --rm mcpdef tls issue --client ci-bot --out
  /var/lib/mcpdef/clients --config /etc/mcpdef/mcpdef.toml`. Hand the
  workload `ci-bot.crt` and `ci-bot.key`; the command prints the `ca` and
  `crl` to add. `mcpdef tls revoke <serial>` takes one back, from the next
  reload.
- **Envoy or Istio in front**, terminating TLS. They check the certificates,
  and forward each one in a header that MCPdef reads from their addresses
  alone: set [`[gateway.trusted_proxy]`](./CONFIG.md#gatewaytrusted_proxy--a-proxy-that-terminates-tls-in-front),
  and keep the listener where only the proxy reaches it.

## Connecting clients

`mcpdef connect <client>` prints the entry each MCP client needs for this
gateway, in that client's own format and with how it trusts the CA:
`claude-code`, `claude-desktop`, `cursor`, `vscode`, `codex` or `generic`.
`--write` merges it into the client's file. Run it with the gateway's config,
and with `--url` when the client reaches the gateway by another address than
the config listens on. A client that cannot present a certificate, or trust a
private CA, runs `mcpdef bridge <url>` as its stdio server instead, which does
both for it; Claude Desktop's entry is one.

## Checking a deployment

`mcpdef doctor --config /etc/mcpdef/mcpdef.toml` checks the config, the
listeners' TLS, the identity provider's keys and clock, the admin listener's
exposure and every upstream, as `run` would open them, and keeps nothing a
running gateway keeps. It exits non-zero on a problem, so it works as a step
before a rollout: in compose, `docker compose run --rm mcpdef doctor --config
/etc/mcpdef/mcpdef.toml`; in Kubernetes, a Job or an init container with the
gateway's config and secrets mounted.

A worked end-to-end example (EKS + real MCP servers + Prometheus/Grafana) lives
in the monorepo lab; this chart + compose are the reusable, production-shaped
starting points.
