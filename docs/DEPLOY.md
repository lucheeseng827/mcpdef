<!-- SPDX-License-Identifier: Apache-2.0 -->
# Deploying mcpdef

`mcpdef` is one static binary. Run it on a VM with Docker/Podman, or on
Kubernetes with the bundled Helm chart. In both cases you provide one
`mcpdef.toml` declaring the MCP servers to front (see [CONFIG.md](./CONFIG.md)),
and the gateway serves clients over Streamable HTTP on `:7878` while the optional
read-only admin server (Prometheus `/metrics` + a status UI) runs on `:7879`.

> **Security defaults.** The admin server has **no auth of its own**, so it is
> never reachable off-host by default: compose binds it to loopback (`127.0.0.1`)
> only, and the Helm chart leaves it **off** (`admin.enabled=false`) — turn it on
> with `admin.enabled=true` **and** `[gateway.admin] enabled = true` in `config`,
> and keep it in-cluster / behind a NetworkPolicy or auth proxy. The binary has
> **no in-process TLS** — put a TLS-terminating reverse proxy (and `[gateway.auth]`)
> in front of `:7878` for internet exposure. The audit ledger persists only if you
> give it a durable volume.

## On a cloud VM (Docker or Podman)

Files: [`deploy/compose/`](../deploy/compose).

```sh
cd deploy/compose
cp mcpdef.example.toml mcpdef.toml      # declare your MCP servers
docker compose up -d                    # or: podman-compose up -d
docker compose logs -f mcpdef           # "mcpdef X.Y.Z ready · N upstream(s) · listening …"
```

- Clients: `http://<vm-ip>:7878/mcp` (front it with your own TLS proxy).
- Admin UI / metrics: published to `127.0.0.1:7879` only — reach it over an SSH
  tunnel: `ssh -L 7879:127.0.0.1:7879 user@vm`, then open `http://localhost:7879`.
- The audit ledger lives in the `mcpdef-audit` named volume (persists across
  restarts). Back it up; it is your tamper-evident record.

Upgrade: bump the `image:` tag in `compose.yaml`, `docker compose pull && docker
compose up -d`. State (the ledger) survives.

## On Kubernetes (Helm)

Chart: [`deploy/helm/mcpdef`](../deploy/helm/mcpdef).

```sh
# from module_58/
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
| `admin.enabled` | `false` | publish the unauthenticated admin/metrics port (`:7879`); also set `[gateway.admin] enabled = true` in `config` |
| `persistence.enabled` | `false` | give the audit ledger a PVC (else emptyDir, lost on restart); requires `replicaCount: 1` (RWO, single-writer) |
| `serviceMonitor.enabled` | `false` | create a Prometheus-Operator ServiceMonitor for `/metrics` (requires `admin.enabled=true`) |
| `service.type` | `ClusterIP` | expose via your own Ingress/LoadBalancer + TLS |
| `resources`, `replicaCount` | 1 replica | note: each replica keeps its **own** ledger; `persistence.enabled` pins this to 1 |

Reach it:

```sh
# MCP endpoint (in-cluster): http://mcpdef.mcpdef.svc:7878/mcp
# admin UI + /metrics (only when admin.enabled=true):
kubectl -n mcpdef port-forward svc/mcpdef 7879:7879
#   → http://localhost:7879
```

### Metrics & Grafana

Metrics live on the admin listener, so enable it first: `--set admin.enabled=true`
(and `[gateway.admin] enabled = true` in `config`). Keep it private.

- **Prometheus Operator**: `--set serviceMonitor.enabled=true` and Prometheus
  scrapes `mcpdef` `/metrics` automatically.
- **Plain Prometheus**: scrape the `admin` port —
  `static_configs: [{ targets: ["mcpdef.mcpdef.svc:7879"] }]`.
- **Grafana**: import [`deploy/grafana/mcpdef-dashboard.json`](../deploy/grafana/mcpdef-dashboard.json)
  ("mcpdef — gateway governance": call rate by decision, denies by rule, calls by
  server, latency p50/p95, upstreams/uptime). It prompts for your Prometheus
  data source on import.

### Notes

- **Single replica by default.** The gateway serialises upstream calls and each
  replica keeps its own audit ledger / pin store (no cross-replica coordination
  in OSS) — scale out only if you aggregate the ledgers downstream.
- **Exposing it.** For traffic from outside the cluster, front `:7878` with an
  Ingress that terminates TLS and enable `[gateway.auth]` (OAuth 2.1) in `config`.
  Do **not** expose `:7879` without an auth proxy.

A worked end-to-end example (EKS + real MCP servers + Prometheus/Grafana) lives
in the monorepo lab; this chart + compose are the reusable, production-shaped
starting points.
