<!-- SPDX-License-Identifier: Apache-2.0 -->
# MCPdef console

The console the gateway's admin listener serves at `/`: a Vite + React app built
on the MCPdef design system, bound to the admin API (`/api/v1`, see
[`../docs/API.md`](../docs/API.md#admin-listener-gatewayadmin)).

Six screens: **Overview · Audit log · Servers & tools · Policy · Inspect · Config**.
A screen whose data the gateway does not serve, or will not show the caller, says
so; the rest of the console carries on.

## Screenshots

The app running against the mock backend (all data fetched over `/api/v1`).

### Overview — health, allow/deny KPIs, deny-by-rule, recent denials
![Overview](docs/screenshots/overview.png)

### Audit log — filterable hash-linked ledger; row → hash-chain detail; Verify
![Audit log](docs/screenshots/audit-log.png)

### Servers & tools — status, pin state, poisoned/drift flags, resolved policy
![Servers & tools](docs/screenshots/servers.png)

<details>
<summary>Policy · Inspect · Config</summary>

**Policy** — ordered rules (first-match-wins), RBAC, profiles (read-only)
![Policy](docs/screenshots/policy.png)

**Inspect** — off/warn/enforce mode, rule packs, redacted findings
![Inspect](docs/screenshots/inspect.png)

**Config** — redacted effective config + paste-to-validate (`POST /config/validate`)
![Config](docs/screenshots/config.png)

</details>

## How it ships

```
 console/ (this app) ──npm run build──▶ crates/mcpdef-console/ ──▶ the mcpdef binary
   React + Vite                          assets/: each file, and its     admin listener
                                         brotli and gzip forms           serves it at /
                                         src/assets.rs: the table
```

`npm run build` runs `vite build` into `crates/mcpdef-console/assets/`, then
`scripts/embed.mjs` writes each text file's brotli and gzip forms beside it and
the table the crate serves them from. Both are committed, so building the
gateway, `cargo install` included, needs no Node. The build is reproducible: CI
builds again from the lockfile and fails on any difference.

The gateway serves `/` and `/assets/*` from that table: the encoding the client
prefers of those it has, an entity tag (`304` for a client that holds the file),
`immutable` for the hashed files under `/assets/`, and `no-cache` for the page.
A gateway built without its default `console` feature serves its small built-in
status page instead.

**Content security policy.** The admin listener sends
`default-src 'none'; script-src 'self'; style-src 'self'; …` with every answer.
So the page loads its script and styles as files, never inline; the design
system styles through React's `style` prop, which sets the CSSOM and which the
policy does not block; keyframes live in `src/ds/tokens/motion.css`; and no asset
is ever inlined as a `data:` URI (`assetsInlineLimit: 0`).

**Fonts.** IBM Plex Sans and Mono, latin, woff2, the weights the design system
uses, in `src/ds/fonts/` with their license (`OFL.txt`, SIL Open Font License
1.1). Another script falls back to the system's ui-sans and ui-mono.

## Develop it

```bash
cd console
npm ci

# against the mock backend: Vite on :5173, proxying /api to the mock on :7879
npm run dev

# against a gateway: point the proxy at its admin listener
MCPDEF_ADMIN=http://127.0.0.1:7879 npx vite

# build into the crate (then `cargo build` picks it up)
npm run build

# check it in Chromium against a gateway it starts: every screen, dark and
# light, axe-core's WCAG 2.1 AA rules, no error and no CSP violation (CI runs it)
(cd .. && cargo build -p mcpdef --bins) && npm run check
```

- **`src/ds/`** — the MCPdef design system (tokens + the inline-styled React
  primitives). Screens compose these; they don't re-style.
- **`src/screens/`** — the nine screens. Each takes the fetched `data` and the
  caller's session and renders them; an operator's actions are confirmed first.
- **`src/theme.js`** — dark, light, or as the system prefers, kept in the
  browser; `src/ds/tokens/colors.css` holds both palettes.
- **`src/api/client.js`** — the **only** place the console talks to the gateway:
  who the caller is (`/api/v1/session`), then each dataset on its own.
- **`server/mcpdef-mock.mjs`** — a dependency-free stand-in for the admin API,
  with realistic data, for working on the screens without a gateway.

Licensed under Apache-2.0, as the rest of MCPdef. What the build bundles keeps
its own license: IBM Plex under the SIL Open Font License 1.1, React under MIT
(`crates/mcpdef-console/licenses/`).
