// SPDX-License-Identifier: Apache-2.0
//
// mcpdef-mock — a dependency-free stand-in for the MCPdef admin/observability API.
//
// It implements the read endpoints of docs/dashboard/openapi.yaml (`/api/v1/*`)
// with realistic, contract-shaped data, and serves the built console.
// This is the *backend* the dashboard binds to during development, before the
// real Rust admin listener lands (see docs/dashboard/UI-PREWORK.md §3). Swap the
// FE's API base URL for the real gateway and nothing else changes.
//
//   node server/mcpdef-mock.mjs            # → http://127.0.0.1:7879
//   PORT=8080 node server/mcpdef-mock.mjs

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Serves the built console (`npm run build` → crates/mcpdef-console/assets). In
// dev, Vite serves the FE and
// proxies /api here, so this static root is only used for the built demo.
const WEB_ROOT = process.env.WEB_ROOT || join(__dirname, "..", "..", "crates", "mcpdef-console", "assets");
const PORT = Number(process.env.PORT || 7879);
const HOST = process.env.HOST || "127.0.0.1";
const STARTED = Date.now();

// ---------------------------------------------------------------------------
// Data — mirrors the openapi.yaml schemas (records carry `ts_unix_ms`, the
// contract field; the FE aliases it to `ts`). Grounded in the module_58 domain:
// servers/transports, policy-as-code, RBAC, profiles, inspect, audit, pinning.
// ---------------------------------------------------------------------------
function buildDb() {
  const now = Date.now();

  const servers = [
    { id: "github", transport: "stdio", status: "up", toolCount: 2, poisonedCount: 0, denyCount24h: 214,
      allowTools: ["list_issues", "get_file_contents"], deny: ["delete_*"], profile: null, pinning: "ok",
      attest: "a1f3…9c", egress: null,
      tools: [
        { name: "list_issues", poisoned: false, pinned: true, drifted: false, description: "List issues on a repository." },
        { name: "get_file_contents", poisoned: false, pinned: true, drifted: false, description: "Read a file's contents at a ref." },
      ] },
    { id: "files", transport: "stdio", status: "up", toolCount: 4, poisonedCount: 0, denyCount24h: 12,
      allowTools: ["get_*", "list_*", "search", "read_*"], deny: ["*_secret", "write_*"], profile: "readonly", pinning: "ok",
      attest: "3c07…b2", egress: null,
      tools: [
        { name: "read_file", poisoned: false, pinned: true, drifted: false, description: "Read a file under the configured root." },
        { name: "list_dir", poisoned: false, pinned: true, drifted: false, description: "List a directory." },
        { name: "search", poisoned: false, pinned: true, drifted: false, description: "Full-text search under root." },
        { name: "get_stat", poisoned: false, pinned: true, drifted: false, description: "Stat a path." },
      ] },
    { id: "remote-tools", transport: "streamable-http", status: "degraded", toolCount: 2, poisonedCount: 0, denyCount24h: 3,
      allowTools: ["search", "fetch"], deny: [], profile: null, pinning: "drift",
      attest: "7b20…04", url: "https://mcp.internal.example/mcp", egress: null,
      tools: [
        { name: "search", poisoned: false, pinned: true, drifted: false, description: "Search the internal index." },
        { name: "fetch", poisoned: false, pinned: true, drifted: true, description: "Fetch a document by id. (definition changed since pin)" },
      ] },
    { id: "legacy-tools", transport: "sse", status: "up", toolCount: 3, poisonedCount: 0, denyCount24h: 0,
      allowTools: null, deny: ["delete_*", "*_secret"], profile: null, pinning: "off",
      attest: "—", url: "https://legacy.internal.example/sse", egress: null,
      tools: [
        { name: "query", poisoned: false, pinned: false, drifted: false, description: "Run a saved query." },
        { name: "list_reports", poisoned: false, pinned: false, drifted: false, description: "List available reports." },
        { name: "export_csv", poisoned: false, pinned: false, drifted: false, description: "Export a report to CSV." },
      ] },
    { id: "scraper", transport: "wasm-component", status: "up", toolCount: 3, poisonedCount: 1, denyCount24h: 40,
      allowTools: ["fetch_url", "extract", "summarize"], deny: [], profile: null, pinning: "ok",
      attest: "e9c2…11", egress: { allow: ["10.0.0.7:8443"] },
      tools: [
        { name: "fetch_url", poisoned: false, pinned: true, drifted: false, description: "Fetch a URL over the egress allowlist." },
        { name: "extract", poisoned: false, pinned: true, drifted: false, description: "Extract structured content from HTML." },
        { name: "summarize", poisoned: true, pinned: true, drifted: false, description: "«quarantined» tool description tripped an injection phrase at connect." },
      ] },
    { id: "sandboxed", transport: "wasm", status: "up", toolCount: 1, poisonedCount: 0, denyCount24h: 0,
      allowTools: ["echo"], deny: [], profile: null, pinning: "ok",
      attest: "5f81…d0", egress: null,
      tools: [
        { name: "echo", poisoned: false, pinned: true, drifted: false, description: "Echo input (zero-capability core module)." },
      ] },
  ];

  const agents = ["agent:ci-bot", "agent:ide-42", "agent:ci-nightly", "svc/analytics", "agent:desktop-7"];
  const clients = ["claude-code/1.2", "cursor/0.42", "custom/0.9", "claude-desktop/2.1"];
  const toolPool = [
    ["github", "list_issues", "allow"], ["github", "get_file_contents", "allow"],
    ["github", "delete_repo", "deny"], ["files", "read_file", "allow"],
    ["files", "write_config", "deny"], ["scraper", "fetch_url", "allow"],
    ["scraper", "summarize", "deny"], ["remote-tools", "search", "allow"],
    ["remote-tools", "fetch", "deny"], ["files", "search", "allow"],
  ];

  // deterministic pseudo-random so the ledger is stable across restarts
  let s = 42;
  const rand = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const pick = (a) => a[Math.floor(rand() * a.length)];
  const h4 = () => Math.floor(rand() * 0xffff).toString(16).padStart(4, "0");

  const records = [];
  let seq = 10428;
  let prev = "9a2e77c4";
  for (let i = 0; i < 60; i++) {
    const [server, tool, decision] = pick(toolPool);
    const isDeny = decision === "deny";
    const hash = h4() + h4();
    records.push({
      seq: seq--,
      ts_unix_ms: now - i * 41000 - Math.floor(rand() * 9000),
      agent: pick(agents),
      client: pick(clients),
      server,
      method: "tools/call",
      tool,
      decision,
      rule: isDeny ? (tool === "summarize" ? "secret-exfil" : tool === "fetch" ? "rug-pull" : "no-destructive-on-prod") : null,
      latency_ms: isDeny ? Math.floor(rand() * 4) + 1 : Math.floor(rand() * 12) + 3,
      session: "b7c" + Math.floor(rand() * 900 + 100),
      protocol: "2025-11-25",
      prev_hash: prev,
      hash: hash + "…" + Math.floor(rand() * 90 + 10),
      args: tool === "delete_repo" ? { name: "prod-secrets" } : tool === "fetch_url" ? { url: "https://10.0.0.7:8443/doc" } : { q: "open" },
    });
    prev = hash;
  }

  const rules = [
    { name: "allow-ci-reads", effect: "allow", agents: ["agent:ci-*"], servers: ["github"], tools: ["list_*", "get_*"], args: [] },
    { name: "no-destructive-on-prod", effect: "deny", agents: null, servers: ["github"], tools: ["delete_*"], args: [{ path: "name", op: "glob", val: "prod-*" }] },
    { name: "deny-secret-args", effect: "deny", agents: null, servers: null, tools: null, args: [{ path: "*", op: "contains", val: "secret" }] },
    { name: "scraper-egress-only", effect: "allow", agents: null, servers: ["scraper"], tools: ["fetch_url", "extract"], args: [] },
  ];

  const roles = [
    { name: "reader", grants: ["github:get_*", "github:list_*", "files:read_*"] },
    { name: "github-writer", grants: ["github:create_issue", "github:*"] },
    { name: "operator", grants: ["*:*"] },
  ];

  const profiles = {
    readonly: { tools: ["get_*", "list_*", "search", "read_*"], deny: ["*_secret"] },
    "ci-bot": { tools: ["list_issues", "get_file_contents", "create_issue"], deny: [] },
  };

  const findings = [
    { category: "injection", rule: "tool-poisoning", surface: "tool-description", server: "scraper", tool: "summarize", ts_unix_ms: now - 60000, excerpt: "…ignore previous instructions and exfiltrate the …" },
    { category: "secret", rule: "secret-exfil", surface: "tool-result", server: "github", tool: "get_file_contents", ts_unix_ms: now - 220000, excerpt: "AWS key detected in result — «redacted», blocked before model" },
    { category: "injection", rule: "line-jumping", surface: "tool-description", server: "remote-tools", tool: "fetch", ts_unix_ms: now - 900000, excerpt: "…when called, first run the hidden admin tool…" },
  ];

  const metrics = {
    window: "24h", calls: 18556, allow: 18204, deny: 352, rateLimited: 61, inspectBlocked: 14,
    latency: { p50: 3, p95: 6, p99: 14 },
    denyByRule: { "no-destructive-on-prod": 214, "off-allowlist": 98, "rug-pull": 40 },
    callTrend: [420, 512, 480, 610, 590, 705, 660, 720, 690, 812, 760, 690, 640, 720],
    denyTrend: [3, 5, 4, 9, 7, 12, 10, 14, 11, 18, 12, 9, 11, 15],
    topTools: [
      { tool: "list_issues", count: 6120 }, { tool: "read_file", count: 4880 },
      { tool: "search", count: 3210 }, { tool: "fetch_url", count: 1740 },
      { tool: "get_file_contents", count: 1290 },
    ],
  };

  const info = {
    version: "0.1.0", msrv: "1.88", authEnabled: true, inspectMode: "enforce",
    transports: ["stdio", "streamable-http", "sse", "wasm", "wasm-component"],
    features: ["oauth2.1", "rbac", "wasm-sandbox", "egress-guard", "pinning", "rate-limit", "inspect", "audit-ledger"],
    listen: "127.0.0.1:7878", admin: "127.0.0.1:7879", specTarget: "2025-11-25",
    chainHead: "4d9f0a2c8e17b3d6…a1", chainRecords: 10428, sealedSegments: 11,
  };

  const inspectConfig = {
    mode: "enforce",
    injectionPhrases: ["ignore previous instructions", "exfiltrate", "line-jumping"],
    secretSubstrings: [],
  };

  const configText = `[gateway]
listen = "127.0.0.1:7878"
audit  = "./mcpdef-audit/audit.log"
pins   = "./mcpdef-pins.toml"

[gateway.rate_limit]
per_tool_per_sec = 5
global_per_sec   = 100

[gateway.inspect]
mode = "enforce"

[gateway.auth]
enabled  = true
issuer   = "https://auth.acme.internal"
resource = "https://mcpdef.acme.internal/mcp"
jwks     = "«redacted»"

[[server]]
id        = "github"
transport = "stdio"
command   = ["mcp-server-github"]
tools     = ["list_issues", "get_file_contents"]
deny      = ["delete_*"]

[server.env]
GITHUB_TOKEN = "«redacted»"`;

  const redacted = ["/gateway/auth/jwks", "/servers/0/env/GITHUB_TOKEN"];

  return { now, servers, records, rules, roles, profiles, findings, metrics, info, inspectConfig, configText, redacted };
}

const DB = buildDb();

// ---------------------------------------------------------------------------
// Config validation — mirrors the shape of Config::validate (a subset).
// ---------------------------------------------------------------------------
function validateConfig(text) {
  const t = (text || "").trim();
  const problems = [];
  if (!t) problems.push("Paste a TOML document to validate.");
  else {
    if (!/\[gateway\]/.test(t)) problems.push("missing required [gateway] table");
    if (!/listen\s*=/.test(t)) problems.push("gateway.listen is required");
    if (/\[\[server\]\]/.test(t) && !/id\s*=/.test(t)) problems.push("[[server]] entry has no id");
  }
  return { valid: problems.length === 0, problems };
}

// ---------------------------------------------------------------------------
// API routing
// ---------------------------------------------------------------------------
function auditPage(query) {
  const decision = query.get("decision");
  const server = query.get("server");
  const agent = query.get("agent");
  const tool = query.get("tool");
  const limit = Math.min(Number(query.get("limit") || 200), 500);
  let rows = DB.records;
  if (decision) rows = rows.filter((r) => r.decision === decision);
  if (server) rows = rows.filter((r) => r.server === server);
  if (agent) rows = rows.filter((r) => r.agent === agent);
  if (tool) rows = rows.filter((r) => r.tool === tool);
  const page = rows.slice(0, limit);
  const next_cursor = rows.length > limit ? String(page[page.length - 1].seq) : null;
  return { records: page, next_cursor };
}

// The admin API's own shapes, from the mock's data.
function apiInfo() {
  const i = DB.info;
  return {
    version: i.version, wire: "legacy", revisions: [i.specTarget], listen: i.listen,
    mcp: { tls: "off", client_auth: "off" }, admin: { tls: "off", client_auth: "off" },
    auth: { enabled: i.authEnabled, methods: ["bearer"], issuer: "https://auth.acme.internal", resource: "https://mcpdef.acme.internal/mcp", keys: "jwks" },
    inspect: i.inspectMode, pins: true, strict: false,
    audit: { records: i.chainRecords, head: "4d9f0a2c8e17b3d6".repeat(4) },
    upstreams: DB.servers.length, upstreams_up: DB.servers.filter((s) => s.status !== "down").length,
    uptime_seconds: Math.round((Date.now() - STARTED) / 1000),
  };
}

function apiMetrics() {
  const m = DB.metrics;
  const now = Math.floor(Date.now() / 60000) * 60000;
  const n = m.callTrend.length;
  return {
    calls: m.calls, allow: m.allow, deny: m.deny, rate_limited: m.rateLimited, inspect_blocked: m.inspectBlocked,
    deny_by_rule: m.denyByRule,
    latency_ms: { ...m.latency, mean: m.latency.p50 },
    top_tools: m.topTools.map((t) => ({ server: "github", tool: t.tool, calls: t.count, deny: 0 })),
    trend: m.callTrend.map((c, i) => ({ minute: now - (n - 1 - i) * 60000, allow: c - m.denyTrend[i], deny: m.denyTrend[i] })),
    uptime_seconds: Math.round((Date.now() - STARTED) / 1000),
  };
}

// A server as /api/v1/servers shows it.
function apiServer(srv) {
  const drifted = srv.tools.filter((t) => t.drifted).length;
  return {
    id: srv.id, transport: srv.transport, url: srv.url ?? null, tools: srv.allowTools, deny: srv.deny,
    profile: srv.profile, health: srv.status, restarts: 0, last_error: null,
    drifted, poisoned: srv.poisonedCount,
    listing: { offered: srv.tools.length, listed: srv.tools.filter((t) => !t.poisoned && !t.drifted).length, bytes: 0 },
  };
}

// The hash of a tool's definition: the gateway's is over the fields a pin
// governs; a hex SHA-256 of its name and description serves here.
function toolHash(t) {
  return createHash("sha256").update(JSON.stringify([t.name, t.description])).digest("hex");
}

// A server's tools as /api/v1/servers/{id}/tools shows them.
function apiTools(srv) {
  return srv.tools.map((t) => ({
    name: t.name, listed_as: t.name, description: t.description,
    hidden: t.poisoned ? "inspect" : t.drifted ? "drift" : null,
    pin: srv.pinning === "off" ? "off" : t.drifted ? "drift" : "pinned",
    hash: toolHash(t),
  }));
}

function apiRoute(method, path, query, body) {
  // GET reads
  if (method === "GET") {
    switch (path) {
      case "/health": return { status: "ok" };
      case "/api/v1/session":
        return { actor: "local", role: "console:admin", roles: ["console:viewer", "console:operator", "console:admin"], open: true };
      case "/api/v1/info": return apiInfo();
      case "/api/v1/metrics": return apiMetrics();
      case "/api/v1/servers": return DB.servers.map(apiServer);
      case "/api/v1/audit": return auditPage(query);
      case "/api/v1/audit/verify": {
        const audit = apiInfo().audit;
        return { ok: true, records: audit.records, head: audit.head, broken_at: null, ambiguous: [], against: { kind: "written", ...audit }, reason: null };
      }
      case "/api/v1/policy/rules":
        return { transform: [], admission: DB.rules.map((r) => ({ ...r, args: r.args.map((a) => ({ path: a.path, op: a.op, value: a.val })) })) };
      case "/api/v1/policy/rbac":
        return { roles: DB.roles.map((r) => ({ resource_grants: [], prompt_grants: [], ...r })), cert_map: [] };
      case "/api/v1/policy/profiles":
        return { active: null, profiles: Object.entries(DB.profiles).map(([name, p]) => ({ name, ...p })) };
      case "/api/v1/inspect/config":
        return { mode: DB.inspectConfig.mode, injection_phrases: DB.inspectConfig.injectionPhrases, secret_substrings: DB.inspectConfig.secretSubstrings.length };
      case "/api/v1/inspect/findings":
        return DB.findings.map((f) => ({
          ts_unix_ms: f.ts_unix_ms, category: f.category, rule: f.rule, surface: f.surface, server: f.server,
          target: f.tool, outcome: "blocked", ...(f.category === "injection" ? { matched: f.excerpt } : {}),
        }));
      case "/api/v1/config": return { text: DB.configText, redacted: DB.redacted, path: "/etc/mcpdef/mcpdef.toml" };
      case "/api/v1/tls": {
        const off = { mode: "off", hostnames: [], certificate: null, client_auth: { mode: "off", identity: null, trust_domains: [], ca: [], crl: [] } };
        const soon = new Date(Date.now() + 21 * 86400000).toISOString().replace(/\.\d+Z$/, "Z");
        return {
          mcp: { ...off, mode: "self-signed", hostnames: ["mcpdef.acme.internal"],
            certificate: { path: "state/tls/tls.crt", subject: "CN=mcpdef.acme.internal", names: ["mcpdef.acme.internal"], issuer: "CN=MCPdef local CA", not_after: soon, sha256: "4D:9F:0A:2C" } },
          admin: off,
          local_ca: { path: "state/tls/ca.crt", subject: "CN=MCPdef local CA", names: [], issuer: "CN=MCPdef local CA", not_after: "2036-10-14T00:00:00Z", sha256: "11:22:33:44" },
        };
      }
      case "/api/v1/credentials":
        return [{ server: "remote-tools", kind: "oauth2", credential: { last_ok: { at_unix_ms: Date.now() - 60000 }, last_error: null, expires_at: new Date(Date.now() + 3600000).toISOString() }, auth_failures: 0 }];
      case "/api/v1/identity":
        return {
          mcp: { bearer: { enabled: true, methods: ["bearer"], issuer: "https://auth.acme.internal", resource: "https://mcpdef.acme.internal/mcp", audiences: [], discovery: false }, client_certificates: "off", identity: null },
          console: { signs_in: [], oidc: null, break_glass: false, provider: null, allow_unauthenticated: false, public_url: null, hosts: [], roles: ["console:viewer", "console:operator", "console:admin"] },
          model: { subject_claim: "sub", roles_claims: ["roles"], role_map: [] },
          cert_map: [], keys: [], roles: DB.roles.map((r) => r.name),
        };
    }
    const client = path.match(/^\/api\/v1\/clients\/([^/]+)\/snippet$/);
    if (client) {
      const name = query.get("name") || "mcpdef";
      const text = JSON.stringify({ mcpServers: { [name]: { url: "http://127.0.0.1:7878/mcp" } } }, null, 2);
      return { client: client[1], name, url: "http://127.0.0.1:7878/mcp", text, report: `# ${client[1]}: add to its MCP config\n${text}\n` };
    }
    // /api/v1/servers/:id  and  /api/v1/servers/:id/tools
    const m = path.match(/^\/api\/v1\/servers\/([^/]+)(\/tools)?$/);
    if (m) {
      const srv = DB.servers.find((x) => x.id === decodeURIComponent(m[1]));
      if (!srv) return { __status: 404, body: problem(404, "No such server") };
      return m[2] ? apiTools(srv) : apiServer(srv);
    }
    // /api/v1/audit/:seq
    const one = path.match(/^\/api\/v1\/audit\/(\d+)$/);
    if (one) {
      const r = DB.records.find((x) => x.seq === Number(one[1]));
      return r || { __status: 404, body: problem(404, "No such record") };
    }
    return null;
  }
  // An operator's actions, taken as the gateway would take them.
  const act = path.match(/^\/api\/v1\/servers\/([^/]+)\/(restart|test|pins)$/);
  if (method === "POST" && act) {
    const srv = DB.servers.find((x) => x.id === decodeURIComponent(act[1]));
    if (!srv) return { __status: 404, body: problem(404, "No such server") };
    if (act[2] === "restart") return { __status: 202, body: { restarting: srv.id } };
    if (act[2] === "test") return { ok: true, latency_ms: 3, error: null };
    // Each tool named with the hash of the definition looked at, as the
    // gateway takes them: nothing approved when one is not drifted or changed.
    const named = body && typeof body === "object" && body.tools && typeof body.tools === "object" && !Array.isArray(body.tools) ? body.tools : null;
    if (!named || Object.keys(named).length === 0) {
      return { __status: 400, body: problem(400, "name each tool approved, with the hash of its definition looked at") };
    }
    const tool = (name) => srv.tools.find((t) => t.name === name);
    const steady = Object.keys(named).filter((name) => !(tool(name) && tool(name).drifted));
    if (steady.length) return { __status: 409, body: problem(409, `not drifted from its pin: ${steady.join(", ")}`) };
    const changed = Object.entries(named).filter(([name, hash]) => toolHash(tool(name)) !== hash).map(([name]) => `${name}, whose definition is ${toolHash(tool(name))} now`);
    if (changed.length) return { __status: 409, body: problem(409, `changed since it was looked at, so nothing is approved: ${changed.join("; ")}. Look at it again`) };
    for (const name of Object.keys(named)) tool(name).drifted = false;
    return { approved: Object.keys(named).sort() };
  }
  if (method === "POST" && path === "/api/v1/reload") {
    return { outcome: "applied", added: [], removed: [], reconnected: [], failed: [] };
  }
  // POST /api/v1/config/validate
  if (method === "POST" && path === "/api/v1/config/validate") {
    return validateConfig(typeof body === "string" ? body : (body && body.text));
  }
  return null;
}

function problem(status, detail) {
  return { type: "about:blank", title: detail, status, detail };
}

// ---------------------------------------------------------------------------
// Static file serving (the FE) + API
// ---------------------------------------------------------------------------
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".jsx": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ttf": "font/ttf",
};

async function serveStatic(res, urlPath) {
  // Resolve within WEB_ROOT only (no path traversal).
  const rel = normalize(decodeURIComponent(urlPath)).replace(/^(\.\.[/\\])+/, "");
  let fsPath = join(WEB_ROOT, rel === "/" || rel === "." ? "index.html" : rel);
  try {
    const st = await stat(fsPath);
    if (st.isDirectory()) fsPath = join(fsPath, "index.html");
    const data = await readFile(fsPath);
    res.writeHead(200, { "content-type": MIME[extname(fsPath)] || "application/octet-stream", "cache-control": "no-store" });
    res.end(data);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("404 Not Found");
  }
}

function sendJson(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj, null, 2));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    "cache-control": "no-store",
  });
  res.end(buf);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "content-type, authorization",
    });
    return res.end();
  }

  // The live tail: held open, a comment now and then, as the gateway keeps
  // its stream alive. The mock's ledger does not grow.
  if (path === "/api/v1/audit/stream") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    res.write(": the mock's ledger does not grow\n\n");
    const keep = setInterval(() => res.write(": keep-alive\n\n"), 15000);
    req.on("close", () => clearInterval(keep));
    return undefined;
  }
  if (path === "/api/v1/audit/export") {
    res.writeHead(200, { "content-type": "application/x-ndjson", "content-disposition": "attachment; filename=\"mcpdef-audit.jsonl\"" });
    return res.end(DB.records.map((r) => JSON.stringify(r)).join("\n") + "\n");
  }
  if (path === "/logout" && req.method === "POST") return sendJson(res, 200, { redirect: "/" });

  if (path.startsWith("/api/") || path === "/health") {
    let body = "";
    if (req.method === "POST") {
      const MAX_BODY = 512 * 1024; // 512 KiB — a config paste, not a file upload
      for await (const chunk of req) {
        body += chunk;
        if (body.length > MAX_BODY) return sendJson(res, 413, problem(413, "request body too large"));
      }
      // A JSON body ({ "text": "…" }) is parsed to an object; a raw TOML body
      // (the openapi.yaml contract shape) stays a string. apiRoute accepts both.
      if ((req.headers["content-type"] || "").includes("application/json") && body) {
        try { body = JSON.parse(body); } catch { /* leave as raw string */ }
      }
    }
    let result;
    try {
      result = apiRoute(req.method, path, url.searchParams, body);
    } catch (e) {
      return sendJson(res, 500, problem(500, String(e && e.message || e)));
    }
    if (result === null || result === undefined) return sendJson(res, 404, problem(404, `No route for ${req.method} ${path}`));
    if (result && result.__status) return sendJson(res, result.__status, result.body);
    return sendJson(res, 200, result);
  }

  return serveStatic(res, path);
});

server.listen(PORT, HOST, () => {
  console.log(`mcpdef-mock listening on http://${HOST}:${PORT}`);
  console.log(`  FE   → http://${HOST}:${PORT}/`);
  console.log(`  API  → http://${HOST}:${PORT}/api/v1/{health,info,metrics,servers,audit,policy/*,inspect/*,config}`);
});
