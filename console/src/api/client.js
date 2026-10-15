// SPDX-License-Identifier: Apache-2.0
// MCPdef console — API client. The single place the console talks to the
// gateway's admin API (/api/v1, docs/API.md). The gateway serves the console
// itself, so the API is on the same origin; in dev, Vite proxies /api to a
// gateway, or to server/mcpdef-mock.mjs.

export const BASE = "/api/v1";

// Every request carries an AbortController timeout so a stalled or dropped
// backend surfaces a clear error instead of spinning the console forever.
const TIMEOUT_MS = 10000;

/** A request that failed: its HTTP status (0 when no usable answer came), and
 * why: the `detail` of its problem document, or what went wrong. */
export class ApiError extends Error {
  constructor(status, detail, path, body = null) {
    super(`${path} → ${detail}`);
    this.status = status;
    this.detail = detail;
    this.path = path;
    this.body = body;
  }
}

/** Off to sign in, coming back to this page of the console. */
export function signIn(at = "/login") {
  const here = window.location.pathname + window.location.search + window.location.hash;
  window.location.assign(`${at}?then=${encodeURIComponent(here)}`);
}

async function fetchJson(path, init = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(BASE + path, { credentials: "same-origin", ...init, signal: controller.signal });
  } catch (e) {
    if (e.name === "AbortError") throw new ApiError(0, `timed out after ${TIMEOUT_MS}ms`, path);
    throw e;
  } finally {
    clearTimeout(id);
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    let body = null;
    try {
      body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      // not a problem document
    }
    // Not signed in, or no longer: where the console signs people in, it
    // sends them to, and back here after.
    if (res.status === 401) signIn();
    throw new ApiError(res.status, detail, path, body);
  }
  if (res.status === 204) return null;
  try {
    return await res.json();
  } catch (_) {
    throw new ApiError(0, `answered ${res.headers.get("content-type") || "with no content type"}, not JSON`, path);
  }
}

function get(path) {
  return fetchJson(path, { headers: { accept: "application/json" } });
}

/** A change: JSON, or no body; the browser says it comes from this origin. */
function post(path, body) {
  const init = { method: "POST", headers: { accept: "application/json" } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  return fetchJson(path, init);
}

/** Who the caller is: `{ actor, role, roles, open }`, and `sign_in`, or
 * `sign_out` and `name`. */
export function getSession() {
  return get("/session");
}

/** Sign out, and on to where the gateway says: its identity provider's
 * sign-out, or the console. */
export async function signOut() {
  const res = await fetch("/logout", { method: "POST", credentials: "same-origin", headers: { accept: "application/json" } });
  const said = res.ok ? await res.json() : { redirect: "/" };
  window.location.assign(said.redirect || "/");
}

// A dataset that fails, however it fails (not served yet, not for this
// caller, an error, a timeout, an answer that is not JSON), is null, with why
// in `unavailable`: its screen says so, and the rest of the console carries
// on. Only the session decides whether the console runs at all.
async function optional(key, path, unavailable) {
  try {
    return await get(path);
  } catch (e) {
    unavailable[key] = e instanceof ApiError
      ? { path: BASE + path, status: e.status, detail: e.detail }
      : { path: BASE + path, status: 0, detail: e.message || String(e) };
    return null;
  }
}

/** A server as the Servers screen reads it, from `/servers`. */
function normalizeServer(s) {
  return {
    ...s,
    status: s.health ?? "unknown",
    offered: s.listing?.offered ?? 0,
    listed: s.listing?.listed ?? 0,
    allowTools: s.tools ?? null,
    deny: s.deny ?? [],
    drifted: s.drifted ?? 0,
    poisoned: s.poisoned ?? 0,
    collisions: s.tool_collisions ?? [],
    resources: s.resources ?? [],
    templates: s.resource_templates ?? [],
    prompts: s.prompts ?? [],
  };
}

// Each dataset in the shape its screens read. A dataset not there stays null.
const screenShapes = {
  metrics: (m) => ({
    calls: m.calls,
    allow: m.allow,
    deny: m.deny,
    rateLimited: m.rate_limited,
    inspectBlocked: m.inspect_blocked,
    latency: { p50: m.latency_ms.p50, p95: m.latency_ms.p95, p99: m.latency_ms.p99 },
    denyByRule: m.deny_by_rule,
    callTrend: m.trend.map((t) => t.allow + t.deny),
    denyTrend: m.trend.map((t) => t.deny),
    topTools: m.top_tools.map((t) => ({ tool: t.tool, server: t.server, count: t.calls, deny: t.deny })),
    uptime: m.uptime_seconds,
  }),
  info: (i) => ({
    ...i,
    inspectMode: i.inspect,
    listen: i.serving ? i.serving.mcp : i.listen,
    specTarget: (i.revisions || [])[0],
    chainRecords: i.audit.records,
    chainHead: i.audit.head ? `${i.audit.head.slice(0, 16)}…` : "—",
  }),
  rules: (r) => {
    const args = (rule) => (rule.args || []).map((a) => ({ path: a.path, op: a.op, val: a.value ?? "" }));
    return {
      transform: r.transform.map((rule) => ({ ...rule, args: args(rule) })),
      admission: r.admission.map((rule) => ({ ...rule, args: args(rule) })),
    };
  },
  roles: (r) => r.roles,
  certMap: (r) => r.cert_map,
  profiles: (p) => ({ active: p.active, all: Object.fromEntries(p.profiles.map((x) => [x.name, { tools: x.tools, deny: x.deny }])) }),
  findings: (f) => f.map((x) => ({
    ...x,
    tool: x.target,
    ts: x.ts_unix_ms,
    excerpt: x.matched ? `…${x.matched}…` : x.category === "secret" ? `${x.rule}: the secret itself is not kept` : "",
  })),
};

function shaped(key, value) {
  return value != null && screenShapes[key] ? screenShapes[key](value) : value;
}

/** A record as the screens read it: `ts` for `ts_unix_ms`. */
export function record(r) {
  return { ...r, ts: r.ts_unix_ms };
}

/**
 * Fetch every dataset the console shows, each on its own, and assemble them
 * in the shape the screens consume. The audit log pages its own records; the
 * overview reads the newest.
 */
export async function loadData() {
  const unavailable = {};
  const sources = {
    servers: "/servers",
    records: "/audit?limit=200",
    rules: "/policy/rules",
    roles: "/policy/rbac",
    profiles: "/policy/profiles",
    findings: "/inspect/findings",
    inspect: "/inspect/config",
    metrics: "/metrics",
    info: "/info",
    config: "/config",
    tls: "/tls",
    credentials: "/credentials",
    identity: "/identity",
  };
  const fetched = await Promise.all(
    Object.entries(sources).map(async ([key, path]) => [key, await optional(key, path, unavailable)])
  );
  const raw = Object.fromEntries(fetched);
  const d = Object.fromEntries(fetched.map(([key, value]) => [key, shaped(key, value)]));
  // /audit pages its records ({ records, next_cursor }); a bare array is the
  // answer to `?limit` alone.
  const records = d.records ? (Array.isArray(d.records) ? d.records : d.records.records) : null;
  return {
    servers: d.servers ? d.servers.map(normalizeServer) : null,
    records: records ? records.map(record) : null,
    rules: d.rules,
    roles: d.roles,
    certMap: raw.roles ? screenShapes.certMap(raw.roles) : null,
    profiles: d.profiles,
    findings: d.findings,
    inspect: d.inspect,
    metrics: d.metrics,
    info: d.info,
    tls: d.tls,
    credentials: d.credentials,
    identity: d.identity,
    configText: d.config ? d.config.text : null,
    configPath: d.config ? d.config.path : null,
    redacted: d.config ? d.config.redacted : null,
    unavailable,
    now: Date.now(),
  };
}

/** The audit filters a page, an export and the stream take, as a query. */
function auditQuery(filters, extra = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...filters, ...extra })) {
    if (v !== undefined && v !== null && v !== "" && v !== "all") q.set(k, String(v));
  }
  return q.toString();
}

/** A page of the ledger, newest first: `{ records, next_cursor }`. The
 * cursor is sent even when empty, for the first page: `limit` alone answers
 * the bare list of the newest records, as before paging. */
export async function auditPage(filters, cursor = "", limit = 50) {
  const page = await get(`/audit?cursor=${encodeURIComponent(cursor || "")}&${auditQuery(filters, { limit })}`);
  return { records: page.records.map(record), next: page.next_cursor };
}

/** One record, by its seq. */
export async function auditRecord(seq) {
  return record(await get(`/audit/${encodeURIComponent(seq)}`));
}

/** Where the records the filters take are exported, in `format`. */
export function exportUrl(format, filters) {
  return `${BASE}/audit/export?${auditQuery(filters, { format })}`;
}

/** Where each record the filters take is sent as it is appended: each after
 * the record `after` (its seq), when given, so that none written since it was
 * read is missed; else from the end of the ledger. */
export function streamUrl(filters, after) {
  const q = auditQuery(filters, { after });
  return `${BASE}/audit/stream${q ? `?${q}` : ""}`;
}

/** The gateway's check of its ledger: GET /audit/verify. */
export function verifyLedger() {
  return get("/audit/verify");
}

/** Each tool a server's connection offers. */
export function serverTools(id) {
  return get(`/servers/${encodeURIComponent(id)}/tools`);
}

/** What `mcpdef connect <client>` prints for this gateway: `{ client, name,
 * url, text, report }`. */
export function snippet(client, name, tokenEnv) {
  const q = new URLSearchParams({ name: name || "mcpdef" });
  if (tokenEnv) q.set("token_env", tokenEnv);
  return get(`/clients/${encodeURIComponent(client)}/snippet?${q}`);
}

/** Open a server again now. */
export function restartServer(id) {
  return post(`/servers/${encodeURIComponent(id)}/restart`);
}

/** Ping a server over its live connection: `{ ok, latency_ms, error }`. */
export function testServer(id) {
  return post(`/servers/${encodeURIComponent(id)}/test`);
}

/** Take the drifted tools' definitions as their pins, each named with the
 * hash of the definition looked at, `{ name: hash }`: `{ approved }`. Nothing
 * is approved when one has changed since. */
export function approveDrift(id, tools) {
  return post(`/servers/${encodeURIComponent(id)}/pins`, { tools });
}

/** Read the config again and apply it. A refusal is `409`, its document
 * saying why: answered here, not thrown. */
export async function reloadConfig() {
  try {
    return await post("/reload");
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && e.body) return e.body;
    throw e;
  }
}

/** POST a candidate config to /config/validate (wraps Config::validate). */
export function validateConfig(text) {
  return post("/config/validate", { text });
}

/** Whether `session` holds `role` or one above it. */
export function holds(session, role) {
  const order = ["console:viewer", "console:operator", "console:admin"];
  return !!session && order.indexOf(session.role) >= order.indexOf(role);
}
