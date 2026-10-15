// SPDX-License-Identifier: Apache-2.0
// The built-in status UI's script: see admin_ui.html. Served as a file of
// its own, as the content security policy wants.
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function card(k, v) {
  return `<div class="card"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;
}
function fmtUptime(s) {
  s = Number(s) || 0;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}

// Up is the allow colour and down the deny colour; the last error, if any,
// shows beneath with when it happened, and then how its credentials fare.
function health(s) {
  const cls = { up: "allow", degraded: "degraded", starting: "starting", down: "deny" }[s.health] || "starting";
  let out = `<span class="badge ${cls}">${esc(s.health)}</span>`;
  if (s.restarts) out += ` <span class="muted">${esc(s.restarts)} restart(s)</span>`;
  if (s.last_error) {
    const at = new Date(s.last_error.at_unix_ms).toLocaleTimeString();
    out += `<div class="muted">${esc(at)}: ${esc(s.last_error.message)}</div>`;
  }
  return out + credential(s.credential);
}

// How the credentials MCPdef sends a server fare, for one with [server.auth]:
// when it last took them, when they expire, and what went wrong last.
function credential(c) {
  if (!c) return "";
  const at = (t) => esc(new Date(t.at_unix_ms).toLocaleTimeString());
  let out = c.last_ok ? `credentials taken ${at(c.last_ok)}` : "credentials not taken yet";
  if (c.expires_at) out += ` · expire ${esc(c.expires_at)}`;
  if (c.last_error) out += `<br>${at(c.last_error)}: ${esc(c.last_error.message)}`;
  return `<div class="muted">${out}</div>`;
}

// A refusal's detail, from its problem document, is what the header shows.
async function getJSON(u) {
  const r = await fetch(u);
  if (!r.ok) {
    const e = new Error(r.status);
    try { e.detail = (await r.json()).detail; } catch (_) { /* not a problem document */ }
    throw e;
  }
  return r.json();
}

async function refresh() {
  try {
    const [status, stats, servers, audit] = await Promise.all([
      getJSON("/api/v1/status"),
      getJSON("/api/v1/stats"),
      getJSON("/api/v1/servers"),
      getJSON("/api/v1/audit?limit=50"),
    ]);
    $("#live").style.background = "var(--allow)";
    $("#hdr").textContent =
      `v${status.version} · ${status.upstreams_up}/${status.upstreams} upstream(s) up · ` +
      `up ${fmtUptime(status.uptime_seconds)}`;

    $("#cards").innerHTML =
      card("Total calls", stats.total) +
      card("Allowed", stats.allow) +
      card("Denied", stats.deny) +
      card("Avg latency", (stats.avg_latency_ms || 0).toFixed(1) + " ms") +
      card("Upstreams", stats.upstreams);

    $("#servers > tbody").innerHTML = servers.length
      ? servers.map((s) => {
          const tools = s.tools == null ? '<span class="muted">— (deny-only)</span>'
            : (s.tools.length ? s.tools.map((t) => `<span class="pill">${esc(t)}</span>`).join("")
              : '<span class="muted">none</span>');
          const deny = s.deny && s.deny.length
            ? s.deny.map((d) => `<span class="pill deny">${esc(d)}</span>`).join("")
            : '<span class="muted">—</span>';
          return `<tr><td>${esc(s.id)}</td><td>${health(s)}</td><td>${esc(s.transport)}</td>` +
            `<td class="muted">${esc(s.url || "(stdio)")}</td><td>${tools}</td><td>${deny}</td></tr>`;
        }).join("")
      : '<tr><td colspan="6" class="muted">no servers</td></tr>';

    $("#audit > tbody").innerHTML = audit.length
      ? audit.map((r) => {
          const t = new Date(r.ts_unix_ms).toLocaleTimeString();
          const badge = r.decision === "allow"
            ? '<span class="badge allow">allow</span>'
            : '<span class="badge deny">deny</span>';
          // An upstream's own record (it went down, or came back) has no tool.
          const what = r.kind === "upstream"
            ? `<span class="muted">upstream ${esc(r.method)}</span>`
            : esc(r.tool || "—");
          return `<tr><td class="muted">${esc(t)}</td><td>${esc(r.server)}</td>` +
            `<td>${what}</td><td>${badge}</td>` +
            `<td class="muted">${esc(r.rule || "")}</td><td>${esc(r.latency_ms)}</td></tr>`;
        }).join("")
      : '<tr><td colspan="6" class="muted">no calls yet</td></tr>';
  } catch (e) {
    $("#live").style.background = "var(--deny)";
    $("#hdr").textContent = e.detail || "disconnected — retrying…";
  }
}

refresh();
setInterval(refresh, 3000);
