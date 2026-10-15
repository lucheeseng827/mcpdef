// SPDX-License-Identifier: Apache-2.0
// MCPdef dashboard — formatting helpers (ES module port of the DS ui-kit helpers).
function two(n) { return String(n).padStart(2, "0"); }

// Absolute UTC used in detail views: 2026-06-23 17:04:11Z
export function fmtTime(ts) {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}Z`;
}

// Short relative time used in tables: 41s ago
export function fmtRel(ts, now) {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return s + "s ago";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  if (h < 24) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}

export const TRANSPORT = {
  stdio: "stdio", "streamable-http": "streamable-http", sse: "legacy sse",
  wasm: "wasm · sandbox", "wasm-component": "wasm-component · sandbox",
};

export function statusTone(s) {
  return s === "up" ? "good" : s === "degraded" ? "warn" : s === "down" ? "danger" : "default";
}
export function pinTone(p) {
  return p === "ok" ? "good" : p === "drift" ? "warn" : "default";
}
export function grouped(n) { return n.toLocaleString("en-US"); }
