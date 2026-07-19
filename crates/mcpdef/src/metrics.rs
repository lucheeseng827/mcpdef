// SPDX-License-Identifier: Apache-2.0
//! In-process metrics for the OSS admin / observability server.
//!
//! Counters are incremented at the single audit chokepoint
//! ([`Gateway::audit`](crate::gateway::Gateway)), so every governed `tools/call`
//! is counted exactly once. The registry renders Prometheus text (for
//! `GET /metrics`) and a JSON snapshot (for the built-in UI's `/api/v1/stats`).
//!
//! Design: the gateway already serialises upstream calls behind a mutex, so a
//! plain `Mutex` here adds no contention beyond what exists; recording is a short
//! sync critical section with no `.await` held across the lock.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

/// Latency histogram bucket upper bounds, in milliseconds.
const LAT_BUCKETS_MS: [u64; 11] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

#[derive(Default)]
struct Inner {
    /// (server, tool, decision, rule) -> count. `decision` is "allow"/"deny";
    /// `rule` is the deny rule name, or "" for an allow.
    calls: BTreeMap<(String, String, String, String), u64>,
    /// Per-bucket (exclusive) latency counts, aligned with `LAT_BUCKETS_MS`.
    lat_counts: [u64; 11],
    /// Calls slower than the largest bucket.
    lat_over: u64,
    lat_sum_ms: u64,
    lat_total: u64,
}

/// Shared metrics registry. Clone the `Arc` into both the gateway (writer) and
/// the admin server (reader).
pub struct Metrics {
    inner: Mutex<Inner>,
    started: Instant,
    /// Configured upstream count (set once at startup).
    upstreams: u64,
}

impl Metrics {
    pub fn new(upstreams: u64) -> Self {
        Metrics {
            inner: Mutex::new(Inner::default()),
            started: Instant::now(),
            upstreams,
        }
    }

    /// Record one governed decision. `decision` is "allow" or "deny"; `rule` is the
    /// deny rule name (empty for an allow).
    pub fn record_call(
        &self,
        server: &str,
        tool: &str,
        decision: &str,
        rule: &str,
        latency_ms: u64,
    ) {
        let mut g = self.inner.lock().unwrap();
        *g.calls
            .entry((server.into(), tool.into(), decision.into(), rule.into()))
            .or_insert(0) += 1;
        g.lat_total += 1;
        g.lat_sum_ms += latency_ms;
        let mut placed = false;
        for (i, bound) in LAT_BUCKETS_MS.iter().enumerate() {
            if latency_ms <= *bound {
                g.lat_counts[i] += 1;
                placed = true;
                break;
            }
        }
        if !placed {
            g.lat_over += 1;
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Prometheus text exposition (v0.0.4).
    pub fn render_prometheus(&self) -> String {
        let g = self.inner.lock().unwrap();
        let mut out = String::new();

        out.push_str("# HELP mcpdef_tools_calls_total Governed tools/call decisions.\n");
        out.push_str("# TYPE mcpdef_tools_calls_total counter\n");
        for ((server, tool, decision, rule), n) in &g.calls {
            out.push_str(&format!(
                "mcpdef_tools_calls_total{{server=\"{}\",tool=\"{}\",decision=\"{}\",rule=\"{}\"}} {}\n",
                esc(server),
                esc(tool),
                esc(decision),
                esc(rule),
                n
            ));
        }

        out.push_str("# HELP mcpdef_call_latency_ms Governed tools/call latency (ms).\n");
        out.push_str("# TYPE mcpdef_call_latency_ms histogram\n");
        let mut cum = 0u64;
        for (i, bound) in LAT_BUCKETS_MS.iter().enumerate() {
            cum += g.lat_counts[i];
            out.push_str(&format!(
                "mcpdef_call_latency_ms_bucket{{le=\"{bound}\"}} {cum}\n"
            ));
        }
        cum += g.lat_over;
        out.push_str(&format!(
            "mcpdef_call_latency_ms_bucket{{le=\"+Inf\"}} {cum}\n"
        ));
        out.push_str(&format!("mcpdef_call_latency_ms_sum {}\n", g.lat_sum_ms));
        out.push_str(&format!("mcpdef_call_latency_ms_count {}\n", g.lat_total));

        out.push_str("# HELP mcpdef_upstreams Configured upstream MCP servers.\n");
        out.push_str("# TYPE mcpdef_upstreams gauge\n");
        out.push_str(&format!("mcpdef_upstreams {}\n", self.upstreams));

        out.push_str("# HELP mcpdef_uptime_seconds Gateway process uptime.\n");
        out.push_str("# TYPE mcpdef_uptime_seconds gauge\n");
        out.push_str(&format!(
            "mcpdef_uptime_seconds {}\n",
            self.started.elapsed().as_secs()
        ));

        out
    }

    /// JSON snapshot for the built-in UI (`/api/v1/stats`).
    pub fn snapshot_json(&self) -> serde_json::Value {
        let g = self.inner.lock().unwrap();
        let mut allow = 0u64;
        let mut deny = 0u64;
        let mut by_server: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut by_rule: BTreeMap<String, u64> = BTreeMap::new();
        for ((server, _tool, decision, rule), n) in &g.calls {
            let e = by_server.entry(server.clone()).or_default();
            if decision == "allow" {
                allow += n;
                e.0 += n;
            } else {
                deny += n;
                e.1 += n;
                if !rule.is_empty() {
                    *by_rule.entry(rule.clone()).or_default() += n;
                }
            }
        }
        let avg = if g.lat_total > 0 {
            g.lat_sum_ms as f64 / g.lat_total as f64
        } else {
            0.0
        };
        serde_json::json!({
            "total": allow + deny,
            "allow": allow,
            "deny": deny,
            "avg_latency_ms": avg,
            "upstreams": self.upstreams,
            "uptime_seconds": self.started.elapsed().as_secs(),
            "by_server": by_server.iter()
                .map(|(k, (a, d))| serde_json::json!({"server": k, "allow": a, "deny": d}))
                .collect::<Vec<_>>(),
            "by_rule": by_rule.iter()
                .map(|(k, n)| serde_json::json!({"rule": k, "count": n}))
                .collect::<Vec<_>>(),
        })
    }
}

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
