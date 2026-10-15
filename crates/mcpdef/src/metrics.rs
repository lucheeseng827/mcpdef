// SPDX-License-Identifier: Apache-2.0
//! In-process metrics for the OSS admin / observability server.
//!
//! Counters are incremented at the single audit chokepoint
//! ([`Gateway::audit`](crate::gateway::Gateway)), so every governed `tools/call`
//! is counted exactly once. The registry renders Prometheus text (for
//! `GET /metrics`), a JSON snapshot (for the built-in UI's `/api/v1/stats`),
//! and the console's view (`/api/v1/metrics`): totals, latency percentiles,
//! the top tools, and the last hour minute by minute.
//!
//! Design: recording is a short sync critical section under a plain `Mutex`,
//! with no `.await` held across the lock. Upstream health is not recorded here:
//! [`render_upstreams`] renders it from the gateway's live view when scraped.

use crate::gateway::{HealthState, UpstreamStatus};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Latency histogram bucket upper bounds, in milliseconds.
const LAT_BUCKETS_MS: [u64; 11] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// How many minutes back the trend goes.
const TREND_MINUTES: u64 = 60;
/// How many tools the console's view ranks.
const TOP_TOOLS: usize = 10;

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
    /// The calls of each of the last hour's minutes that had any, oldest
    /// first: (minutes since the epoch, allowed, denied).
    minutes: VecDeque<(u64, u64, u64)>,
}

/// Shared metrics registry. Clone the `Arc` into both the gateway (writer) and
/// the admin server (reader).
pub struct Metrics {
    inner: Mutex<Inner>,
    started: Instant,
    /// Configured upstream count: set at startup, and by each reload.
    upstreams: AtomicU64,
}

impl Metrics {
    pub fn new(upstreams: u64) -> Self {
        Metrics {
            inner: Mutex::new(Inner::default()),
            started: Instant::now(),
            upstreams: AtomicU64::new(upstreams),
        }
    }

    /// How many upstreams are configured, after a reload.
    pub fn set_upstreams(&self, upstreams: u64) {
        self.upstreams.store(upstreams, Ordering::Relaxed);
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
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
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
        let minute = unix_ms() / 60_000;
        if g.minutes.back().is_none_or(|m| m.0 != minute) {
            g.minutes.push_back((minute, 0, 0));
            while g
                .minutes
                .front()
                .is_some_and(|m| m.0 + TREND_MINUTES <= minute)
            {
                g.minutes.pop_front();
            }
        }
        if let Some(m) = g.minutes.back_mut() {
            match decision {
                "allow" => m.1 += 1,
                _ => m.2 += 1,
            }
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Prometheus text exposition (v0.0.4).
    pub fn render_prometheus(&self) -> String {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
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
        out.push_str(&format!(
            "mcpdef_upstreams {}\n",
            self.upstreams.load(Ordering::Relaxed)
        ));

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
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
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
            "upstreams": self.upstreams.load(Ordering::Relaxed),
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

impl Metrics {
    /// The console's view (`/api/v1/metrics`), since the gateway started:
    /// how many calls were allowed and denied, and under which rules;
    /// `rate_limited` and `inspect_blocked` among the denials; latency
    /// percentiles, estimated from the histogram as Prometheus's
    /// `histogram_quantile` does (`null` with no calls); the most-called tools,
    /// with how many of their calls were denied; and the last hour, a minute
    /// at a time, oldest first, each minute as the time it starts.
    pub fn console_json(&self) -> serde_json::Value {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut allow, mut deny) = (0u64, 0u64);
        let mut by_rule: BTreeMap<&str, u64> = BTreeMap::new();
        let mut by_tool: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
        for ((server, tool, decision, rule), n) in &g.calls {
            let calls = by_tool.entry((server, tool)).or_default();
            calls.0 += n;
            if decision == "allow" {
                allow += n;
            } else {
                deny += n;
                calls.1 += n;
                *by_rule.entry(rule).or_default() += n;
            }
        }
        let rule = |name: &str| by_rule.get(name).copied().unwrap_or(0);
        let mut top: Vec<_> = by_tool.into_iter().collect();
        top.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
        let now = unix_ms() / 60_000;
        let trend: Vec<serde_json::Value> = (now + 1 - TREND_MINUTES..=now)
            .map(|minute| {
                let (allow, deny) = g
                    .minutes
                    .iter()
                    .find(|m| m.0 == minute)
                    .map_or((0, 0), |m| (m.1, m.2));
                serde_json::json!({ "minute": minute * 60_000, "allow": allow, "deny": deny })
            })
            .collect();
        serde_json::json!({
            "calls": allow + deny,
            "allow": allow,
            "deny": deny,
            "rate_limited": rule("rate-limited"),
            "inspect_blocked": rule("injection") + rule("secret-exfil"),
            "deny_by_rule": by_rule,
            "latency_ms": {
                "p50": quantile(&g, 0.50),
                "p95": quantile(&g, 0.95),
                "p99": quantile(&g, 0.99),
                "mean": (g.lat_total > 0).then(|| g.lat_sum_ms as f64 / g.lat_total as f64),
            },
            "top_tools": top
                .iter()
                .take(TOP_TOOLS)
                .map(|((server, tool), (calls, deny))| {
                    serde_json::json!({ "server": server, "tool": tool, "calls": calls, "deny": deny })
                })
                .collect::<Vec<_>>(),
            "trend": trend,
            "uptime_seconds": self.started.elapsed().as_secs(),
        })
    }
}

/// The latency under which `q` of the calls fell, interpolated within its
/// bucket; the largest bucket's bound for one over it; `None` with no calls.
fn quantile(g: &Inner, q: f64) -> Option<f64> {
    if g.lat_total == 0 {
        return None;
    }
    let rank = q * g.lat_total as f64;
    let mut below = 0u64;
    let mut lower = 0u64;
    for (i, upper) in LAT_BUCKETS_MS.iter().enumerate() {
        let count = g.lat_counts[i];
        if count > 0 && (below + count) as f64 >= rank {
            let within = (rank - below as f64).max(0.0) / count as f64;
            let at = lower as f64 + (upper - lower) as f64 * within;
            return Some((at * 10.0).round() / 10.0);
        }
        below += count;
        lower = *upper;
    }
    Some(LAT_BUCKETS_MS[LAT_BUCKETS_MS.len() - 1] as f64)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Prometheus text for each upstream's health: `mcpdef_upstream_up` is 1 while it
/// is open (up or degraded) and 0 while it starts or is down, and
/// `mcpdef_upstream_restarts_total` counts the times it was started again.
///
/// `mcpdef_upstream_cert_expiry_seconds` is when the certificate an HTTPS
/// upstream presented last expires, as a Unix time, for an alert on
/// `mcpdef_upstream_cert_expiry_seconds - time()`. It is there only for
/// upstreams that have shown one, and not at all when none has.
///
/// `mcpdef_upstream_auth_failures_total` counts the times an upstream refused
/// MCPdef's credentials, or MCPdef had none to send it.
/// `mcpdef_credential_expiry_seconds` is when a credential MCPdef sends an
/// upstream expires, as a Unix time: `credential="token"` for an OAuth token,
/// once one is fetched, and `credential="client_cert"` for the certificate an
/// HTTPS upstream's connection presents. Like the certificate's expiry, it is
/// there only for the credentials that say.
pub fn render_upstreams(status: &[UpstreamStatus]) -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP mcpdef_upstream_up Whether an upstream is open (1), or starting or down (0).\n",
    );
    out.push_str("# TYPE mcpdef_upstream_up gauge\n");
    for u in status {
        let up = matches!(u.health, HealthState::Up | HealthState::Degraded);
        out.push_str(&format!(
            "mcpdef_upstream_up{{server=\"{}\"}} {}\n",
            esc(&u.id),
            u8::from(up)
        ));
    }
    out.push_str(
        "# HELP mcpdef_upstream_restarts_total Times an upstream was started again after going down.\n",
    );
    out.push_str("# TYPE mcpdef_upstream_restarts_total counter\n");
    for u in status {
        out.push_str(&format!(
            "mcpdef_upstream_restarts_total{{server=\"{}\"}} {}\n",
            esc(&u.id),
            u.restarts
        ));
    }
    out.push_str(
        "# HELP mcpdef_upstream_auth_failures_total Times an upstream refused MCPdef's credentials, or MCPdef had none to send it.\n",
    );
    out.push_str("# TYPE mcpdef_upstream_auth_failures_total counter\n");
    for u in status {
        out.push_str(&format!(
            "mcpdef_upstream_auth_failures_total{{server=\"{}\"}} {}\n",
            esc(&u.id),
            u.auth_failures
        ));
    }
    let expiries: Vec<(&str, i64)> = status
        .iter()
        .filter_map(|u| Some((u.id.as_str(), u.tls.as_ref()?.not_after_unix?)))
        .collect();
    if !expiries.is_empty() {
        out.push_str(
            "# HELP mcpdef_upstream_cert_expiry_seconds When the certificate an HTTPS upstream presented last expires, as a Unix time.\n",
        );
        out.push_str("# TYPE mcpdef_upstream_cert_expiry_seconds gauge\n");
        for (id, expiry) in expiries {
            out.push_str(&format!(
                "mcpdef_upstream_cert_expiry_seconds{{server=\"{}\"}} {expiry}\n",
                esc(id)
            ));
        }
    }
    let credentials: Vec<(&str, &str, i64)> = status
        .iter()
        .flat_map(|u| {
            let token = u.credential.as_ref().and_then(|c| c.expires_at_unix);
            let cert = u.tls.as_ref().and_then(|t| t.client_not_after_unix);
            [("token", token), ("client_cert", cert)]
                .into_iter()
                .filter_map(move |(kind, expiry)| Some((u.id.as_str(), kind, expiry?)))
        })
        .collect();
    if !credentials.is_empty() {
        out.push_str(
            "# HELP mcpdef_credential_expiry_seconds When a credential MCPdef sends an upstream expires, as a Unix time: an OAuth token, or a client certificate.\n",
        );
        out.push_str("# TYPE mcpdef_credential_expiry_seconds gauge\n");
        for (id, kind, expiry) in credentials {
            out.push_str(&format!(
                "mcpdef_credential_expiry_seconds{{server=\"{}\",credential=\"{kind}\"}} {expiry}\n",
                esc(id)
            ));
        }
    }
    out
}

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_while_counting_does_not_stop_the_counting() {
        let m = std::sync::Arc::new(Metrics::new(1));
        m.record_call("a", "echo", "allow", "", 3);
        let poisoner = std::sync::Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.inner.lock().unwrap();
            panic!("a panic while the counters are held");
        })
        .join();
        assert!(m.inner.is_poisoned());
        m.record_call("a", "echo", "deny", "denylist", 5);
        assert_eq!(m.snapshot_json()["total"], 2);
        assert!(m.render_prometheus().contains("mcpdef_tools_calls_total"));
        assert_eq!(m.console_json()["calls"], 2);
    }
    use crate::gateway::TlsStatus;

    #[test]
    fn the_console_view_counts_ranks_and_trends_the_calls() {
        let m = Metrics::new(2);
        let empty = m.console_json();
        assert_eq!(empty["calls"], 0);
        assert!(empty["latency_ms"]["p50"].is_null());
        assert_eq!(empty["trend"].as_array().unwrap().len(), 60);
        for i in 0..90u64 {
            m.record_call("a", "read", "allow", "", 3 + i % 4);
        }
        for _ in 0..6 {
            m.record_call("b", "write", "deny", "rate-limited", 1);
        }
        for rule in ["injection", "secret-exfil", "rug-pull", "rbac"] {
            m.record_call("b", "fetch", "deny", rule, 2);
        }
        let v = m.console_json();
        assert_eq!(
            (v["calls"].clone(), v["allow"].clone(), v["deny"].clone()),
            (100.into(), 90.into(), 10.into())
        );
        assert_eq!(v["rate_limited"], 6);
        assert_eq!(v["inspect_blocked"], 2);
        assert_eq!(v["deny_by_rule"]["rug-pull"], 1);
        assert_eq!(v["deny_by_rule"]["rate-limited"], 6);
        let top = v["top_tools"].as_array().unwrap();
        assert_eq!(
            top.iter()
                .map(|t| (
                    t["tool"].as_str().unwrap(),
                    t["calls"].as_u64().unwrap(),
                    t["deny"].as_u64().unwrap()
                ))
                .collect::<Vec<_>>(),
            [("read", 90, 0), ("write", 6, 6), ("fetch", 4, 4)]
        );
        // 3 to 6 ms, all but ten in the 5 ms and 10 ms buckets.
        let p50 = v["latency_ms"]["p50"].as_f64().unwrap();
        assert!((1.0..=10.0).contains(&p50), "{p50}");
        assert!(v["latency_ms"]["p99"].as_f64().unwrap() <= 10.0);
        let trend = v["trend"].as_array().unwrap();
        assert_eq!(trend.len(), 60);
        let (allowed, denied) = trend.iter().fold((0, 0), |(a, d), m| {
            (
                a + m["allow"].as_u64().unwrap(),
                d + m["deny"].as_u64().unwrap(),
            )
        });
        assert_eq!((allowed, denied), (90, 10));
        let minutes: Vec<u64> = trend
            .iter()
            .map(|m| m["minute"].as_u64().unwrap())
            .collect();
        assert!(minutes.windows(2).all(|w| w[1] == w[0] + 60_000));
        // The last is this minute (or the one before, if it turned meanwhile).
        let now = unix_ms() / 60_000 * 60_000;
        assert!(
            minutes[59] == now || minutes[59] + 60_000 == now,
            "{minutes:?}"
        );
    }

    #[test]
    fn a_quantile_is_interpolated_within_its_bucket() {
        let m = Metrics::new(0);
        for _ in 0..10 {
            m.record_call("a", "t", "allow", "", 20);
        }
        // All ten in the 10-25 ms bucket: the median halfway through it.
        let v = m.console_json();
        assert_eq!(v["latency_ms"]["p50"], 17.5);
        m.record_call("a", "t", "allow", "", 60_000);
        assert_eq!(m.console_json()["latency_ms"]["p99"], 5000.0);
    }

    #[test]
    fn upstream_health_renders_as_a_gauge_and_a_counter() {
        let status = |id: &str, health, restarts| UpstreamStatus {
            id: id.into(),
            health,
            restarts,
            last_error: None,
            tls: None,
            credential: None,
            auth_failures: 0,
            tool_collisions: Vec::new(),
            offers: None,
        };
        let text = render_upstreams(&[
            status("a", HealthState::Up, 0),
            status("b", HealthState::Degraded, 1),
            status("c", HealthState::Down, 7),
            status("d\"e", HealthState::Starting, 0),
        ]);
        for line in [
            "# TYPE mcpdef_upstream_up gauge",
            "mcpdef_upstream_up{server=\"a\"} 1",
            "mcpdef_upstream_up{server=\"b\"} 1",
            "mcpdef_upstream_up{server=\"c\"} 0",
            "mcpdef_upstream_up{server=\"d\\\"e\"} 0",
            "# TYPE mcpdef_upstream_restarts_total counter",
            "mcpdef_upstream_restarts_total{server=\"c\"} 7",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing {line:?} in\n{text}"
            );
        }
        // No upstream has shown a certificate: no expiry, not even its HELP.
        assert!(!text.contains("cert_expiry"), "{text}");
    }

    #[test]
    fn each_certificate_an_upstream_showed_renders_its_expiry() {
        let status = |id: &str, tls: Option<(&'static str, Option<i64>)>| UpstreamStatus {
            id: id.into(),
            health: HealthState::Up,
            restarts: 0,
            last_error: None,
            tls: tls.map(|(verify, not_after_unix)| TlsStatus {
                verify,
                fingerprint: Some("AB:CD".into()),
                not_after: None,
                not_after_unix,
                client_not_after: None,
                client_not_after_unix: None,
            }),
            credential: None,
            auth_failures: 0,
            tool_collisions: Vec::new(),
            offers: None,
        };
        let text = render_upstreams(&[
            status("ca", Some(("ca", Some(1_927_843_200)))),
            status("plain", None),
            status("unread", Some(("ca", None))),
            status("p\"n", Some(("pin", Some(67_090_118_400)))),
        ]);
        let expiries: Vec<&str> = text.lines().filter(|l| l.contains("cert_expiry")).collect();
        assert_eq!(
            expiries,
            [
                "# HELP mcpdef_upstream_cert_expiry_seconds When the certificate an HTTPS upstream presented last expires, as a Unix time.",
                "# TYPE mcpdef_upstream_cert_expiry_seconds gauge",
                "mcpdef_upstream_cert_expiry_seconds{server=\"ca\"} 1927843200",
                "mcpdef_upstream_cert_expiry_seconds{server=\"p\\\"n\"} 67090118400",
            ]
        );
    }

    #[test]
    fn auth_failures_count_for_every_upstream_and_each_credential_says_when_it_expires() {
        use crate::gateway::CredentialStatus;
        let status = |id: &str, failures, token: Option<i64>, cert: Option<i64>| UpstreamStatus {
            id: id.into(),
            health: HealthState::Up,
            restarts: 0,
            last_error: None,
            tls: cert.map(|at| TlsStatus {
                verify: "ca",
                fingerprint: None,
                not_after: None,
                not_after_unix: None,
                client_not_after: None,
                client_not_after_unix: Some(at),
            }),
            credential: token.map(|at| CredentialStatus {
                last_ok: None,
                last_error: None,
                expires_at: None,
                expires_at_unix: Some(at),
            }),
            auth_failures: failures,
            tool_collisions: Vec::new(),
            offers: None,
        };
        let text = render_upstreams(&[
            status("plain", 0, None, None),
            status("oauth", 3, Some(1_790_427_600), None),
            status("m\"tls", 1, Some(1_790_427_601), Some(1_804_118_400)),
        ]);
        let lines =
            |name: &str| -> Vec<&str> { text.lines().filter(|l| l.contains(name)).collect() };
        assert_eq!(
            lines("auth_failures"),
            [
                "# HELP mcpdef_upstream_auth_failures_total Times an upstream refused MCPdef's credentials, or MCPdef had none to send it.",
                "# TYPE mcpdef_upstream_auth_failures_total counter",
                "mcpdef_upstream_auth_failures_total{server=\"plain\"} 0",
                "mcpdef_upstream_auth_failures_total{server=\"oauth\"} 3",
                "mcpdef_upstream_auth_failures_total{server=\"m\\\"tls\"} 1",
            ]
        );
        assert_eq!(
            lines("credential_expiry"),
            [
                "# HELP mcpdef_credential_expiry_seconds When a credential MCPdef sends an upstream expires, as a Unix time: an OAuth token, or a client certificate.",
                "# TYPE mcpdef_credential_expiry_seconds gauge",
                "mcpdef_credential_expiry_seconds{server=\"oauth\",credential=\"token\"} 1790427600",
                "mcpdef_credential_expiry_seconds{server=\"m\\\"tls\",credential=\"token\"} 1790427601",
                "mcpdef_credential_expiry_seconds{server=\"m\\\"tls\",credential=\"client_cert\"} 1804118400",
            ]
        );
        // No credential says when it expires: no expiry, not even its HELP.
        let text = render_upstreams(&[status("plain", 0, None, None)]);
        assert!(!text.contains("credential_expiry"), "{text}");
    }
}
