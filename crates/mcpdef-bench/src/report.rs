// SPDX-License-Identifier: Apache-2.0
//! The report: what was run, where, and what came out — as JSON for machines and
//! as Markdown tables for people (and for a CI job summary).

use crate::stats::Summary;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Bumped when a field changes meaning; `compare` refuses to mix schemas.
pub const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema: u32,
    pub generated_at_unix: u64,
    /// First line of `mcpdef version` for the binary that was measured.
    pub mcpdef_version: String,
    pub commit: Option<String>,
    pub note: Option<String>,
    pub machine: Machine,
    pub params: Params,
    pub scenarios: Scenarios,
}

/// Where the numbers came from. Two reports are only compared when these match.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Machine {
    pub os: String,
    pub arch: String,
    pub cpus: usize,
    pub cpu_model: Option<String>,
    pub mem_total_kb: Option<u64>,
}

/// How hard and how long each scenario pushed. Part of comparability too: a quick
/// run and a full one measure different things.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Params {
    pub quick: bool,
    /// Unmeasured calls before each measured run. The slow-neighbour scenario
    /// makes at least twice as many as it has clients.
    pub warmup: usize,
    /// Measured calls per allowed / denied run.
    pub requests: usize,
    /// Client counts the allowed / denied runs step through.
    pub concurrency: Vec<usize>,
    /// How long the slow neighbour takes to answer.
    pub slow_ms: u64,
    pub neighbour_upstreams: usize,
    /// Clients calling the fast upstreams in the slow-neighbour scenario. The
    /// slow neighbour's own caller is one more.
    pub neighbour_concurrency: usize,
    /// How long the fast calls run with no slow call in flight.
    pub neighbour_alone_ms: u64,
    /// How long the fast calls run beside the slow one.
    pub neighbour_beside_ms: u64,
    pub idle_upstreams: usize,
    pub idle_load_requests: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scenarios {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<Allowed>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<Denied>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slow_neighbour: Vec<SlowNeighbour>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_rss: Option<IdleRss>,
}

/// An allowlisted call, straight to the upstream and through the gateway, at one
/// client count. `added_*` is the gateway's cost; `ratio_*` is the same as a
/// multiple, which is what travels between machines.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Allowed {
    pub concurrency: usize,
    pub direct: Summary,
    pub gateway: Summary,
    pub added_p50_us: i64,
    pub added_p99_us: i64,
    pub ratio_p50: f64,
    pub ratio_p99: f64,
}

impl Allowed {
    pub fn new(concurrency: usize, direct: Summary, gateway: Summary) -> Self {
        Allowed {
            concurrency,
            added_p50_us: signed_diff(gateway.p50_us, direct.p50_us),
            added_p99_us: signed_diff(gateway.p99_us, direct.p99_us),
            ratio_p50: ratio(gateway.p50_us, direct.p50_us),
            ratio_p99: ratio(gateway.p99_us, direct.p99_us),
            direct,
            gateway,
        }
    }
}

/// A call the allowlist refuses. No upstream is involved, so its cost is the
/// gateway's alone; `ratio_p50_vs_direct` sets it against a direct upstream call
/// at the same client count, to be comparable across machines.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Denied {
    pub concurrency: usize,
    pub gateway: Summary,
    pub ratio_p50_vs_direct: f64,
}

/// Calls to fast upstreams with no slow call in flight (`alone`), and while one
/// upstream is busy answering a slow call (`beside_slow`). A gateway that keeps
/// its upstreams independent shows a ratio near 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlowNeighbour {
    /// Upstream transport: `http` or `stdio`.
    pub transport: String,
    pub upstreams: usize,
    pub slow_ms: u64,
    pub concurrency: usize,
    pub alone: Summary,
    pub beside_slow: Summary,
    pub slow_calls_completed: u64,
    pub ratio_p50: f64,
    pub ratio_p99: f64,
}

impl SlowNeighbour {
    pub fn ratios(mut self) -> Self {
        self.ratio_p50 = ratio(self.beside_slow.p50_us, self.alone.p50_us);
        self.ratio_p99 = ratio(self.beside_slow.p99_us, self.alone.p99_us);
        self
    }
}

/// Resident memory of the gateway process (not its stdio children), idle and
/// after a burst of calls.
///
/// The resident set splits into anonymous memory (heap and stacks: what the
/// gateway allocated) and file-backed pages (mostly its own executable). The
/// file-backed part moves between runs of one binary with the kernel's page
/// cache, so anonymous memory is the steadier measure of what the gateway costs.
/// It is Linux-only, and absent from reports made before it was recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdleRss {
    pub upstreams: usize,
    /// Whether the admin listener was on, the console opened, before the
    /// memory was read. Absent from reports made before it was.
    #[serde(default)]
    pub console: bool,
    pub idle_rss_kb: u64,
    pub idle_hwm_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_anon_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_file_kb: Option<u64>,
    pub after_load_rss_kb: u64,
    pub after_load_hwm_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_load_anon_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_load_file_kb: Option<u64>,
    pub load_requests: usize,
}

pub fn ratio(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 / b as f64
    }
}

fn signed_diff(a: u64, b: u64) -> i64 {
    i64::try_from(a).unwrap_or(i64::MAX) - i64::try_from(b).unwrap_or(i64::MAX)
}

impl Report {
    /// The report as Markdown: a header and one table per scenario that ran.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let m = &self.machine;
        let _ = writeln!(s, "## mcpdef-bench — {}", self.mcpdef_version);
        let _ = writeln!(
            s,
            "\n{} {} · {} CPUs{}{} · {} run",
            m.os,
            m.arch,
            m.cpus,
            m.cpu_model
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            self.commit
                .as_deref()
                .map(|c| format!(" · commit `{}`", c.chars().take(12).collect::<String>()))
                .unwrap_or_default(),
            if self.params.quick { "quick" } else { "full" },
        );
        if let Some(note) = &self.note {
            let _ = writeln!(s, "\n> {note}");
        }
        let sc = &self.scenarios;

        if !sc.allowed.is_empty() {
            let _ = writeln!(
                s,
                "\n### allowed — what the gateway adds to an allowlisted call\n\n\
                 | clients | direct p50 | direct p99 | via gateway p50 | via gateway p99 | added p50 | added p99 | gateway calls/s | errors |\n\
                 |---|---|---|---|---|---|---|---|---|"
            );
            for a in &sc.allowed {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | {} | {} | {:.0} | {} |",
                    a.concurrency,
                    fmt_us(a.direct.p50_us),
                    fmt_us(a.direct.p99_us),
                    fmt_us(a.gateway.p50_us),
                    fmt_us(a.gateway.p99_us),
                    fmt_signed_us(a.added_p50_us),
                    fmt_signed_us(a.added_p99_us),
                    a.gateway.rps,
                    a.direct.errors + a.gateway.errors,
                );
            }
        }

        if !sc.denied.is_empty() {
            let _ = writeln!(
                s,
                "\n### denied — a call the allowlist refuses (no upstream involved)\n\n\
                 | clients | p50 | p99 | calls/s | p50 vs a direct call | errors |\n\
                 |---|---|---|---|---|---|"
            );
            for d in &sc.denied {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {:.0} | {:.2}× | {} |",
                    d.concurrency,
                    fmt_us(d.gateway.p50_us),
                    fmt_us(d.gateway.p99_us),
                    d.gateway.rps,
                    d.ratio_p50_vs_direct,
                    d.gateway.errors,
                );
            }
        }

        if let Some(first) = sc.slow_neighbour.first() {
            let _ = writeln!(
                s,
                "\n### slow-neighbour — {} upstreams, one answering in {}; latency of calls to the other {}\n\n\
                 | upstreams over | clients | p99 alone | p99 beside the slow one | p99 ratio | p50 ratio | slow calls done | errors |\n\
                 |---|---|---|---|---|---|---|---|",
                first.upstreams,
                fmt_us(first.slow_ms * 1000),
                first.upstreams.saturating_sub(1),
            );
            for n in &sc.slow_neighbour {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | **{:.1}×** | {:.1}× | {} | {} |",
                    n.transport,
                    n.concurrency,
                    fmt_us(n.alone.p99_us),
                    fmt_us(n.beside_slow.p99_us),
                    n.ratio_p99,
                    n.ratio_p50,
                    n.slow_calls_completed,
                    n.alone.errors + n.beside_slow.errors,
                );
            }
        }

        if let Some(r) = &sc.idle_rss {
            let _ = writeln!(
                s,
                "\n### idle-rss — the gateway process fronting {} stdio upstreams{}\n\n\
                 | | idle | after {} calls |\n|---|---|---|",
                r.upstreams,
                if r.console { ", the console on" } else { "" },
                r.load_requests,
            );
            let kb = |v: Option<u64>| v.map(fmt_kb).unwrap_or_else(|| "—".into());
            let _ = writeln!(
                s,
                "| anonymous (heap, stacks) | {} | {} |",
                kb(r.idle_anon_kb),
                kb(r.after_load_anon_kb),
            );
            let _ = writeln!(
                s,
                "| file-backed (mostly the executable) | {} | {} |",
                kb(r.idle_file_kb),
                kb(r.after_load_file_kb),
            );
            let _ = writeln!(
                s,
                "| RSS | {} | {} |",
                fmt_kb(r.idle_rss_kb),
                fmt_kb(r.after_load_rss_kb),
            );
            let _ = writeln!(
                s,
                "\nPeak RSS: {}. Compare anonymous memory: the file-backed part moves with the \
                 kernel's page cache between runs of the same binary.",
                kb(r.after_load_hwm_kb.or(r.idle_hwm_kb)),
            );
        }
        s
    }
}

pub fn fmt_us(us: u64) -> String {
    if us < 1_000 {
        format!("{us} µs")
    } else if us < 1_000_000 {
        format!("{:.2} ms", us as f64 / 1e3)
    } else {
        format!("{:.2} s", us as f64 / 1e6)
    }
}

fn fmt_signed_us(us: i64) -> String {
    let sign = if us < 0 { "−" } else { "+" };
    format!("{sign}{}", fmt_us(us.unsigned_abs()))
}

pub fn fmt_kb(kb: u64) -> String {
    format!("{:.1} MiB", kb as f64 / 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_in_their_natural_unit() {
        assert_eq!(fmt_us(250), "250 µs");
        assert_eq!(fmt_us(1_500), "1.50 ms");
        assert_eq!(fmt_us(5_000_000), "5.00 s");
        assert_eq!(fmt_signed_us(-1_500), "−1.50 ms");
        assert_eq!(fmt_kb(10_240), "10.0 MiB");
    }

    #[test]
    fn allowed_derives_the_gateways_cost() {
        let direct = Summary {
            p50_us: 100,
            p99_us: 200,
            ..Summary::default()
        };
        let gateway = Summary {
            p50_us: 150,
            p99_us: 500,
            ..Summary::default()
        };
        let a = Allowed::new(1, direct, gateway);
        assert_eq!((a.added_p50_us, a.added_p99_us), (50, 300));
        assert!((a.ratio_p50 - 1.5).abs() < 1e-9);
        assert!((a.ratio_p99 - 2.5).abs() < 1e-9);
    }

    #[test]
    fn a_zero_denominator_is_not_a_panic() {
        assert_eq!(ratio(5, 0), 0.0);
    }

    #[test]
    fn the_slow_neighbour_table_says_how_many_clients_called() {
        let mut r: Report =
            serde_json::from_str(include_str!("../baselines/serialized.json")).unwrap();
        let summary = |p99_us| Summary {
            p50_us: 1_000,
            p99_us,
            ..Summary::default()
        };
        r.scenarios = Scenarios {
            slow_neighbour: vec![SlowNeighbour {
                transport: "http".into(),
                upstreams: 20,
                slow_ms: 5_000,
                concurrency: 200,
                alone: summary(40_000),
                beside_slow: summary(42_000),
                slow_calls_completed: 3,
                ratio_p50: 0.0,
                ratio_p99: 0.0,
            }
            .ratios()],
            ..Scenarios::default()
        };
        let md = r.render();
        assert!(
            md.contains("| upstreams over | clients | p99 alone |"),
            "{md}"
        );
        assert!(
            md.contains("| http | 200 | 40.00 ms | 42.00 ms | **1.1×** | 1.0× | 3 | 0 |"),
            "{md}"
        );
    }

    fn idle_rss(anon: Option<u64>) -> IdleRss {
        IdleRss {
            upstreams: 10,
            console: true,
            idle_rss_kb: 9_216,
            idle_hwm_kb: Some(9_216),
            idle_anon_kb: anon,
            idle_file_kb: anon.map(|a| 9_216 - a),
            after_load_rss_kb: 10_240,
            after_load_hwm_kb: Some(10_240),
            after_load_anon_kb: anon.map(|a| a * 2),
            after_load_file_kb: anon.map(|a| 10_240 - a * 2),
            load_requests: 1000,
        }
    }

    #[test]
    fn idle_rss_shows_the_anonymous_and_file_backed_parts() {
        let mut r: Report =
            serde_json::from_str(include_str!("../baselines/serialized.json")).unwrap();
        r.scenarios = Scenarios {
            idle_rss: Some(idle_rss(Some(1_024))),
            ..Scenarios::default()
        };
        let md = r.render();
        assert!(
            md.contains("| anonymous (heap, stacks) | 1.0 MiB | 2.0 MiB |"),
            "{md}"
        );
        assert!(
            md.contains("| file-backed (mostly the executable) | 8.0 MiB | 8.0 MiB |"),
            "{md}"
        );
        assert!(md.contains("| RSS | 9.0 MiB | 10.0 MiB |"), "{md}");
        assert!(md.contains("Peak RSS: 10.0 MiB."), "{md}");
        // Without the split, as off Linux or in an old report, the cells say so.
        r.scenarios.idle_rss = Some(idle_rss(None));
        assert!(r.render().contains("| anonymous (heap, stacks) | — | — |"));
    }

    #[test]
    fn a_commit_is_cut_to_twelve_characters_not_bytes() {
        let mut r: Report =
            serde_json::from_str(include_str!("../baselines/serialized.json")).unwrap();
        r.commit = Some("0123456789abcdef".into());
        assert!(r.render().contains(" · commit `0123456789ab`"));
        // `--commit` takes any string. Byte 12 of this one falls inside its
        // sixth `é`, where a cut by bytes panics.
        r.commit = Some(format!("a{}", "é".repeat(15)));
        let cut = format!(" · commit `a{}`", "é".repeat(11));
        assert!(r.render().contains(&cut));
    }

    #[test]
    fn absent_anonymous_memory_leaves_the_json_as_it_was() {
        let json = serde_json::to_value(idle_rss(None)).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(!keys
            .iter()
            .any(|k| k.ends_with("_anon_kb") || k.ends_with("_file_kb")));
        let json = serde_json::to_value(idle_rss(Some(800))).unwrap();
        assert_eq!(json["idle_anon_kb"], 800);
        assert_eq!(json["after_load_file_kb"], 10_240 - 1_600);
    }
}
