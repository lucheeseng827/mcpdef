// SPDX-License-Identifier: Apache-2.0
//! Comparing a report against a baseline.
//!
//! Only **ratios measured within one run** are compared: gateway-over-direct for
//! an allowed call, denied-over-direct, beside-over-alone for the slow neighbour.
//! Both sides of each ratio share a machine, a moment and a load, so noise that
//! moves one moves the other. Resident memory is the one absolute number, because
//! it does not depend on how busy the machine was.
//!
//! Even ratios drift between environments, so two reports are **compared only
//! when they are comparable**: same schema, same machine (OS, arch, CPU count and
//! model) and same run parameters. Otherwise the comparison says why it will not
//! judge, rather than guessing — the rule the lab's other latency gate settled on.

use crate::report::{Params, Report, SCHEMA};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// How far a metric may rise over its baseline before it is called a regression.
///
/// Calibrated on two back-to-back runs of one binary on a 4-vCPU machine:
/// - single-client p50 ratios moved by up to 11 %;
/// - tails and 16-client ratios by up to 24 % in a full run, and up to 68 % in a
///   quick one, whose p99 rests on a handful of samples.
///
/// Memory was calibrated on 20 full and 20 quick runs of one binary:
/// - idle anonymous memory moved by up to 2.5 %;
/// - anonymous memory after the burst of calls by up to 12 %, because the
///   allocator's footprint depends on how the concurrent calls interleaved;
/// - resident memory by up to 16 %, all of it file-backed pages of the
///   executable, which follow the kernel's page cache rather than the gateway.
///
/// The bands sit above those swings, so a warning means a change and not noise.
/// Slow-neighbour ratios get a wide band on purpose: the change that matters there
/// is orders of magnitude (thousands to about one), not tens of percent.
pub fn tolerance(metric: &str) -> f64 {
    if metric == "idle_rss.idle_anon_kb" {
        0.05
    } else if metric.starts_with("idle_rss.") {
        0.20
    } else if metric.starts_with("slow_neighbour.") {
        0.50
    } else if metric.contains(".c1.") && !metric.contains("p99") {
        0.25
    } else {
        0.50
    }
}

/// The comparable numbers in a report, keyed for `--max` gates and for tables.
/// Every one of them is better lower.
pub fn metrics(r: &Report) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    for a in &r.scenarios.allowed {
        m.insert(format!("allowed.c{}.ratio_p50", a.concurrency), a.ratio_p50);
        m.insert(format!("allowed.c{}.ratio_p99", a.concurrency), a.ratio_p99);
    }
    for d in &r.scenarios.denied {
        m.insert(
            format!("denied.c{}.ratio_p50_vs_direct", d.concurrency),
            d.ratio_p50_vs_direct,
        );
    }
    for n in &r.scenarios.slow_neighbour {
        m.insert(
            format!("slow_neighbour.{}.ratio_p50", n.transport),
            n.ratio_p50,
        );
        m.insert(
            format!("slow_neighbour.{}.ratio_p99", n.transport),
            n.ratio_p99,
        );
    }
    if let Some(i) = &r.scenarios.idle_rss {
        m.insert("idle_rss.idle_rss_kb".into(), i.idle_rss_kb as f64);
        m.insert(
            "idle_rss.after_load_rss_kb".into(),
            i.after_load_rss_kb as f64,
        );
        // Absent from reports made before it was recorded, and off Linux. A
        // metric missing from the baseline is left unjudged, never a regression.
        if let Some(kb) = i.idle_anon_kb {
            m.insert("idle_rss.idle_anon_kb".into(), kb as f64);
        }
        if let Some(kb) = i.after_load_anon_kb {
            m.insert("idle_rss.after_load_anon_kb".into(), kb as f64);
        }
    }
    m
}

/// Why `baseline` and `current` cannot be compared; empty when they can.
pub fn incomparable(baseline: &Report, current: &Report) -> Vec<String> {
    let mut why = Vec::new();
    if baseline.schema != current.schema || current.schema != SCHEMA {
        why.push(format!(
            "report schema {} vs {} (this build reads {SCHEMA})",
            baseline.schema, current.schema
        ));
    }
    let (b, c) = (&baseline.machine, &current.machine);
    if (&b.os, &b.arch) != (&c.os, &c.arch) {
        why.push(format!(
            "platform {}/{} vs {}/{}",
            b.os, b.arch, c.os, c.arch
        ));
    }
    if b.cpus != c.cpus {
        why.push(format!("{} CPUs vs {}", b.cpus, c.cpus));
    }
    if b.cpu_model != c.cpu_model {
        why.push(format!(
            "CPU {} vs {}",
            b.cpu_model.as_deref().unwrap_or("unknown"),
            c.cpu_model.as_deref().unwrap_or("unknown")
        ));
    }
    if baseline.params != current.params {
        why.push(if baseline.params.quick != current.params.quick {
            "a quick run against a full one".to_string()
        } else {
            format!(
                "different run parameters ({})",
                changed_params(&baseline.params, &current.params).join(", ")
            )
        });
    }
    why
}

/// The parameters that differ, each as `name baseline vs current`.
fn changed_params(baseline: &Params, current: &Params) -> Vec<String> {
    let fields = |p: &Params| match serde_json::to_value(p) {
        Ok(Value::Object(fields)) => fields,
        _ => serde_json::Map::new(),
    };
    let (b, c) = (fields(baseline), fields(current));
    b.iter()
        .filter(|&(name, value)| c.get(name) != Some(value))
        .map(|(name, value)| {
            let now = c.get(name).unwrap_or(&Value::Null);
            format!("{name} {value} vs {now}")
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Improved,
    Regressed,
    /// Nothing to compare against (no baseline, or not comparable).
    Unjudged,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub metric: String,
    pub baseline: Option<f64>,
    pub current: f64,
    pub verdict: Verdict,
}

/// The whole comparison: rows, and the reasons it failed or did not judge.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub rows: Vec<Row>,
    /// Empty when a baseline was given and was comparable.
    pub not_judged: Vec<String>,
    /// Why some metrics of a comparable baseline were left unjudged: a
    /// scenario the two runs measured differently.
    pub unjudged: Vec<String>,
    /// `--max` limits the current report broke (or could not be checked against).
    pub gate_failures: Vec<String>,
}

impl Outcome {
    pub fn regressions(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.verdict == Verdict::Regressed)
            .count()
    }

    /// Whether a baseline was actually compared against.
    pub fn judged(&self) -> bool {
        self.not_judged.is_empty()
    }
}

/// Why the two runs' idle memory is not alike, if it is not: one measured
/// with the console open, the other without, as reports made before it was
/// were.
fn idle_rss_differs(baseline: &Report, current: &Report) -> Option<String> {
    let b = baseline.scenarios.idle_rss.as_ref()?;
    let c = current.scenarios.idle_rss.as_ref()?;
    let open = |on: bool| if on { "open" } else { "closed" };
    (b.console != c.console).then(|| {
        format!(
            "idle_rss, measured with the console {} in the baseline and {} in this run",
            open(b.console),
            open(c.console)
        )
    })
}

/// Compare `current` with `baseline` (if any), and check the `--max` gates.
pub fn compare(baseline: Option<&Report>, current: &Report, gates: &[(String, f64)]) -> Outcome {
    let cur = metrics(current);
    let mut out = Outcome::default();

    let base = match baseline {
        None => {
            out.not_judged.push("no baseline was given".into());
            None
        }
        Some(b) => {
            let why = incomparable(b, current);
            if why.is_empty() {
                let mut base = metrics(b);
                // Idle memory with the console open is not idle memory
                // without it: unjudged, never a regression.
                if let Some(why) = idle_rss_differs(b, current) {
                    base.retain(|metric, _| !metric.starts_with("idle_rss."));
                    out.unjudged.push(why);
                }
                Some(base)
            } else {
                out.not_judged = why;
                None
            }
        }
    };

    for (metric, &current) in &cur {
        let baseline = base.as_ref().and_then(|b| b.get(metric)).copied();
        let verdict = match baseline {
            None => Verdict::Unjudged,
            Some(b) if b > 0.0 && current > b * (1.0 + tolerance(metric)) => Verdict::Regressed,
            Some(b) if current < b * (1.0 - tolerance(metric)) => Verdict::Improved,
            Some(_) => Verdict::Ok,
        };
        out.rows.push(Row {
            metric: metric.clone(),
            baseline,
            current,
            verdict,
        });
    }

    for (metric, max) in gates {
        match cur.get(metric) {
            Some(&v) if v > *max => out
                .gate_failures
                .push(format!("{metric} = {v:.3} is over its limit of {max}")),
            Some(_) => {}
            None => out.gate_failures.push(format!(
                "{metric} has a limit but is not in this report — a gate that checks nothing is not a gate"
            )),
        }
    }
    out
}

/// Parse a `--max` argument: `metric=limit`.
pub fn parse_gate(s: &str) -> Result<(String, f64), String> {
    let (metric, limit) = s
        .split_once('=')
        .ok_or_else(|| format!("`{s}` is not metric=limit"))?;
    let limit: f64 = limit
        .trim()
        .parse()
        .map_err(|_| format!("`{limit}` is not a number"))?;
    Ok((metric.trim().to_string(), limit))
}

impl Outcome {
    /// Markdown for a person or a CI job summary.
    pub fn render(&self) -> String {
        let mut s = String::from("## mcpdef-bench — comparison\n");
        if !self.judged() {
            let _ = writeln!(
                s,
                "\n**Not compared:** {}. The table shows this run only.",
                self.not_judged.join("; ")
            );
        }
        if !self.unjudged.is_empty() {
            let _ = writeln!(s, "\n**Left unjudged:** {}.", self.unjudged.join("; "));
        }
        let _ = writeln!(
            s,
            "\n| metric | baseline | this run | change | |\n|---|---|---|---|---|"
        );
        for r in &self.rows {
            let (base, change) = match r.baseline {
                Some(b) if b > 0.0 => (
                    fmt_value(&r.metric, b),
                    format!("{:+.0}%", (r.current / b - 1.0) * 100.0),
                ),
                Some(b) => (fmt_value(&r.metric, b), "—".into()),
                None => ("—".into(), "—".into()),
            };
            let mark = match r.verdict {
                Verdict::Ok => "ok",
                Verdict::Improved => "better",
                Verdict::Regressed => "**worse**",
                Verdict::Unjudged => "",
            };
            let _ = writeln!(
                s,
                "| `{}` | {} | {} | {} | {} |",
                r.metric,
                base,
                fmt_value(&r.metric, r.current),
                change,
                mark
            );
        }
        for g in &self.gate_failures {
            let _ = writeln!(s, "\n**Gate failed:** {g}");
        }
        s
    }

    /// GitHub Actions annotations, so a regression shows on the run page.
    pub fn annotations(&self) -> Vec<String> {
        let mut a = Vec::new();
        for r in self.rows.iter().filter(|r| r.verdict == Verdict::Regressed) {
            a.push(format!(
                "::warning title=mcpdef bench regression::{} rose from {} to {} (tolerance {:.0}%)",
                r.metric,
                fmt_value(&r.metric, r.baseline.unwrap_or_default()),
                fmt_value(&r.metric, r.current),
                tolerance(&r.metric) * 100.0
            ));
        }
        if !self.judged() {
            a.push(format!(
                "::warning title=mcpdef bench not compared::{}",
                self.not_judged.join("; ")
            ));
        }
        for why in &self.unjudged {
            a.push(format!("::notice title=mcpdef bench left unjudged::{why}"));
        }
        for g in &self.gate_failures {
            a.push(format!("::error title=mcpdef bench gate::{g}"));
        }
        a
    }
}

fn fmt_value(metric: &str, v: f64) -> String {
    if metric.ends_with("_kb") {
        format!("{:.1} MiB", v / 1024.0)
    } else {
        format!("{v:.2}×")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Allowed, IdleRss, Machine, Params, Scenarios, SlowNeighbour};
    use crate::stats::Summary;

    fn summary(p50: u64, p99: u64) -> Summary {
        Summary {
            p50_us: p50,
            p99_us: p99,
            ..Summary::default()
        }
    }

    fn report(gateway_p99: u64, beside_p99: u64, rss_kb: u64) -> Report {
        Report {
            schema: SCHEMA,
            generated_at_unix: 0,
            mcpdef_version: "mcpdef test".into(),
            commit: None,
            note: None,
            machine: Machine {
                os: "linux".into(),
                arch: "x86_64".into(),
                cpus: 4,
                cpu_model: Some("cpu".into()),
                mem_total_kb: None,
            },
            params: Params {
                quick: false,
                warmup: 1,
                requests: 1,
                concurrency: vec![1],
                slow_ms: 5000,
                neighbour_upstreams: 20,
                neighbour_concurrency: 8,
                neighbour_alone_ms: 1,
                neighbour_beside_ms: 1,
                idle_upstreams: 10,
                idle_load_requests: 1,
            },
            scenarios: Scenarios {
                allowed: vec![Allowed::new(
                    1,
                    summary(100, 100),
                    summary(150, gateway_p99),
                )],
                denied: vec![],
                slow_neighbour: vec![SlowNeighbour {
                    transport: "http".into(),
                    upstreams: 20,
                    slow_ms: 5000,
                    concurrency: 8,
                    alone: summary(100, 100),
                    beside_slow: summary(100, beside_p99),
                    slow_calls_completed: 3,
                    ratio_p50: 0.0,
                    ratio_p99: 0.0,
                }
                .ratios()],
                idle_rss: Some(IdleRss {
                    upstreams: 10,
                    console: false,
                    idle_rss_kb: rss_kb,
                    idle_hwm_kb: None,
                    idle_anon_kb: None,
                    idle_file_kb: None,
                    after_load_rss_kb: rss_kb,
                    after_load_hwm_kb: None,
                    after_load_anon_kb: None,
                    after_load_file_kb: None,
                    load_requests: 1,
                }),
            },
        }
    }

    fn verdict(o: &Outcome, metric: &str) -> Verdict {
        o.rows.iter().find(|r| r.metric == metric).unwrap().verdict
    }

    #[test]
    fn a_rise_past_tolerance_is_a_regression_and_a_fall_an_improvement() {
        let base = report(200, 100, 20_000);
        let cur = report(400, 40, 20_000); // p99 ratio 2.0 → 4.0; neighbour 1.0 → 0.4
        let o = compare(Some(&base), &cur, &[]);
        assert!(o.judged());
        assert_eq!(verdict(&o, "allowed.c1.ratio_p99"), Verdict::Regressed);
        assert_eq!(
            verdict(&o, "slow_neighbour.http.ratio_p99"),
            Verdict::Improved
        );
        assert_eq!(verdict(&o, "idle_rss.idle_rss_kb"), Verdict::Ok);
        assert_eq!(o.regressions(), 1);
    }

    #[test]
    fn idle_memory_with_the_console_open_is_not_judged_against_it_closed() {
        // The committed baselines measured idle memory with the console
        // closed; a run now opens it, and holds about a fifth more.
        let base = report(200, 100, 8_480);
        let mut cur = report(200, 100, 10_445);
        cur.scenarios.idle_rss.as_mut().unwrap().console = true;
        let o = compare(Some(&base), &cur, &[]);
        assert!(o.judged(), "the rest is compared: {:?}", o.not_judged);
        for metric in ["idle_rss.idle_rss_kb", "idle_rss.after_load_rss_kb"] {
            let row = o.rows.iter().find(|r| r.metric == metric).unwrap();
            assert_eq!((row.baseline, row.verdict), (None, Verdict::Unjudged));
        }
        assert_eq!(verdict(&o, "allowed.c1.ratio_p99"), Verdict::Ok);
        assert_eq!(o.regressions(), 0);
        assert_eq!(
            o.unjudged,
            ["idle_rss, measured with the console closed in the baseline and open in this run"]
        );
        assert!(o.render().contains("**Left unjudged:** idle_rss, measured"));
        // Both open: judged as before, a fifth more a regression.
        let mut opened = base.clone();
        opened.scenarios.idle_rss.as_mut().unwrap().console = true;
        let o = compare(Some(&opened), &cur, &[]);
        assert!(o.unjudged.is_empty());
        assert_eq!(verdict(&o, "idle_rss.idle_rss_kb"), Verdict::Regressed);
    }

    #[test]
    fn tolerances_follow_how_noisy_each_kind_of_metric_is() {
        assert_eq!(tolerance("allowed.c1.ratio_p50"), 0.25);
        assert_eq!(tolerance("denied.c1.ratio_p50_vs_direct"), 0.25);
        assert_eq!(tolerance("allowed.c1.ratio_p99"), 0.50);
        assert_eq!(tolerance("allowed.c16.ratio_p50"), 0.50);
        assert_eq!(tolerance("slow_neighbour.http.ratio_p99"), 0.50);
        assert_eq!(tolerance("idle_rss.idle_rss_kb"), 0.20);
    }

    /// `report`, with anonymous memory recorded, as a current run does.
    fn with_anon(mut r: Report, idle_kb: u64, after_load_kb: u64) -> Report {
        let i = r.scenarios.idle_rss.as_mut().unwrap();
        i.idle_anon_kb = Some(idle_kb);
        i.after_load_anon_kb = Some(after_load_kb);
        r
    }

    #[test]
    fn anonymous_memory_has_its_own_bands() {
        assert_eq!(tolerance("idle_rss.idle_anon_kb"), 0.05);
        assert_eq!(tolerance("idle_rss.after_load_anon_kb"), 0.20);
    }

    #[test]
    fn idle_anonymous_memory_is_judged_on_a_tight_band() {
        let base = with_anon(report(200, 100, 20_000), 800, 1_600);
        // +6 % idle anonymous memory: a regression, where RSS would need +20 %.
        let o = compare(
            Some(&base),
            &with_anon(report(200, 100, 20_000), 850, 1_600),
            &[],
        );
        assert_eq!(verdict(&o, "idle_rss.idle_anon_kb"), Verdict::Regressed);
        assert_eq!(verdict(&o, "idle_rss.after_load_anon_kb"), Verdict::Ok);
        assert_eq!(verdict(&o, "idle_rss.idle_rss_kb"), Verdict::Ok);
        // +4 % is within the swing of one binary.
        let o = compare(
            Some(&base),
            &with_anon(report(200, 100, 20_000), 832, 1_600),
            &[],
        );
        assert_eq!(verdict(&o, "idle_rss.idle_anon_kb"), Verdict::Ok);
        // After the burst the band is wider: +15 % passes, +25 % does not.
        let o = compare(
            Some(&base),
            &with_anon(report(200, 100, 20_000), 800, 1_840),
            &[],
        );
        assert_eq!(verdict(&o, "idle_rss.after_load_anon_kb"), Verdict::Ok);
        let o = compare(
            Some(&base),
            &with_anon(report(200, 100, 20_000), 800, 2_000),
            &[],
        );
        assert_eq!(
            verdict(&o, "idle_rss.after_load_anon_kb"),
            Verdict::Regressed
        );
    }

    #[test]
    fn a_metric_missing_from_an_old_baseline_is_left_unjudged() {
        let base = report(200, 100, 20_000); // recorded before anonymous memory was
        let cur = with_anon(report(200, 100, 20_000), 800, 1_600);
        let o = compare(Some(&base), &cur, &[]);
        assert!(o.judged());
        for metric in ["idle_rss.idle_anon_kb", "idle_rss.after_load_anon_kb"] {
            let row = o.rows.iter().find(|r| r.metric == metric).unwrap();
            assert_eq!((row.baseline, row.verdict), (None, Verdict::Unjudged));
        }
        assert_eq!(verdict(&o, "idle_rss.idle_rss_kb"), Verdict::Ok);
        assert_eq!(o.regressions(), 0);
    }

    /// The committed baselines predate anonymous memory. They still load, and a
    /// run that records it is still judged against them on everything else.
    #[test]
    fn the_committed_baselines_still_load_and_compare() {
        for text in [
            include_str!("../baselines/serialized.json"),
            include_str!("../baselines/serialized-quick.json"),
        ] {
            let base: Report = serde_json::from_str(text).unwrap();
            let idle = base.scenarios.idle_rss.as_ref().unwrap();
            assert_eq!((idle.idle_anon_kb, idle.after_load_anon_kb), (None, None));
            let mut cur = base.clone();
            let i = cur.scenarios.idle_rss.as_mut().unwrap();
            (i.idle_anon_kb, i.after_load_anon_kb) = (Some(800), Some(1_600));
            let o = compare(Some(&base), &cur, &[]);
            assert!(o.judged(), "{:?}", o.not_judged);
            assert_eq!(o.regressions(), 0);
            assert_eq!(verdict(&o, "idle_rss.idle_anon_kb"), Verdict::Unjudged);
            assert_eq!(verdict(&o, "allowed.c1.ratio_p50"), Verdict::Ok);
        }
    }

    /// The 200-client baseline holds the slow-neighbour scenario alone, run with
    /// the defaults and `--neighbour-concurrency 200`. A run like that is judged
    /// against it; the default run, at 8 clients, is not.
    #[test]
    fn the_200_client_baseline_judges_runs_at_200_clients() {
        let base: Report =
            serde_json::from_str(include_str!("../baselines/serialized-200-clients.json")).unwrap();
        assert_eq!(
            base.params,
            Params {
                neighbour_concurrency: 200,
                ..Params::defaults(false)
            }
        );
        let mut cur = base.clone();
        cur.scenarios.slow_neighbour = std::mem::take(&mut cur.scenarios.slow_neighbour)
            .into_iter()
            .map(|mut n| {
                n.beside_slow = n.alone.clone(); // no longer held up
                n.ratios()
            })
            .collect();
        let o = compare(
            Some(&base),
            &cur,
            &[
                ("slow_neighbour.http.ratio_p99".into(), 1.1),
                ("slow_neighbour.stdio.ratio_p99".into(), 1.1),
            ],
        );
        assert!(o.judged(), "{:?}", o.not_judged);
        assert!(o.gate_failures.is_empty(), "{:?}", o.gate_failures);
        for transport in ["http", "stdio"] {
            let metric = format!("slow_neighbour.{transport}.ratio_p99");
            assert_eq!(verdict(&o, &metric), Verdict::Improved);
        }

        let eight: Report =
            serde_json::from_str(include_str!("../baselines/serialized.json")).unwrap();
        assert_eq!(
            compare(Some(&eight), &cur, &[]).not_judged,
            ["different run parameters (neighbour_concurrency 8 vs 200)"]
        );
    }

    #[test]
    fn a_different_machine_is_not_compared() {
        let base = report(200, 100, 20_000);
        let mut cur = report(900, 100, 20_000);
        cur.machine.cpus = 2;
        let o = compare(Some(&base), &cur, &[]);
        assert!(!o.judged());
        assert!(o.not_judged[0].contains("CPUs"));
        assert_eq!(o.regressions(), 0);
    }

    #[test]
    fn a_quick_run_is_not_compared_with_a_full_one() {
        let base = report(200, 100, 20_000);
        let mut cur = report(200, 100, 20_000);
        cur.params.quick = true;
        let o = compare(Some(&base), &cur, &[]);
        assert_eq!(o.not_judged, ["a quick run against a full one"]);
    }

    #[test]
    fn a_run_with_another_client_count_is_not_compared_and_says_why() {
        let base = report(200, 100, 20_000);
        let mut cur = report(200, 100, 20_000);
        cur.params.neighbour_concurrency = 200;
        let o = compare(Some(&base), &cur, &[]);
        assert_eq!(
            o.not_judged,
            ["different run parameters (neighbour_concurrency 8 vs 200)"]
        );
        cur.params.concurrency = vec![1, 32];
        let o = compare(Some(&base), &cur, &[]);
        assert_eq!(
            o.not_judged,
            ["different run parameters (concurrency [1] vs [1,32], neighbour_concurrency 8 vs 200)"]
        );
        // Its limits are still checked: they need no baseline.
        let o = compare(
            Some(&base),
            &cur,
            &[("slow_neighbour.http.ratio_p99".into(), 1.1)],
        );
        assert!(o.gate_failures.is_empty(), "{:?}", o.gate_failures);
    }

    #[test]
    fn gates_hold_with_or_without_a_baseline() {
        let cur = report(200, 5_000, 20_000); // slow-neighbour p99 ratio 50×
        let o = compare(
            None,
            &cur,
            &[
                ("slow_neighbour.http.ratio_p99".into(), 1.5),
                ("allowed.c1.ratio_p99".into(), 10.0),
            ],
        );
        assert_eq!(o.gate_failures.len(), 1);
        assert!(o.gate_failures[0].starts_with("slow_neighbour.http.ratio_p99"));
    }

    #[test]
    fn a_gate_on_a_missing_metric_fails_rather_than_passing_silently() {
        let o = compare(None, &report(200, 100, 1), &[("nope".into(), 1.0)]);
        assert_eq!(o.gate_failures.len(), 1);
    }

    #[test]
    fn gate_arguments_parse() {
        assert_eq!(
            parse_gate("slow_neighbour.http.ratio_p99=1.5").unwrap(),
            ("slow_neighbour.http.ratio_p99".to_string(), 1.5)
        );
        assert!(parse_gate("no-equals").is_err());
        assert!(parse_gate("x=abc").is_err());
    }
}
