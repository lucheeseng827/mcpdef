// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-bench` — a load harness for the mcpdef gateway.
//!
//! It runs the **real `mcpdef` binary** as a child process in front of mock MCP
//! upstreams it hosts itself, drives it with concurrent clients, and reports five
//! scenarios as JSON and as Markdown:
//!
//! * **allowed** — an allowlisted `tools/call`, through the gateway and straight to
//!   the upstream in the same run: the difference is what the gateway adds.
//! * **allowed-bearer** — the same through a gateway with `[gateway.auth]` on,
//!   checking an RS256 bearer token against pinned keys on every call.
//! * **denied** — a call the allowlist refuses; no upstream is involved.
//! * **slow-neighbour** — twenty upstreams, one of them slow: are calls to the
//!   other nineteen held up by it? Run over HTTP and over stdio upstreams, from
//!   8 clients or as many as `--neighbour-concurrency` asks for.
//! * **idle-rss** — resident memory of the gateway fronting ten stdio upstreams.
//!
//! `compare` checks a report against a baseline using ratios measured within one
//! run, and only when both came from the same kind of machine with the same
//! parameters. See the crate README for how baselines are kept.
//!
//! `first-call` times something else: the commands README.md gives a new user,
//! from an installed `mcpdef` to its first governed call (see [`first_call`]).
//! `offline` runs those commands and a policy update on a host with no route
//! out, and, under strace, fails if `mcpdef` reaches past loopback (see
//! [`offline`]).

mod bearer;
mod compare;
mod first_call;
mod gateway;
mod load;
mod mock;
mod offline;
mod report;
mod scenarios;
mod stats;
#[cfg(feature = "wasm")]
mod wasm;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use report::{Machine, Params, Report, Scenarios, SCHEMA};
use scenarios::{Ctx, Transport};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "mcpdef-bench",
    version,
    about = "Load harness for the mcpdef gateway: added overhead, denied-call cost, slow-neighbour isolation and idle memory"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the scenarios against an mcpdef binary and write a report.
    Run(RunArgs),
    /// Compare a report with a baseline (ratios only, same machine only), and
    /// check `--max` limits.
    Compare(CompareArgs),
    /// Time the README's commands from an installed mcpdef to its first
    /// governed call, through the gateway and through a Claude Code hook.
    FirstCall(FirstCallArgs),
    /// Run the README's commands and a policy update from an installed mcpdef,
    /// as on a host with no route out: with --strace, fail on any address past
    /// loopback.
    Offline(OfflineArgs),
    /// Serve a mock MCP upstream over stdio. The gateway under test spawns this.
    #[command(hide = true)]
    MockStdio(MockStdioArgs),
}

#[derive(Args)]
struct RunArgs {
    /// The mcpdef binary to measure [default: `mcpdef` beside this binary]
    #[arg(long)]
    mcpdef: Option<PathBuf>,
    /// A CI-sized run: fewer calls, and the slow neighbour at 1 s instead of 5 s.
    #[arg(long)]
    quick: bool,
    /// Scenarios to run, comma-separated.
    #[arg(long, value_enum, value_delimiter = ',', default_value = DEFAULT_SCENARIOS)]
    scenarios: Vec<Scenario>,
    /// The component wasm-instantiate makes instances of.
    #[cfg_attr(not(feature = "wasm"), allow(dead_code))]
    #[arg(long, default_value = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../mcpdef-sandbox/tests/fixtures/echo_component.wasm"
    ))]
    wasm_component: PathBuf,
    /// How long the slow neighbour takes to answer, in milliseconds.
    #[arg(long)]
    slow_ms: Option<u64>,
    /// Client counts for the allowed and denied scenarios, comma-separated.
    #[arg(long, value_delimiter = ',', value_parser = clients)]
    concurrency: Option<Vec<usize>>,
    /// Clients calling the fast upstreams in the slow-neighbour scenario
    /// [default: 8]. The slow neighbour's own caller is one more.
    #[arg(long, value_parser = clients)]
    neighbour_concurrency: Option<usize>,
    /// Measured calls per allowed / denied run.
    #[arg(long)]
    requests: Option<usize>,
    /// Write the JSON report to this file.
    #[arg(long)]
    out: Option<PathBuf>,
    /// A line describing the machine or the run, kept in the report.
    #[arg(long)]
    note: Option<String>,
    /// The commit being measured [default: $GITHUB_SHA, then `git rev-parse HEAD`]
    #[arg(long)]
    commit: Option<String>,
}

impl RunArgs {
    /// The run's parameters: the defaults for a full or a quick run, with the
    /// options given on top.
    fn params(&self) -> Params {
        let mut params = Params::defaults(self.quick);
        if let Some(ms) = self.slow_ms {
            params.slow_ms = ms;
            params.neighbour_beside_ms = 3 * ms;
        }
        if let Some(c) = &self.concurrency {
            params.concurrency = c.clone();
        }
        if let Some(n) = self.neighbour_concurrency {
            params.neighbour_concurrency = n;
        }
        if let Some(n) = self.requests {
            params.requests = n;
        }
        params
    }
}

/// A client count, which must be at least one: zero would run one client and
/// report none.
fn clients(s: &str) -> Result<usize, String> {
    match s.trim().parse::<usize>() {
        Ok(0) => Err("a run needs at least 1 client".into()),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("`{s}` is not a number of clients")),
    }
}

/// A number of runs, which must be at least one: zero would time nothing and
/// pass.
fn runs(s: &str) -> Result<usize, String> {
    match s.trim().parse::<usize>() {
        Ok(0) => Err("first-call needs at least 1 run".into()),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("`{s}` is not a number of runs")),
    }
}

/// Every scenario this build can run: wasm-instantiate only in a build with the
/// `wasm` feature, which links the sandbox in.
#[cfg(feature = "wasm")]
const DEFAULT_SCENARIOS: &str =
    "allowed,allowed-bearer,allowed-bearer-fsync,denied,slow-neighbour,idle-rss,wasm-instantiate";
#[cfg(not(feature = "wasm"))]
const DEFAULT_SCENARIOS: &str =
    "allowed,allowed-bearer,allowed-bearer-fsync,denied,slow-neighbour,idle-rss";

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Scenario {
    Allowed,
    AllowedBearer,
    AllowedBearerFsync,
    Denied,
    SlowNeighbour,
    IdleRss,
    WasmInstantiate,
}

#[derive(Args)]
struct CompareArgs {
    /// The report to judge. Repeat it for several runs of one build: each metric
    /// is then judged on its best run.
    #[arg(long, required = true)]
    current: Vec<PathBuf>,
    /// The report to judge it against, repeatable as `--current` is. Without
    /// one, only `--max` limits are checked.
    #[arg(long)]
    baseline: Vec<PathBuf>,
    /// Fail when a metric is over a limit: `--max slow_neighbour.http.ratio_p99=1.5`.
    /// Repeatable. Checked with or without a baseline.
    #[arg(long = "max", value_parser = compare::parse_gate)]
    gates: Vec<(String, f64)>,
    /// Fail when no comparable baseline was compared against — for the runs whose
    /// result someone acts on, where a check that judged nothing must not pass.
    #[arg(long)]
    require_comparable: bool,
    /// Fail on a regression beyond tolerance, not just warn.
    #[arg(long)]
    fail_on_regression: bool,
}

#[derive(Args)]
struct FirstCallArgs {
    /// The mcpdef binary to measure [default: `mcpdef` beside this binary]
    #[arg(long)]
    mcpdef: Option<PathBuf>,
    /// How many times to run both paths, each time from a fresh home directory
    /// and project.
    #[arg(long, default_value_t = 3, value_parser = runs)]
    runs: usize,
    /// Fail when a path takes longer than this many seconds.
    #[arg(long, default_value_t = 60)]
    max_seconds: u64,
    /// Write the JSON report to this file.
    #[arg(long)]
    out: Option<PathBuf>,
    /// A line describing the machine or the run, kept in the report.
    #[arg(long)]
    note: Option<String>,
    /// The commit being measured [default: $GITHUB_SHA, then `git rev-parse HEAD`]
    #[arg(long)]
    commit: Option<String>,
}

#[derive(Args)]
struct OfflineArgs {
    /// The mcpdef binary to run [default: `mcpdef` beside this binary]
    #[arg(long)]
    mcpdef: Option<PathBuf>,
    /// Fail when a command takes longer than this many seconds.
    #[arg(long, default_value_t = 60)]
    max_seconds: u64,
    /// Run again under `strace -f`, every process it starts with it, and fail
    /// on any network call to an address past loopback, or to port 53.
    #[arg(long)]
    strace: bool,
}

#[derive(Args)]
struct MockStdioArgs {
    /// A tool to expose. Repeatable.
    #[arg(long = "tool", required = true)]
    tools: Vec<String>,
    /// How long every call takes to answer, in milliseconds.
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        // A spawned upstream: plain blocking stdio, no async runtime needed.
        Cmd::MockStdio(a) => {
            let delay = Duration::from_millis(a.delay_ms);
            mock::run_stdio(
                a.tools
                    .into_iter()
                    .map(|name| mock::MockTool::slow(name, delay))
                    .collect(),
            )
        }
        Cmd::Run(a) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run(a)),
        Cmd::Compare(a) => compare_reports(a),
        Cmd::FirstCall(a) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(first_call(a)),
        Cmd::Offline(a) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(offline(a)),
    }
}

/// The mcpdef binary `given`, or the one beside `self_exe`, by its absolute
/// path: `first-call` runs it from directories of its own.
fn mcpdef_binary(given: Option<PathBuf>, self_exe: &Path) -> Result<PathBuf> {
    let mcpdef = match given {
        Some(p) => p,
        None => self_exe.with_file_name(format!("mcpdef{}", std::env::consts::EXE_SUFFIX)),
    };
    if !mcpdef.is_file() {
        bail!(
            "no mcpdef binary at {} — build it (`cargo build --release -p mcpdef`) or pass --mcpdef",
            mcpdef.display()
        );
    }
    std::fs::canonicalize(&mcpdef).with_context(|| format!("finding {}", mcpdef.display()))
}

async fn run(a: RunArgs) -> Result<()> {
    if cfg!(not(feature = "wasm")) && a.scenarios.contains(&Scenario::WasmInstantiate) {
        bail!(
            "wasm-instantiate needs a harness built with the `wasm` feature: \
             cargo build --release -p mcpdef-bench --features wasm"
        );
    }
    let params = a.params();
    let self_exe = std::env::current_exe().context("locating this binary")?;
    let mcpdef = mcpdef_binary(a.mcpdef, &self_exe)?;

    // Generous enough that the slow neighbour's calls are timed, never cut off.
    let timeout = Duration::from_millis((4 * params.slow_ms).max(30_000));
    let ctx = Ctx {
        mcpdef: mcpdef.clone(),
        self_exe,
        client: load::client(timeout)?,
        params: params.clone(),
    };

    let want = |s| a.scenarios.contains(&s);
    let mut scenarios = Scenarios::default();
    let calls = scenarios::Calls {
        allowed: want(Scenario::Allowed),
        allowed_bearer: want(Scenario::AllowedBearer),
        allowed_bearer_fsync: want(Scenario::AllowedBearerFsync),
        denied: want(Scenario::Denied),
    };
    if calls.allowed || calls.allowed_bearer || calls.allowed_bearer_fsync || calls.denied {
        eprintln!("mcpdef-bench: allowed / allowed-bearer / allowed-bearer-fsync / denied");
        let measured = scenarios::allowed_and_denied(&ctx, calls).await?;
        scenarios.allowed = measured.allowed;
        scenarios.allowed_bearer = measured.allowed_bearer;
        scenarios.allowed_bearer_fsync = measured.allowed_bearer_fsync;
        scenarios.denied = measured.denied;
    }
    if want(Scenario::SlowNeighbour) {
        for transport in [Transport::Http, Transport::Stdio] {
            eprintln!("mcpdef-bench: slow-neighbour over {}", transport.name());
            scenarios
                .slow_neighbour
                .push(scenarios::slow_neighbour(&ctx, transport).await?);
        }
    }
    if want(Scenario::IdleRss) {
        eprintln!("mcpdef-bench: idle-rss");
        scenarios.idle_rss = Some(scenarios::idle_rss(&ctx).await?);
    }
    #[cfg(feature = "wasm")]
    if want(Scenario::WasmInstantiate) {
        eprintln!("mcpdef-bench: wasm-instantiate");
        scenarios.wasm_instantiate =
            Some(wasm::wasm_instantiate(&a.wasm_component, params.warmup, params.requests).await?);
    }

    let report = Report {
        schema: SCHEMA,
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        mcpdef_version: gateway::version(&mcpdef)?,
        commit: a.commit.or_else(detect_commit),
        note: a.note,
        machine: machine(),
        params,
        scenarios,
    };
    if let Some(out) = &a.out {
        std::fs::write(out, serde_json::to_string_pretty(&report)? + "\n")
            .with_context(|| format!("writing {}", out.display()))?;
        eprintln!("mcpdef-bench: report written to {}", out.display());
    }
    print!("{}", report.render());
    Ok(())
}

async fn first_call(a: FirstCallArgs) -> Result<()> {
    if cfg!(windows) {
        bail!("first-call runs the hook through `sh`, as Claude Code does on Linux and macOS");
    }
    let self_exe = std::env::current_exe().context("locating this binary")?;
    let mcpdef = mcpdef_binary(a.mcpdef, &self_exe)?;
    let max = Duration::from_secs(a.max_seconds);
    eprintln!("mcpdef-bench: first-call, {} run(s)", a.runs);
    let runs = first_call::measure(&mcpdef, &self_exe, a.runs, max).await?;
    let report = first_call::Report {
        schema: first_call::SCHEMA,
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        mcpdef_version: gateway::version(&mcpdef)?,
        commit: a.commit.or_else(detect_commit),
        note: a.note,
        machine: machine(),
        max_ms: a.max_seconds.saturating_mul(1000),
        runs,
    };
    if let Some(out) = &a.out {
        std::fs::write(out, serde_json::to_string_pretty(&report)? + "\n")
            .with_context(|| format!("writing {}", out.display()))?;
        eprintln!("mcpdef-bench: report written to {}", out.display());
    }
    print!("{}", report.render());
    let over = report.over();
    if !over.is_empty() {
        bail!("past the limit: {}", over.join("; "));
    }
    Ok(())
}

async fn offline(a: OfflineArgs) -> Result<()> {
    if cfg!(windows) {
        bail!("offline reloads the gateway with SIGHUP, and runs the hook through `sh`");
    }
    let self_exe = std::env::current_exe().context("locating this binary")?;
    let mcpdef = mcpdef_binary(a.mcpdef, &self_exe)?;
    if a.strace {
        return offline_traced(&self_exe, &mcpdef, a.max_seconds);
    }
    let m = machine();
    println!(
        "## mcpdef-bench offline — {}\n\n{} {}{}\n",
        gateway::version(&mcpdef)?,
        m.os,
        m.arch,
        detect_commit()
            .map(|c| format!(" · commit `{}`", c.chars().take(12).collect::<String>()))
            .unwrap_or_default(),
    );
    let done = offline::check(&mcpdef, &self_exe, Duration::from_secs(a.max_seconds)).await?;
    for step in done {
        println!("- ✓ {step}");
    }
    Ok(())
}

/// `offline`, run again under `strace -f`, then judged on what it did on the
/// network.
fn offline_traced(self_exe: &Path, mcpdef: &Path, max_seconds: u64) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("--strace runs the steps under strace, which is Linux's");
    }
    let scratch = tempfile::tempdir().context("making a scratch directory")?;
    let trace = scratch.path().join("network.trace");
    let status = std::process::Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=%network", "-o"])
        .arg(&trace)
        .arg(self_exe)
        .args([
            "offline",
            "--max-seconds",
            &max_seconds.to_string(),
            "--mcpdef",
        ])
        .arg(mcpdef)
        .status()
        .context("running strace: install it, or run without --strace")?;
    if !status.success() {
        bail!("the steps failed under strace ({status})");
    }
    let text =
        std::fs::read_to_string(&trace).with_context(|| format!("reading {}", trace.display()))?;
    let traced = offline::Traced::read(&text);
    let mark = if traced.outward.is_empty() {
        "✓"
    } else {
        "✗"
    };
    println!("- {mark} {}", traced.render());
    if !traced.outward.is_empty() {
        bail!(
            "{} network call(s) reached past loopback",
            traced.outward.len()
        );
    }
    Ok(())
}

fn compare_reports(a: CompareArgs) -> Result<()> {
    let read = |paths: &[PathBuf]| -> Result<Vec<Report>> {
        paths.iter().map(|p| read_report(p)).collect()
    };
    let outcome = compare::compare_best(&read(&a.baseline)?, &read(&a.current)?, &a.gates);
    print!("{}", outcome.render());
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        for line in outcome.annotations() {
            println!("{line}");
        }
    }
    if !outcome.gate_failures.is_empty() {
        bail!("{} limit(s) broken", outcome.gate_failures.len());
    }
    if a.require_comparable && !outcome.judged() {
        bail!(
            "no comparable baseline was compared against: {}",
            outcome.not_judged.join("; ")
        );
    }
    if a.fail_on_regression && outcome.regressions() > 0 {
        bail!("{} metric(s) regressed", outcome.regressions());
    }
    Ok(())
}

fn read_report(path: &Path) -> Result<Report> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn detect_commit() -> Option<String> {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        if !sha.is_empty() {
            return Some(sha);
        }
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !sha.is_empty()).then_some(sha)
}

fn machine() -> Machine {
    let proc_field = |file: &str, key: &str| -> Option<String> {
        std::fs::read_to_string(file).ok()?.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    Machine {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        cpu_model: proc_field("/proc/cpuinfo", "model name"),
        mem_total_kb: proc_field("/proc/meminfo", "MemTotal")
            .and_then(|v| v.trim_end_matches("kB").trim().parse().ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn run_args(args: &[&str]) -> Result<RunArgs, clap::Error> {
        let argv = ["mcpdef-bench", "run"].iter().chain(args);
        match Cli::try_parse_from(argv)?.cmd {
            Cmd::Run(a) => Ok(a),
            _ => unreachable!("parsed as `run`"),
        }
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_slow_neighbours_client_count_is_a_run_parameter() {
        assert_eq!(run_args(&[]).unwrap().params().neighbour_concurrency, 8);
        let quick = run_args(&["--quick"]).unwrap().params();
        assert_eq!(quick.neighbour_concurrency, 8);

        let params = run_args(&["--neighbour-concurrency", "200"])
            .unwrap()
            .params();
        assert_eq!(params.neighbour_concurrency, 200);
        // It changes nothing else, so only the slow-neighbour scenario differs.
        let as_default = Params {
            neighbour_concurrency: 8,
            ..params
        };
        assert_eq!(as_default, Params::defaults(false));
    }

    #[test]
    fn a_run_with_no_clients_is_refused() {
        for args in [
            &["--neighbour-concurrency", "0"][..],
            &["--concurrency", "1,0"],
        ] {
            let e = run_args(args).err().expect("refused");
            assert!(e.to_string().contains("at least 1 client"), "{e}");
        }
        let e = run_args(&["--neighbour-concurrency", "many"])
            .err()
            .expect("refused");
        assert!(e.to_string().contains("not a number of clients"), "{e}");
        assert_eq!(
            run_args(&["--concurrency", "1,16"])
                .unwrap()
                .params()
                .concurrency,
            [1, 16]
        );
    }
}
