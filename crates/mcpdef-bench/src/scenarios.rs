// SPDX-License-Identifier: Apache-2.0
//! The four scenarios. Each starts its own gateway on its own scratch directory,
//! so one scenario's ledger, pins and upstream processes never colour another's.

use crate::gateway::{Gateway, Upstream};
use crate::load::{self, Budget, Expect, Load};
use crate::mock::{self, HttpMock, MockTool};
use crate::report::{ratio, Allowed, Denied, IdleRss, Params, SlowNeighbour};
use crate::stats::{summarize, Summary};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// What every scenario needs: the binary under test, this binary (the stdio
/// mock), a client, and the run's parameters.
pub struct Ctx {
    pub mcpdef: PathBuf,
    pub self_exe: PathBuf,
    pub client: reqwest::Client,
    pub params: Params,
}

impl Params {
    /// The default full run, or the CI-sized quick one.
    pub fn defaults(quick: bool) -> Params {
        let slow_ms = if quick { 1_000 } else { 5_000 };
        Params {
            quick,
            warmup: if quick { 100 } else { 300 },
            requests: if quick { 600 } else { 3_000 },
            concurrency: vec![1, 16],
            slow_ms,
            neighbour_upstreams: 20,
            neighbour_concurrency: 8,
            neighbour_alone_ms: if quick { 1_500 } else { 5_000 },
            // Three whole slow calls: long enough that every fast client meets one.
            neighbour_beside_ms: 3 * slow_ms,
            idle_upstreams: 10,
            idle_load_requests: if quick { 300 } else { 1_000 },
        }
    }
}

impl Ctx {
    fn load(
        &self,
        url: &str,
        tools: &[&str],
        expect: Expect,
        concurrency: usize,
        budget: Budget,
    ) -> Load {
        Load {
            client: self.client.clone(),
            url: url.to_string(),
            tools: Arc::new(tools.iter().map(|t| t.to_string()).collect()),
            expect,
            concurrency,
            budget,
        }
    }

    /// Warm up (unmeasured), then measure.
    async fn measure(
        &self,
        url: &str,
        tools: &[&str],
        expect: Expect,
        concurrency: usize,
    ) -> Summary {
        self.load(
            url,
            tools,
            expect,
            concurrency,
            Budget::Requests(self.params.warmup),
        )
        .run()
        .await;
        summarize(
            &self
                .load(
                    url,
                    tools,
                    expect,
                    concurrency,
                    Budget::Requests(self.params.requests),
                )
                .run()
                .await,
        )
    }
}

/// `allowed` and `denied` share one gateway: an HTTP upstream exposing `echo`
/// (allowlisted) and `danger` (not). The allowed call is also made straight to
/// the upstream, at the same client count, so the gateway's cost is a difference
/// measured in one run.
pub async fn allowed_and_denied(
    ctx: &Ctx,
    want_allowed: bool,
    want_denied: bool,
) -> Result<(Vec<Allowed>, Vec<Denied>)> {
    let upstream = mock::spawn_http(vec![MockTool::fast("echo"), MockTool::fast("danger")]).await?;
    let dir = tempfile::tempdir()?;
    let mut gateway = Gateway::start(
        &ctx.mcpdef,
        dir.path(),
        &[Upstream::Http {
            id: "upstream".into(),
            url: upstream.url.clone(),
            allow: vec!["echo".into()],
        }],
        false,
        &ctx.client,
    )
    .await
    .context("starting the gateway for allowed/denied")?;

    let (mut allowed, mut denied) = (Vec::new(), Vec::new());
    for &c in &ctx.params.concurrency {
        eprintln!("  allowed/denied: {c} client(s) — straight to the upstream");
        let direct = ctx
            .measure(&upstream.url, &["echo"], Expect::Success, c)
            .await;
        if want_allowed {
            eprintln!("  allowed/denied: {c} client(s) — through the gateway");
            let via = ctx
                .measure(&gateway.url, &["echo"], Expect::Success, c)
                .await;
            allowed.push(Allowed::new(c, direct.clone(), via));
        }
        if want_denied {
            eprintln!("  allowed/denied: {c} client(s) — denied by the allowlist");
            let refused = ctx
                .measure(&gateway.url, &["danger"], Expect::ToolError, c)
                .await;
            denied.push(Denied {
                concurrency: c,
                ratio_p50_vs_direct: ratio(refused.p50_us, direct.p50_us),
                gateway: refused,
            });
        }
    }
    gateway.stop().await;
    Ok((allowed, denied))
}

/// Upstream transport for the slow-neighbour scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Http,
    Stdio,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Stdio => "stdio",
        }
    }
}

/// The slow-neighbour warm-up makes at least this many calls per client, or
/// `warmup` if that is more. A client's first call opens its connection; with
/// hundreds of clients, `warmup` calls in all could leave some of those first
/// calls in the timed run.
const WARMUP_CALLS_PER_CLIENT: usize = 2;

/// Twenty upstreams, one tool each (`t0`…`t19`). `t0` takes `slow_ms` to answer.
/// Fast calls go round-robin across `t1`…`t19`: first with nothing else in
/// flight, then while one client keeps a call to `t0` in flight the whole time.
///
/// A gateway whose upstreams are independent answers the fast calls just as
/// quickly the second time, so the p99 ratio stays near 1. One that serializes
/// its upstreams makes them wait for `t0`, and the ratio is roughly
/// `slow_ms` over the fast p99.
pub async fn slow_neighbour(ctx: &Ctx, transport: Transport) -> Result<SlowNeighbour> {
    let p = &ctx.params;
    let names: Vec<String> = (0..p.neighbour_upstreams)
        .map(|i| format!("t{i}"))
        .collect();
    let mut mocks: Vec<HttpMock> = Vec::new(); // kept alive until the run ends
    let mut upstreams = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let delay = if i == 0 {
            Duration::from_millis(p.slow_ms)
        } else {
            Duration::ZERO
        };
        let id = format!("s{i}");
        match transport {
            Transport::Http => {
                let m = mock::spawn_http(vec![MockTool::slow(name.clone(), delay)]).await?;
                upstreams.push(Upstream::Http {
                    id,
                    url: m.url.clone(),
                    allow: vec![name.clone()],
                });
                mocks.push(m);
            }
            Transport::Stdio => {
                let mut command = vec![
                    ctx.self_exe.to_string_lossy().into_owned(),
                    "mock-stdio".into(),
                    "--tool".into(),
                    name.clone(),
                ];
                if !delay.is_zero() {
                    command.extend(["--delay-ms".into(), p.slow_ms.to_string()]);
                }
                upstreams.push(Upstream::Stdio {
                    id,
                    command,
                    allow: vec![name.clone()],
                });
            }
        }
    }

    let dir = tempfile::tempdir()?;
    let mut gateway = Gateway::start(&ctx.mcpdef, dir.path(), &upstreams, false, &ctx.client)
        .await
        .with_context(|| {
            format!(
                "starting the gateway for slow-neighbour ({})",
                transport.name()
            )
        })?;
    let fast: Vec<&str> = names[1..].iter().map(String::as_str).collect();
    let c = p.neighbour_concurrency;

    eprintln!("  slow-neighbour ({}): warm-up", transport.name());
    ctx.load(
        &gateway.url,
        &fast,
        Expect::Success,
        c,
        Budget::Requests(p.warmup.max(WARMUP_CALLS_PER_CLIENT * c)),
    )
    .run()
    .await;

    eprintln!("  slow-neighbour ({}): fast calls alone", transport.name());
    let alone = summarize(
        &ctx.load(
            &gateway.url,
            &fast,
            Expect::Success,
            c,
            Budget::For(Duration::from_millis(p.neighbour_alone_ms)),
        )
        .run()
        .await,
    );

    eprintln!(
        "  slow-neighbour ({}): fast calls beside a {} ms call",
        transport.name(),
        p.slow_ms
    );
    let stop = Arc::new(AtomicBool::new(false));
    let busy = tokio::spawn(load::keep_busy(
        ctx.client.clone(),
        gateway.url.clone(),
        names[0].clone(),
        Arc::clone(&stop),
    ));
    // Let the slow call get to the upstream before the fast ones start.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let beside_slow = summarize(
        &ctx.load(
            &gateway.url,
            &fast,
            Expect::Success,
            c,
            Budget::For(Duration::from_millis(p.neighbour_beside_ms)),
        )
        .run()
        .await,
    );
    stop.store(true, Ordering::Relaxed);
    // The slow call in flight would take up to another `slow_ms`; the count of
    // those that finished is all that is needed, so stop waiting after a moment.
    let slow_calls_completed = tokio::time::timeout(Duration::from_millis(p.slow_ms + 2_000), busy)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(0);
    gateway.stop().await;
    drop(mocks);

    Ok(SlowNeighbour {
        transport: transport.name().into(),
        upstreams: p.neighbour_upstreams,
        slow_ms: p.slow_ms,
        concurrency: c,
        alone,
        beside_slow,
        slow_calls_completed,
        ratio_p50: 0.0,
        ratio_p99: 0.0,
    }
    .ratios())
}

/// The gateway process fronting ten stdio upstreams: resident memory once idle,
/// and again after a burst of calls.
pub async fn idle_rss(ctx: &Ctx) -> Result<IdleRss> {
    let p = &ctx.params;
    let names: Vec<String> = (0..p.idle_upstreams).map(|i| format!("t{i}")).collect();
    let upstreams: Vec<Upstream> = names
        .iter()
        .enumerate()
        .map(|(i, name)| Upstream::Stdio {
            id: format!("s{i}"),
            command: vec![
                ctx.self_exe.to_string_lossy().into_owned(),
                "mock-stdio".into(),
                "--tool".into(),
                name.clone(),
            ],
            allow: vec![name.clone()],
        })
        .collect();
    let dir = tempfile::tempdir()?;
    let mut gateway = Gateway::start(&ctx.mcpdef, dir.path(), &upstreams, true, &ctx.client)
        .await
        .context("starting the gateway for idle-rss")?;

    // The console on, and opened: its page, and what its overview asks for.
    let admin = gateway.admin.clone().context("the console is on")?;
    for route in [
        "/",
        "/api/v1/session",
        "/api/v1/info",
        "/api/v1/metrics",
        "/api/v1/servers",
        "/api/v1/audit?limit=200",
    ] {
        let answer = ctx.client.get(format!("{admin}{route}")).send().await?;
        anyhow::ensure!(answer.status().is_success(), "{route}: {}", answer.status());
        answer.bytes().await?;
    }

    eprintln!("  idle-rss: settling");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let idle = gateway
        .memory()
        .context("could not read the gateway's resident memory on this platform")?;

    eprintln!("  idle-rss: {} calls", p.idle_load_requests);
    let tools: Vec<&str> = names.iter().map(String::as_str).collect();
    ctx.load(
        &gateway.url,
        &tools,
        Expect::Success,
        8,
        Budget::Requests(p.idle_load_requests),
    )
    .run()
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = gateway
        .memory()
        .context("could not read the gateway's resident memory")?;
    gateway.stop().await;

    Ok(IdleRss {
        upstreams: p.idle_upstreams,
        console: true,
        idle_rss_kb: idle.rss_kb,
        idle_hwm_kb: idle.hwm_kb,
        idle_anon_kb: idle.anon_kb,
        idle_file_kb: idle.file_kb,
        after_load_rss_kb: after.rss_kb,
        after_load_hwm_kb: after.hwm_kb,
        after_load_anon_kb: after.anon_kb,
        after_load_file_kb: after.file_kb,
        load_requests: p.idle_load_requests,
    })
}
