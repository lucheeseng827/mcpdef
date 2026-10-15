// SPDX-License-Identifier: Apache-2.0
//! The load generator: `concurrency` workers, each sending one `tools/call` at a
//! time and timing it from the first byte sent to the last byte received.
//!
//! Every reply is checked, not just timed. A call counts as a sample only if it
//! came back the way the scenario expects — a result for an allowed call, a
//! tool error for a denied one — so a gateway that got faster by answering
//! wrongly shows up as errors rather than as a speed-up.

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What a correct reply to one call looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// A `result` with `isError: false`.
    Success,
    /// A `result` with `isError: true` — how the gateway reports a denial.
    ToolError,
}

/// How much load one run generates.
#[derive(Clone, Copy, Debug)]
pub enum Budget {
    Requests(usize),
    For(Duration),
}

/// One load run: who to call, with what, how hard, for how long.
#[derive(Clone)]
pub struct Load {
    pub client: Client,
    pub url: String,
    /// Tools to call, round-robin across the whole run.
    pub tools: Arc<Vec<String>>,
    pub expect: Expect,
    pub concurrency: usize,
    pub budget: Budget,
}

/// Latencies of the calls that came back correct, and a count of those that did not.
#[derive(Clone, Debug, Default)]
pub struct Samples {
    pub micros: Vec<u64>,
    pub errors: u64,
    pub wall: Duration,
}

/// The load generator's HTTP client. Never proxied: every target is loopback, and
/// a proxy configured in the environment would otherwise sit in the timed path.
pub fn client(timeout: Duration) -> reqwest::Result<Client> {
    // reqwest needs a crypto provider installed before it builds a client.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .no_proxy()
        .timeout(timeout)
        .pool_max_idle_per_host(512)
        .build()
}

impl Load {
    pub async fn run(&self) -> Samples {
        let started = Instant::now();
        let (limit, deadline) = match self.budget {
            Budget::Requests(n) => (n, None),
            Budget::For(d) => (usize::MAX, Some(started + d)),
        };
        let next = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(self.concurrency);
        for _ in 0..self.concurrency.max(1) {
            let load = self.clone();
            let next = Arc::clone(&next);
            workers.push(tokio::spawn(async move {
                let mut micros = Vec::new();
                let mut errors = 0u64;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= limit || deadline.is_some_and(|d| Instant::now() >= d) {
                        break;
                    }
                    let tool = &load.tools[i % load.tools.len()];
                    let t0 = Instant::now();
                    let ok = call(&load.client, &load.url, i as u64 + 1, tool, load.expect).await;
                    let us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
                    if ok {
                        micros.push(us);
                    } else {
                        errors += 1;
                    }
                }
                (micros, errors)
            }));
        }
        let mut samples = Samples::default();
        for worker in workers {
            if let Ok((micros, errors)) = worker.await {
                samples.micros.extend(micros);
                samples.errors += errors;
            }
        }
        samples.wall = started.elapsed();
        samples
    }
}

/// Keep calling `tool` until `stop` is set, counting the calls that complete —
/// the slow neighbour, holding one slow call in flight for the whole phase.
pub async fn keep_busy(client: Client, url: String, tool: String, stop: Arc<AtomicBool>) -> u64 {
    let mut done = 0u64;
    let mut id = 1_000_000_000u64;
    while !stop.load(Ordering::Relaxed) {
        id += 1;
        if call(&client, &url, id, &tool, Expect::Success).await {
            done += 1;
        }
    }
    done
}

/// Send one `tools/call` and check the reply.
pub async fn call(client: &Client, url: &str, id: u64, tool: &str, expect: Expect) -> bool {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": { "text": "mcpdef-bench" } }
    })
    .to_string();
    let Ok(resp) = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .body(body)
        .send()
        .await
    else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(bytes) = resp.bytes().await else {
        return false;
    };
    let Ok(reply) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let is_error = reply.pointer("/result/isError").and_then(Value::as_bool);
    match expect {
        Expect::Success => is_error == Some(false),
        Expect::ToolError => is_error == Some(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{spawn_http, MockTool};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_run_against_a_mock_counts_every_call() {
        let mock = spawn_http(vec![MockTool::fast("echo")]).await.unwrap();
        let load = Load {
            client: client(Duration::from_secs(10)).unwrap(),
            url: mock.url.clone(),
            tools: Arc::new(vec!["echo".into()]),
            expect: Expect::Success,
            concurrency: 4,
            budget: Budget::Requests(40),
        };
        let samples = load.run().await;
        assert_eq!(samples.micros.len(), 40);
        assert_eq!(samples.errors, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reply_that_is_not_the_expected_kind_is_an_error() {
        let mock = spawn_http(vec![MockTool::fast("echo")]).await.unwrap();
        let load = Load {
            client: client(Duration::from_secs(10)).unwrap(),
            url: mock.url.clone(),
            tools: Arc::new(vec!["echo".into(), "missing".into()]),
            // The mock answers `echo` with a result and `missing` with a JSON-RPC
            // error: neither is a tool error, so every call must count as wrong.
            expect: Expect::ToolError,
            concurrency: 2,
            budget: Budget::Requests(10),
        };
        let samples = load.run().await;
        assert!(samples.micros.is_empty());
        assert_eq!(samples.errors, 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_run_stops_near_its_deadline() {
        let mock = spawn_http(vec![MockTool::fast("echo")]).await.unwrap();
        let load = Load {
            client: client(Duration::from_secs(10)).unwrap(),
            url: mock.url.clone(),
            tools: Arc::new(vec!["echo".into()]),
            expect: Expect::Success,
            concurrency: 2,
            budget: Budget::For(Duration::from_millis(200)),
        };
        let samples = load.run().await;
        assert!(!samples.micros.is_empty());
        assert!(samples.wall < Duration::from_secs(5));
    }
}
