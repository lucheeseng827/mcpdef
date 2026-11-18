// SPDX-License-Identifier: Apache-2.0
//! `[gateway.otel]`: a gateway's governed requests reach an OTLP/HTTP
//! endpoint as spans, each in the trace its caller named, through the real
//! binary.
//!
//! - A tool call's span is the caller's tool execution: in the trace its
//!   `_meta.traceparent` names, else its `traceparent` header's, under the
//!   caller's span, with the pinned digest of the tool's definition.
//! - A refused call's span is an error, named by the rule that refused it.
//! - `mcpdef audit tail --format otlp` gives the same spans, ids and all.
//! - An endpoint that is busy holds the spans back until it takes them; one
//!   that refuses them for good has them dropped, and takes the next.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef_core::{method, Id, Message};
use serde_json::{json, Value};
use std::io::BufRead;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

const TOKEN: &str = "otlp-token-for-the-test-0123";
const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";
const HEADER_TRACE: &str = "0af7651916cd43dd8448eb211c80319c";
const HEADER_PARENT: &str = "b7ad6b7169203331";

/// An OTLP/HTTP receiver: each request it took, and the statuses it answers
/// the next ones with before it takes any.
#[derive(Default)]
struct Collector {
    taken: Mutex<Vec<(HeaderMap, Value)>>,
    refusals: Mutex<Vec<StatusCode>>,
    refused: Mutex<usize>,
}

impl Collector {
    /// The spans of every request it took, in order.
    fn spans(&self) -> Vec<Value> {
        self.taken
            .lock()
            .unwrap()
            .iter()
            .flat_map(|(_, body)| {
                body["resourceSpans"][0]["scopeSpans"][0]["spans"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Its spans, once it has taken at least `n`.
    async fn wait_for(&self, n: usize) -> Vec<Value> {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let spans = self.spans();
            if spans.len() >= n {
                return spans;
            }
            assert!(Instant::now() < until, "{} span(s) of {n}", spans.len());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn traces(State(c): State<Arc<Collector>>, headers: HeaderMap, body: String) -> Response {
    let refusal = {
        let mut refusals = c.refusals.lock().unwrap();
        (!refusals.is_empty()).then(|| refusals.remove(0))
    };
    if let Some(status) = refusal {
        *c.refused.lock().unwrap() += 1;
        return (status, [(header::RETRY_AFTER, "1")], "evald: not now\n").into_response();
    }
    let body: Value = serde_json::from_str(&body).unwrap();
    c.taken.lock().unwrap().push((headers, body));
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"partialSuccess":null}"#,
    )
        .into_response()
}

/// A collector listening on a port of its own, and its address.
async fn collector() -> (Arc<Collector>, String) {
    let c = Arc::new(Collector::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/traces", post(traces))
        .with_state(Arc::clone(&c));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (c, format!("http://{addr}"))
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A gateway fronting the mock, its spans sent to `endpoint`; what it logs,
/// and the port it listens on.
async fn gateway(dir: &Path, endpoint: &str) -> (Running, Arc<Mutex<Vec<String>>>, u16) {
    let config = format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\npins = {pins:?}\n\n\
         [gateway.otel]\nendpoint = {endpoint:?}\ntoken = {{ env = \"MCPDEF_OTLP_TOKEN\" }}\n\
         service_name = \"gateway-test\"\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\"]\n",
        audit = dir.join("audit.log"),
        pins = dir.join("pins.toml"),
    );
    let path = dir.join("mcpdef.toml");
    std::fs::write(&path, config).unwrap();
    let mut child = Command::new(BIN)
        .args(["run", "--http", "--config"])
        .arg(&path)
        .env("MCPDEF_OTLP_TOKEN", TOKEN)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let running = Running(child);
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                log.lock().unwrap().push(line);
            }
        });
    }
    let until = Instant::now() + Duration::from_secs(20);
    let ready = loop {
        if let Some(line) = log.lock().unwrap().iter().find(|l| l.contains(" ready ")) {
            break line.clone();
        }
        assert!(
            Instant::now() < until,
            "no ready line: {:#?}",
            log.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        ready.contains(&format!(" · spans to {endpoint}/v1/traces")),
        "{ready}"
    );
    let port = mcpdef_testkit::listening_port(&ready, "streamable-http ");
    (running, log, port)
}

/// What the gateway logged, once a line of it holds `text`. The exporter logs
/// as it reads the endpoint's answer, which comes after the endpoint holds the
/// spans, and its lines reach the test through a pipe.
async fn logged(log: &Mutex<Vec<String>>, text: &str) -> String {
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        let lines = log.lock().unwrap().join("\n");
        if lines.contains(text) {
            return lines;
        }
        assert!(Instant::now() < until, "never logged {text:?}: {lines}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Call `tool` through the gateway on `port`, with `meta` as the request's
/// `_meta` and `headers` as its own: what it answered.
async fn call(port: u16, tool: &str, meta: Option<Value>, headers: &[(&str, &str)]) -> Value {
    let mut params = json!({ "name": tool, "arguments": { "text": "hi" } });
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    let request = Message::request(Id::Num(1), method::TOOLS_CALL, Some(params));
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut post = client
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(request.to_json_line());
    for (name, value) in headers {
        post = post.header(*name, *value);
    }
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match post.try_clone().unwrap().send().await {
            Ok(answer) => return serde_json::from_str(&answer.text().await.unwrap()).unwrap(),
            Err(e) if Instant::now() > until => panic!("{e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

fn attr<'v>(span: &'v Value, key: &str) -> Option<&'v Value> {
    span["attributes"]
        .as_array()?
        .iter()
        .find(|a| a["key"] == key)
        .map(|a| &a["value"])
}

fn string<'v>(span: &'v Value, key: &str) -> Option<&'v str> {
    attr(span, key)?["stringValue"].as_str()
}

/// The span of the call to `tool`, the `n`th one made.
fn span_of<'s>(spans: &'s [Value], tool: &str, n: usize) -> &'s Value {
    spans
        .iter()
        .filter(|s| string(s, "gen_ai.tool.name") == Some(tool))
        .nth(n)
        .unwrap_or_else(|| panic!("no span {n} for {tool}: {spans:#?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_governed_call_is_a_span_in_its_callers_trace() {
    let dir = tempfile::tempdir().unwrap();
    let (collector, endpoint) = collector().await;
    let (_running, _log, port) = gateway(dir.path(), &endpoint).await;

    let traceparent = format!("00-{TRACE}-{PARENT}-01");
    let header = format!("00-{HEADER_TRACE}-{HEADER_PARENT}-01");
    // In `_meta`, with a header of another trace beside it: `_meta` wins.
    let allowed = call(
        port,
        "echo",
        Some(json!({ "traceparent": traceparent })),
        &[("traceparent", header.as_str())],
    )
    .await;
    assert_eq!(allowed["result"]["isError"], false, "{allowed}");
    // A header alone.
    let refused = call(
        port,
        "delete_repo",
        None,
        &[("traceparent", header.as_str())],
    )
    .await;
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    // Neither, and a `_meta` one that does not read.
    call(
        port,
        "echo",
        Some(json!({ "traceparent": "00-zz-zz-01" })),
        &[],
    )
    .await;

    let spans = collector.wait_for(3).await;
    {
        let taken = collector.taken.lock().unwrap();
        let (headers, body) = &taken[0];
        assert_eq!(headers[header::AUTHORIZATION], format!("Bearer {TOKEN}"));
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let resource = &body["resourceSpans"][0]["resource"]["attributes"][0];
        assert_eq!(resource["value"]["stringValue"], "gateway-test");
    }

    let echo = span_of(&spans, "echo", 0);
    assert_eq!(echo["traceId"], TRACE);
    assert_eq!(echo["parentSpanId"], PARENT);
    assert_eq!(echo["name"], "tools/call echo");
    assert_eq!(echo["kind"], 2);
    assert!(echo.get("status").is_none(), "{echo}");
    assert_eq!(string(echo, "gen_ai.operation.name"), Some("execute_tool"));
    assert_eq!(string(echo, "mcpdef.server"), Some("mock"));
    assert_eq!(string(echo, "mcpdef.decision"), Some("allow"));
    let digest = string(echo, "mcpdef.tool_digest").unwrap();
    assert!(
        digest.starts_with("sha256:") && digest.len() == 71,
        "{digest}"
    );
    assert!(string(echo, "client.address").is_some());

    let refused = span_of(&spans, "delete_repo", 0);
    assert_eq!(refused["traceId"], HEADER_TRACE);
    assert_eq!(refused["parentSpanId"], HEADER_PARENT);
    assert_eq!(refused["status"]["code"], 2);
    let rule = string(refused, "mcpdef.rule").unwrap();
    assert_eq!(string(refused, "error.type"), Some(rule));
    assert_eq!(refused["status"]["message"], rule);

    let untraced = span_of(&spans, "echo", 1);
    let trace = untraced["traceId"].as_str().unwrap();
    assert!(
        trace.len() == 32 && trace != TRACE && trace != HEADER_TRACE,
        "{trace}"
    );
    assert!(untraced.get("parentSpanId").is_none(), "{untraced}");

    // The ledger keeps the trace, verifies, and exports the same spans.
    let audit = dir.path().join("audit.log");
    let ledger = std::fs::read_to_string(&audit).unwrap();
    assert!(
        ledger.contains(&format!("\"trace_id\":\"{TRACE}\"")),
        "{ledger}"
    );
    assert!(
        ledger.contains(&format!("\"parent_id\":\"{PARENT}\"")),
        "{ledger}"
    );
    let verified = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&audit)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");
    let tail = Command::new(BIN)
        .args(["audit", "tail", "--format", "otlp", "--path"])
        .arg(&audit)
        .output()
        .unwrap();
    assert!(tail.status.success(), "{tail:?}");
    let exported: Vec<Value> = String::from_utf8(tail.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let request: Value = serde_json::from_str(line).unwrap();
            request["resourceSpans"][0]["scopeSpans"][0]["spans"][0].clone()
        })
        .collect();
    let ids = |spans: &[Value]| -> Vec<(Value, Value)> {
        spans
            .iter()
            .map(|s| (s["traceId"].clone(), s["spanId"].clone()))
            .collect()
    };
    assert_eq!(ids(&exported), ids(&spans), "the same spans, ids and all");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_endpoint_gets_the_spans_later_and_a_refusing_one_the_next_ones() {
    let dir = tempfile::tempdir().unwrap();
    let (collector, endpoint) = collector().await;
    // Busy twice, then taking.
    *collector.refusals.lock().unwrap() = vec![StatusCode::SERVICE_UNAVAILABLE; 2];
    let (_running, log, port) = gateway(dir.path(), &endpoint).await;

    call(port, "echo", None, &[]).await;
    let spans = collector.wait_for(1).await;
    assert_eq!(spans.len(), 1);
    assert_eq!(*collector.refused.lock().unwrap(), 2);
    let lines = logged(&log, "takes spans again, after 2 failed tries").await;
    assert!(
        lines.contains("failed: it answered 503; trying again"),
        "{lines}"
    );

    // Refused for good: dropped, and the next call's span still goes.
    *collector.refusals.lock().unwrap() = vec![StatusCode::BAD_REQUEST];
    call(port, "echo", None, &[]).await;
    let until = Instant::now() + Duration::from_secs(20);
    while *collector.refused.lock().unwrap() < 3 {
        assert!(Instant::now() < until, "never refused");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    call(port, "echo", None, &[]).await;
    let spans = collector.wait_for(2).await;
    assert_eq!(spans.len(), 2, "the refused span is not sent again");
    let lines = logged(
        &log,
        "refused 1 span(s) with 400: evald: not now; they are not sent again",
    )
    .await;
    assert!(!lines.contains(TOKEN), "the token is never logged");
}
