// SPDX-License-Identifier: Apache-2.0
//! `x-mcp-header`: tool parameters a server asks to see mirrored into
//! `Mcp-Param-{Name}` HTTP headers, on both of MCPdef's sides.
//!
//! - As a client to its upstreams, MCPdef mirrors: a modern Streamable-HTTP
//!   server must reject a call whose annotated argument is in the body with no
//!   matching header, so without this a tool that asks for one cannot be
//!   called through MCPdef at all.
//! - As a server to its clients, it validates: it reads the body of every
//!   call, and the revision has anything that does check the headers against
//!   it, `400` + `-32020` when they disagree.
//! - A tool whose annotations break the revision's rules is not served. The
//!   revision has a client exclude it from `tools/list`; an annotation
//!   carrying CR or LF would otherwise be a header injection on requests MCPdef
//!   sends.
//!
//! All three follow a tool's definition as its server lists it *now*: after a
//! re-list on `notifications/tools/list_changed`, and after a restart.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_audit::Record;
use mcpdef_core::wire::{
    decode_header_value, encode_header_value, error_code, header, WireMode, SPEC_2026_07_28,
};
use mcpdef_core::{method, Id, Message};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// How long a test waits for a re-list or a restart. Far past either, so a
/// slow machine does not fail a test that is right.
const PATIENCE: Duration = Duration::from_secs(10);

/// The revision's `execute_sql` example, its `region` annotated `header`.
fn execute_sql(header: &str) -> Value {
    json!({
        "name": "execute_sql",
        "description": "Execute SQL on Google Cloud Spanner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "region": { "type": "string", "x-mcp-header": header },
                "query": { "type": "string" }
            }
        }
    })
}

fn plain(name: &str) -> Value {
    json!({ "name": name, "description": format!("does {name}"), "inputSchema": { "type": "object" } })
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

struct Setup {
    gw: Gateway,
    dir: TempDir,
    /// The stdio mock's tools, which it reads when it starts.
    tools_file: std::path::PathBuf,
}

impl Setup {
    /// A gateway over the stdio mock listing `tools`, every one allowed, with
    /// `extra` config.
    async fn stdio(tools: Value, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tools_file = dir.path().join("tools.json");
        std::fs::write(&tools_file, tools.to_string()).unwrap();
        let server = format!(
            "[[server]]\nid = \"up\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \
             \"--tools-from\", {:?}]\n",
            tools_file.display().to_string()
        );
        Self::build(dir, tools_file, &server, extra).await
    }

    /// A gateway over the Streamable-HTTP upstream at `url`, speaking
    /// 2026-07-28, with `extra` config.
    async fn http(url: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = format!(
            "[[server]]\nid = \"spanner\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
             spec = \"2026-07-28\"\n"
        );
        let tools_file = dir.path().join("unused.json");
        Self::build(dir, tools_file, &server, extra).await
    }

    async fn build(
        dir: TempDir,
        tools_file: std::path::PathBuf,
        server: &str,
        extra: &str,
    ) -> Self {
        let config = format!(
            "[gateway]\naudit = {:?}\nwire = \"dual\"\n\n{server}\n{extra}",
            dir.path().join("audit.log").display().to_string(),
        );
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(&path, config).unwrap();
        let cfg = Config::load(&path).unwrap();
        let gw = build_gateway(&cfg).await.unwrap();
        Setup {
            gw,
            dir,
            tools_file,
        }
    }

    async fn send(&self, method: &str, params: Option<Value>) -> Message {
        self.gw
            .handle(Message::request(Id::Num(1), method, params))
            .await
            .unwrap()
            .unwrap()
    }

    /// The names `tools/list` shows, as a client sees them.
    async fn listed(&self) -> Vec<String> {
        let reply = self.send(method::TOOLS_LIST, None).await;
        reply.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Wait until `tools/list` shows exactly `names`.
    async fn listed_becomes(&self, names: &[&str]) {
        let until = Instant::now() + PATIENCE;
        loop {
            let listed = self.listed().await;
            if listed == names {
                return;
            }
            assert!(
                Instant::now() < until,
                "still listing {listed:?}, not {names:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Call `tool` with `arguments`, over stdio, as a modern client would:
    /// the gateway stamps what it sends upstream either way.
    async fn call(&self, tool: &str, arguments: Value) -> Value {
        let params = json!({ "name": tool, "arguments": arguments });
        self.send(method::TOOLS_CALL, Some(params))
            .await
            .result
            .expect("a result")
    }

    /// The `tools/call` records in the ledger.
    fn calls(&self) -> Vec<Record> {
        std::fs::read_to_string(self.dir.path().join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<Record>(l).unwrap())
            .filter(|r| r.method.as_deref() == Some(method::TOOLS_CALL))
            .collect()
    }

    /// Serve this gateway on a listener of its own, and return its URL.
    async fn listen(&self) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = HttpConfig {
            listen: addr.to_string(),
            allowed_origins: vec![],
            max_inflight: None,
            wire: WireMode::Dual,
        };
        let gw = self.gw.clone();
        tokio::spawn(async move { serve_http_on(l, gw, cfg, None).await.unwrap() });
        format!("http://{addr}/mcp")
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// A tool that cannot be mirrored is not served
// ---------------------------------------------------------------------------

/// Per tool, never per upstream: the revision is explicit that "a single
/// malformed tool definition does not prevent other valid tools from being
/// used". The tool is hidden, and a call to it is refused and recorded. The
/// allowlist allows everything, so it is not what hides it.
#[tokio::test]
async fn a_tool_whose_annotation_cannot_be_mirrored_is_neither_listed_nor_called() {
    let mut leaky = execute_sql("Region\r\nX-Injected: yes");
    leaky["name"] = json!("leaky");
    let mut twice = plain("twice");
    twice["inputSchema"] = json!({ "type": "object", "properties": {
        "a": { "type": "string", "x-mcp-header": "Tenant" },
        "b": { "type": "string", "x-mcp-header": "tenant" } } });
    let tools = json!([plain("echo"), execute_sql("Region"), leaky, twice]);
    let s = Setup::stdio(tools, "").await;

    assert_eq!(s.listed().await, ["echo", "execute_sql"]);

    for tool in ["leaky", "twice"] {
        let refused = s.call(tool, json!({ "region": "us-west1" })).await;
        assert_eq!(refused["isError"], true, "{refused}");
        assert!(text(&refused).contains("is not served"), "{refused}");
    }
    let leaky = s.call("leaky", json!({})).await;
    assert!(text(&leaky).contains("not an HTTP field name"), "{leaky}");

    let rules: Vec<_> = s
        .calls()
        .into_iter()
        .map(|r| (r.tool.unwrap_or_default(), r.rule))
        .collect();
    assert!(
        rules.contains(&("leaky".into(), Some("x-mcp-header".into()))),
        "{rules:?}"
    );

    // Its siblings are untouched.
    let echoed = s.call("echo", json!({ "x": 1 })).await;
    assert_eq!(echoed["isError"], false, "{echoed}");
}

// ---------------------------------------------------------------------------
// Emission: MCPdef is the client, so it mirrors what a tool asks for
// ---------------------------------------------------------------------------

/// A 2026-07-28 Streamable-HTTP server offering `execute_sql`, its `region`
/// annotated with the header name it holds now, and `poke`, whose answer says
/// the tools changed.
///
/// It **enforces** the mirroring, by what it lists now: `400` + `-32020` when
/// the annotated argument is in the body with no matching header, or with one
/// that disagrees, as the revision says a server must. A mock that merely
/// accepted would pass whether or not MCPdef sent the header.
#[derive(Clone)]
struct Spanner {
    /// The `x-mcp-header` it gives `region`.
    header: Arc<Mutex<String>>,
    /// The `Mcp-Param-*` headers each `execute_sql` call came with, decoded.
    received: Arc<Mutex<Vec<Headers>>>,
    /// How often it was asked for its tools.
    lists: Arc<AtomicUsize>,
}

impl Spanner {
    async fn start(header: &str) -> (String, Spanner) {
        let spanner = Spanner {
            header: Arc::new(Mutex::new(header.to_string())),
            received: Arc::default(),
            lists: Arc::default(),
        };
        let state = spanner.clone();
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move |headers: HeaderMap, body: String| {
                let state = state.clone();
                async move { state.answer(&headers, &body) }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/mcp"), spanner)
    }

    /// Annotate `region` as `header` from now on.
    fn annotate(&self, header: &str) {
        *self.header.lock().unwrap() = header.to_string();
    }

    /// The `Mcp-Param-*` headers the last `execute_sql` call came with.
    fn last_received(&self) -> Headers {
        self.received
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a call")
    }

    fn answer(&self, headers: &HeaderMap, body: &str) -> Response {
        let Ok(msg) = Message::from_json_line(body) else {
            return (StatusCode::BAD_REQUEST, "not JSON-RPC").into_response();
        };
        let Some(id) = msg.id.clone() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let annotation = self.header.lock().unwrap().clone();
        match (msg.method(), msg.tool_name()) {
            (Some(method::SERVER_DISCOVER), _) => json_reply(
                StatusCode::OK,
                Message::result(
                    id,
                    json!({ "resultType": "complete", "supportedVersions": [SPEC_2026_07_28] }),
                ),
            ),
            (Some(method::TOOLS_LIST), _) => {
                self.lists.fetch_add(1, SeqCst);
                json_reply(
                    StatusCode::OK,
                    Message::result(
                        id,
                        json!({ "resultType": "complete",
                                "tools": [execute_sql(&annotation), plain("poke")] }),
                    ),
                )
            }
            (Some(method::TOOLS_CALL), Some("poke")) => {
                // Word that the tools changed, then the answer, as SSE: how a
                // Streamable-HTTP server says so to a client with no stream
                // of its own open.
                let changed = Message::notification(method::TOOLS_LIST_CHANGED, None);
                let done = Message::result(
                    id,
                    json!({ "content": [{ "type": "text", "text": "poked" }], "isError": false }),
                );
                let body: String = [changed, done]
                    .iter()
                    .map(|m| format!("event: message\ndata: {}\n\n", m.to_json_line()))
                    .collect();
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
                    .into_response()
            }
            (Some(method::TOOLS_CALL), Some("execute_sql")) => {
                let received: Headers = headers
                    .iter()
                    .filter(|(name, _)| name.as_str().starts_with(header::PARAM_PREFIX))
                    .map(|(name, value)| {
                        let value = decode_header_value(value.to_str().unwrap()).unwrap();
                        (name.as_str().to_string(), value.into_owned())
                    })
                    .collect();
                self.received.lock().unwrap().push(received);

                let expected = format!(
                    "{}{}",
                    header::PARAM_PREFIX,
                    annotation.to_ascii_lowercase()
                );
                let in_body = msg.params.as_ref().unwrap()["arguments"]["region"]
                    .as_str()
                    .map(str::to_string);
                let sent = headers.get(&expected).map(|v| {
                    decode_header_value(v.to_str().unwrap())
                        .unwrap()
                        .into_owned()
                });
                match (in_body, sent) {
                    (Some(b), Some(h)) if h == b => ok_text(id, &b),
                    (None, None) => ok_text(id, "no region"),
                    (b, h) => json_reply(
                        StatusCode::BAD_REQUEST,
                        Message::error(
                            id,
                            error_code::HEADER_MISMATCH,
                            format!("{expected} {h:?} does not match body {b:?}"),
                        ),
                    ),
                }
            }
            _ => json_reply(
                StatusCode::NOT_FOUND,
                Message::error(id, error_code::METHOD_NOT_FOUND, "no such method"),
            ),
        }
    }
}

/// Headers by name, as a call came with them.
type Headers = Vec<(String, String)>;

fn json_reply(status: StatusCode, msg: Message) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        msg.to_json_line(),
    )
        .into_response()
}

fn ok_text(id: Id, text: &str) -> Response {
    json_reply(
        StatusCode::OK,
        Message::result(
            id,
            json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
        ),
    )
}

/// The annotated argument reaches the upstream as `Mcp-Param-Region`, from
/// the side of the transport that carries every call after the opening. The
/// upstream refuses the call without it, so a green call is the header sent.
#[tokio::test]
async fn an_annotated_argument_reaches_the_upstream_as_its_header() {
    let (url, spanner) = Spanner::start("Region").await;
    let s = Setup::http(&url, "").await;

    let r = s
        .call(
            "execute_sql",
            json!({ "region": "us-west1", "query": "SELECT 1" }),
        )
        .await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(text(&r), "us-west1");
    assert_eq!(
        spanner.last_received(),
        [("mcp-param-region".to_string(), "us-west1".to_string())]
    );
}

/// A value that cannot sit in a header as it is travels as `=?base64?…?=`,
/// and an absent one sends no header at all: "Parameter not in arguments:
/// Client MUST omit the header".
#[tokio::test]
async fn a_value_is_encoded_when_it_must_be_and_omitted_when_absent() {
    let (url, spanner) = Spanner::start("Region").await;
    let s = Setup::http(&url, "").await;

    let r = s.call("execute_sql", json!({ "region": " 亞太-1 " })).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(text(&r), " 亞太-1 ");

    let r = s.call("execute_sql", json!({ "query": "SELECT 1" })).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(text(&r), "no region");
    assert_eq!(spanner.last_received(), []);
}

/// The header says what the body the upstream gets says: an argument
/// transform's value, not the client's.
#[tokio::test]
async fn the_header_says_what_the_transformed_body_says() {
    let (url, spanner) = Spanner::start("Region").await;
    let rule = r#"
[[policy]]
name = "one-region"
effect = "transform"
tools = ["execute_sql"]
set_args = [{ path = "region", set = "eu-west1" }]
"#;
    let s = Setup::http(&url, rule).await;

    let r = s.call("execute_sql", json!({ "region": "us-west1" })).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(text(&r), "eu-west1");
    assert_eq!(
        spanner.last_received(),
        [("mcp-param-region".to_string(), "eu-west1".to_string())]
    );
}

/// After the upstream re-annotates `region` and says its tools changed, the
/// next call goes out by the new annotation, and not by the old one. A copy
/// taken at the opening would send `Mcp-Param-Region`, which the upstream now
/// refuses.
#[tokio::test]
async fn a_call_after_a_re_list_is_sent_by_the_annotation_it_brought() {
    let (url, spanner) = Spanner::start("Region").await;
    let s = Setup::http(&url, "").await;
    let r = s.call("execute_sql", json!({ "region": "us-west1" })).await;
    assert_eq!(r["isError"], false, "{r}");

    spanner.annotate("Zone");
    let lists = spanner.lists.load(SeqCst);
    assert_eq!(text(&s.call("poke", json!({})).await), "poked");
    let until = Instant::now() + PATIENCE;
    while spanner.lists.load(SeqCst) == lists {
        assert!(Instant::now() < until, "the tools were never listed again");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The re-list is in force once a call goes out by it.
    let until = Instant::now() + PATIENCE;
    loop {
        let r = s.call("execute_sql", json!({ "region": "us-west1" })).await;
        if r["isError"] == false {
            assert_eq!(text(&r), "us-west1");
            break;
        }
        assert!(
            Instant::now() < until,
            "never sent by the new annotation: {r}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        spanner.last_received(),
        [("mcp-param-zone".to_string(), "us-west1".to_string())]
    );
}

/// A re-list that breaks a tool's annotation withdraws it; one that mends it
/// serves it again.
#[tokio::test]
async fn a_tool_is_withdrawn_when_its_annotation_breaks_and_served_when_mended() {
    let (url, spanner) = Spanner::start("Region").await;
    let s = Setup::http(&url, "").await;
    assert_eq!(s.listed().await, ["execute_sql", "poke"]);

    spanner.annotate("Region Name");
    s.call("poke", json!({})).await;
    s.listed_becomes(&["poke"]).await;
    let refused = s.call("execute_sql", json!({ "region": "us-west1" })).await;
    assert_eq!(refused["isError"], true, "{refused}");
    assert!(text(&refused).contains("is not served"), "{refused}");

    spanner.annotate("Region");
    s.call("poke", json!({})).await;
    s.listed_becomes(&["execute_sql", "poke"]).await;
    let r = s.call("execute_sql", json!({ "region": "us-west1" })).await;
    assert_eq!(r["isError"], false, "{r}");
}

// ---------------------------------------------------------------------------
// Validation: MCPdef reads the body, so it reconciles the headers with it
// ---------------------------------------------------------------------------

/// POST one modern `tools/call` of `execute_sql` with `arguments` and the
/// `Mcp-Param-*` headers in `extra`. Returns the status and the body.
async fn post_call(url: &str, arguments: Value, extra: &[(&str, &[u8])]) -> (StatusCode, Value) {
    let mut body = modern_call(arguments);
    body["id"] = json!(1);
    post(url, body, extra).await
}

/// A modern `tools/call` of `execute_sql` with `arguments`, as a notification:
/// it carries no id until one is given.
fn modern_call(arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {
            "name": "execute_sql",
            "arguments": arguments,
            "_meta": { "io.modelcontextprotocol/protocolVersion": SPEC_2026_07_28 }
        }
    })
}

/// POST `body` as a modern `tools/call` of `execute_sql`, with the
/// `Mcp-Param-*` headers in `extra`. Returns the status and the body.
async fn post(url: &str, body: Value, extra: &[(&str, &[u8])]) -> (StatusCode, Value) {
    mcpdef_transport::install_crypto_provider();
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", SPEC_2026_07_28)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "execute_sql");
    for (name, value) in extra {
        request = request.header(
            *name,
            reqwest::header::HeaderValue::from_bytes(value).unwrap(),
        );
    }
    let resp = request.body(body.to_string()).send().await.unwrap();
    let status = resp.status();
    let body = serde_json::from_str(&resp.text().await.unwrap()).unwrap_or(Value::Null);
    (StatusCode::from_u16(status.as_u16()).unwrap(), body)
}

/// A listener over the stdio mock, whose `execute_sql` annotates `region` as
/// `Region`.
async fn annotated_listener() -> (String, Setup) {
    let s = Setup::stdio(json!([execute_sql("Region")]), "").await;
    (s.listen().await, s)
}

/// Assert `reply` is the revision's refusal: `400` + `-32020`.
fn assert_mismatch((status, body): (StatusCode, Value), why: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {body}");
    assert_eq!(
        body["error"]["code"],
        error_code::HEADER_MISMATCH,
        "{why}: {body}"
    );
}

/// Assert `reply` reached the tool.
fn assert_called((status, body): (StatusCode, Value), why: &str) {
    assert_eq!(status, StatusCode::OK, "{why}: {body}");
    assert_eq!(body["result"]["isError"], false, "{why}: {body}");
}

/// Each way a recognized header and the body can disagree is refused before
/// anything routes on either. A gateway that let them disagree would be
/// enforcing policy on a value its own client's intermediaries never saw.
#[tokio::test]
async fn a_param_header_that_disagrees_with_the_body_is_refused() {
    let (url, _s) = annotated_listener().await;
    let region = json!({ "region": "us-west1", "query": "SELECT 1" });
    let no_region = json!({ "query": "SELECT 1" });

    assert_mismatch(
        post_call(
            &url,
            region.clone(),
            &[("mcp-param-region", b"eu-central1")],
        )
        .await,
        "a header disagreeing with the body",
    );
    // The revision's own row: "Client omits header but value is in body".
    assert_mismatch(
        post_call(&url, region.clone(), &[]).await,
        "an annotated argument with no header",
    );
    assert_mismatch(
        post_call(&url, no_region, &[("mcp-param-region", b"us-west1")]).await,
        "a header claiming what the body does not carry",
    );
    // Characters a header value cannot carry: not taken for no header.
    assert_mismatch(
        post_call(
            &url,
            json!({ "query": "q" }),
            &[("mcp-param-region", "亞".as_bytes())],
        )
        .await,
        "a header that is not ASCII",
    );
}

/// What the revision allows reaches the tool: a header that agrees, one that
/// is sentinel-encoded (decoded before comparing), the omit state, and an
/// `Mcp-Param-*` the tool never declared, which an intermediary "MUST forward
/// … and otherwise ignore".
#[tokio::test]
async fn a_param_header_that_agrees_with_the_body_reaches_the_tool() {
    let (url, _s) = annotated_listener().await;

    assert_called(
        post_call(
            &url,
            json!({ "region": "us-west1" }),
            &[("Mcp-Param-Region", b"us-west1")],
        )
        .await,
        "a matching header",
    );
    let encoded = encode_header_value("亞太-1").into_owned();
    assert_called(
        post_call(
            &url,
            json!({ "region": "亞太-1" }),
            &[("mcp-param-region", encoded.as_bytes())],
        )
        .await,
        "a sentinel-encoded header",
    );
    assert_called(
        post_call(&url, json!({ "query": "SELECT 1" }), &[]).await,
        "neither sent",
    );
    assert_called(
        post_call(
            &url,
            json!({ "region": "us-west1" }),
            &[
                ("mcp-param-region", b"us-west1"),
                ("mcp-param-tenant", b"acme"),
            ],
        )
        .await,
        "an unrecognized header",
    );
}

/// A tool the allowlist hides is refused as the call itself, never as a
/// header mismatch: the mismatch would tell the caller what its annotations
/// are.
#[tokio::test]
async fn a_hidden_tool_s_annotations_are_not_told() {
    let s = Setup::stdio(
        json!([plain("echo"), execute_sql("Region")]),
        "tools = [\"echo\"]",
    )
    .await;
    let url = s.listen().await;
    let (status, body) = post_call(
        &url,
        json!({ "region": "us-west1" }),
        &[("mcp-param-region", b"eu-central1")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert!(!body.to_string().contains("mcp-param"), "{body}");
}

/// A `tools/call` sent as a notification is not a call: it is not checked,
/// and is accepted with nothing to answer, as any notification is.
#[tokio::test]
async fn a_notification_is_not_checked() {
    let (url, _s) = annotated_listener().await;
    let (status, body) = post(
        &url,
        modern_call(json!({ "region": "us-west1" })),
        &[("mcp-param-region", b"eu-central1")],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

/// The listener checks by the annotations a restarted upstream lists, not the
/// ones it had at startup.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_checks_by_what_a_restarted_upstream_lists() {
    let (url, s) = {
        let s = Setup::stdio(json!([execute_sql("Region"), plain("pid")]), "").await;
        (s.listen().await, s)
    };
    let region = json!({ "region": "us-west1" });
    assert_called(
        post_call(&url, region.clone(), &[("mcp-param-region", b"us-west1")]).await,
        "before the restart",
    );

    // While it is down, `region` is annotated anew.
    std::fs::write(
        &s.tools_file,
        json!([execute_sql("Zone"), plain("pid")]).to_string(),
    )
    .unwrap();
    let pid = text(&s.call("pid", json!({})).await).to_string();
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid])
        .status()
        .unwrap();
    assert!(killed.success());
    let until = Instant::now() + PATIENCE;
    loop {
        let status = &s.gw.upstream_status()[0];
        if status.restarts == 1 && status.health == HealthState::Up {
            break;
        }
        assert!(Instant::now() < until, "{status:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_called(
        post_call(&url, region.clone(), &[("mcp-param-zone", b"us-west1")]).await,
        "by the annotation it lists now",
    );
    assert_mismatch(
        post_call(&url, region, &[("mcp-param-region", b"us-west1")]).await,
        "by the annotation it listed before",
    );
}

/// End to end across a re-list: a client's headers are checked by the new
/// annotation, and the call reaches an upstream that enforces it.
#[tokio::test]
async fn a_client_and_its_upstream_both_go_by_a_re_listed_annotation() {
    let (spanner_url, spanner) = Spanner::start("Region").await;
    let s = Setup::http(&spanner_url, "").await;
    let url = s.listen().await;
    let region = json!({ "region": "us-west1" });
    assert_called(
        post_call(&url, region.clone(), &[("mcp-param-region", b"us-west1")]).await,
        "before the re-list",
    );

    spanner.annotate("Zone");
    let lists = spanner.lists.load(SeqCst);
    s.call("poke", json!({})).await;
    let until = Instant::now() + PATIENCE;
    loop {
        let (status, body) =
            post_call(&url, region.clone(), &[("mcp-param-zone", b"us-west1")]).await;
        if status == StatusCode::OK && body["result"]["isError"] == false {
            break;
        }
        assert!(
            Instant::now() < until,
            "never went by the re-listed annotation: {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(spanner.lists.load(SeqCst) > lists);
    assert_eq!(
        spanner.last_received(),
        [("mcp-param-zone".to_string(), "us-west1".to_string())]
    );
    assert_mismatch(
        post_call(&url, region, &[("mcp-param-region", b"us-west1")]).await,
        "by the annotation it listed before",
    );
}
