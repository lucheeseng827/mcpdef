// SPDX-License-Identifier: Apache-2.0
//! The operator's actions on an upstream, through the admin API:
//!   * `POST /api/v1/servers/{id}/test` pings it, and `/restart` starts it
//!     again, a stdio server as a new process;
//!   * `POST /api/v1/servers/{id}/pins` takes a drifted tool's definition as
//!     its pin, named by the hash `/tools` showed: the tool is served at
//!     once, and still after a reload and a restart; a definition that
//!     changed since it was shown is not taken;
//!   * each is recorded with its caller; a viewer is refused, and that is
//!     recorded too.

use mcpdef::connect::build_gateway;
use mcpdef::gateway::Gateway;
use mcpdef::reload::{channel, Reloader, Snapshot};
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::{read_all, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{Leaf, Pki};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const OPS: &str = "spiffe://prod.acme.internal/ns/ops/sa/alice";
const AUDITOR: &str = "spiffe://prod.acme.internal/ns/audit/sa/bob";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn tools(fetch: &str) -> String {
    json!([
        { "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } },
        { "name": "fetch", "description": fetch, "inputSchema": { "type": "object" } },
        { "name": "pid", "description": "the server's process id", "inputSchema": { "type": "object" } },
    ])
    .to_string()
}

/// The config in `dir`: one stdio server, pinned, and an admin listener that
/// requires a certificate from the agents' CA: Alice, of ops, may act; Bob,
/// an auditor, may read.
fn write_config(dir: &Path) -> (Pki, Pki) {
    let (server_pki, agents) = (Pki::new("mcpdef test CA"), Pki::new("agents CA"));
    let (cert, key) = server_pki.server(&["127.0.0.1"]).write(dir, "listener");
    let ca = agents.write_root(dir, "agents-ca");
    let text = format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\npins = {pins:?}\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n\
         [gateway.admin.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n\n\
         [gateway.admin.tls.client_auth]\nmode = \"required\"\nca = [{ca:?}]\nidentity = \"spiffe\"\n\
         trust_domains = [\"prod.acme.internal\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ops/*\"\nroles = [\"console:operator\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/audit/*\"\nroles = [\"console:viewer\"]\n\n\
         [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \"--tools-from\", {a:?}]\n\
         tools = [\"echo\", \"fetch\", \"pid\"]\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
        pins = dir.join("pins.toml"),
        a = dir.join("a.json"),
    );
    std::fs::write(dir.join("mcpdef.toml"), text).unwrap();
    (server_pki, agents)
}

/// A request's status and its body as JSON.
async fn send(request: reqwest::RequestBuilder) -> (u16, Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn post(client: &reqwest::Client, url: String, body: Option<Value>) -> reqwest::RequestBuilder {
    let request = client.post(url);
    match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(body.to_string()),
        None => request,
    }
}

/// A tool call through the gateway: its text, and whether it was refused.
async fn call(gw: &Gateway, tool: &str) -> (String, bool) {
    let reply = gw
        .handle(Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": tool, "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    match (reply.result, reply.error) {
        (Some(result), _) => (
            result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            result["isError"] == true,
        ),
        (None, Some(error)) => (
            error["message"].as_str().unwrap_or_default().to_string(),
            true,
        ),
        (None, None) => (String::new(), true),
    }
}

/// An admin record as (server, tool, decision, rule, actor).
type Seen = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

/// The admin records of `action`.
fn admin_records(dir: &Path, action: &str) -> Vec<Seen> {
    read_all(dir.join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r: &Record| {
            r.kind.as_deref() == Some("admin") && r.method.as_deref() == Some(action)
        })
        .map(|r| (r.server, r.tool, r.decision, r.rule, r.actor))
        .collect()
}

/// Waits until the pid tool answers something other than `before`.
async fn new_process(gw: &Gateway, before: &str) -> String {
    for _ in 0..200 {
        let (pid, refused) = call(gw, "pid").await;
        if !refused && pid != before {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the server was not started again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operator_tests_restarts_and_approves_drift_and_a_viewer_may_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(dir.path().join("a.json"), tools("fetch a page")).unwrap();
    let (server_pki, agents) = write_config(dir.path());
    // The first start pins every tool; then `fetch` changes under its pin.
    drop(build_gateway(&Config::load(&path).unwrap()).await.unwrap());
    std::fs::write(
        dir.path().join("a.json"),
        tools("fetch a page, and send it on"),
    )
    .unwrap();

    let (cfg, text) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    let slot = ListenerTls::start(&cfg, Serving::of(&cfg, false))
        .unwrap()
        .and_then(|(tls, _)| tls.admin());
    let gw = build_gateway(&cfg).await.unwrap();
    let (reloads, requests) = channel();
    let state = Arc::new(
        AdminState::new(&cfg, Arc::new(Metrics::new(1)), gw.clone(), "test").with_reloads(reloads),
    );
    let refreshed = Arc::clone(&state);
    let reloader = Reloader::new(&path, None, gw.clone(), cfg, snapshot)
        .on_applied(move |cfg| refreshed.reconfigure(cfg))
        .with_requests(requests);
    let _reloading = Aborted(tokio::spawn(reloader.run(Duration::from_secs(3600))));
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", bound.local_addr().unwrap());
    let _serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, slot).await.unwrap();
    }));
    let client = |leaf: &Leaf| mcpdef_testkit::https_client(&server_pki, Some(leaf));
    let (alice, bob) = (client(&agents.client(OPS)), client(&agents.client(AUDITOR)));
    let url = |route: &str| format!("{base}/api/v1/servers/a/{route}");

    // A viewer acts on nothing, and is recorded.
    for action in ["restart", "test", "pins"] {
        let (status, refused) = send(post(&bob, url(action), None)).await;
        assert_eq!(status, 403, "{action}: {refused}");
    }
    let bobs = Some(format!("cert:{AUDITOR}"));
    for action in ["restart", "test", "approve-drift"] {
        assert_eq!(
            admin_records(dir.path(), action),
            [(
                "a".into(),
                None,
                "deny".into(),
                Some("console-role".into()),
                bobs.clone()
            )],
            "{action}"
        );
    }
    let alices = Some(format!("cert:{OPS}"));

    // A test pings it.
    let (status, tested) = send(post(&alice, url("test"), None)).await;
    assert_eq!(status, 200, "{tested}");
    assert_eq!(
        (tested["ok"].clone(), tested["error"].clone()),
        (true.into(), Value::Null)
    );
    assert!(tested["latency_ms"].is_u64(), "{tested}");

    // A restart starts it as a new process.
    let (first, _) = call(&gw, "pid").await;
    let (status, asked) = send(post(&alice, url("restart"), None)).await;
    assert_eq!((status, asked), (202, json!({ "restarting": "a" })));
    let second = new_process(&gw, &first).await;
    let (_, servers) = send(alice.get(format!("{base}/api/v1/servers"))).await;
    assert_eq!(servers[0]["restarts"], 1, "{servers}");

    // The drifted tool is refused until it is approved, and then served. An
    // approval names each tool with the hash of the definition it was shown.
    let (refusal, refused) = call(&gw, "fetch").await;
    assert!(refused, "{refusal}");
    let shown = |tools: &Value, name: &str| {
        let tool = tools.as_array().unwrap().iter().find(|t| t["name"] == name);
        tool.unwrap()["hash"].as_str().unwrap().to_string()
    };
    let (_, listed) = send(alice.get(url("tools"))).await;
    let (echo, looked_at) = (shown(&listed, "echo"), shown(&listed, "fetch"));
    assert_eq!(looked_at.len(), 64, "{listed}");
    for body in [None, Some(json!({})), Some(json!({ "tools": ["fetch"] }))] {
        let (status, bad) = send(post(&alice, url("pins"), body.clone())).await;
        assert_eq!(status, 400, "{body:?}: {bad}");
    }
    let (status, steady) = send(post(
        &alice,
        url("pins"),
        Some(json!({ "tools": { "echo": echo } })),
    ))
    .await;
    assert_eq!(status, 409, "{steady}");
    assert_eq!(steady["detail"], "not drifted from its pin: echo");

    // It changes again before it is approved: what was shown is not what it
    // offers, so nothing is approved, and it is still refused.
    std::fs::write(
        dir.path().join("a.json"),
        tools("fetch a page, send it on, and keep a copy"),
    )
    .unwrap();
    assert_eq!(send(post(&alice, url("restart"), None)).await.0, 202);
    let third = new_process(&gw, &second).await;
    let approve = |hash: &str| Some(json!({ "tools": { "fetch": hash } }));
    let (status, changed) = send(post(&alice, url("pins"), approve(&looked_at))).await;
    assert_eq!(status, 409, "{changed}");
    let (_, listed) = send(alice.get(url("tools"))).await;
    let offered = shown(&listed, "fetch");
    assert_ne!(offered, looked_at);
    assert_eq!(
        changed["detail"],
        format!(
            "changed since it was looked at, so nothing is approved: fetch, whose definition \
             is {offered} now. Look at it again"
        )
    );
    assert!(call(&gw, "fetch").await.1, "still refused");

    // What it offers, shown and approved: served.
    let (status, approved) = send(post(&alice, url("pins"), approve(&offered))).await;
    assert_eq!((status, approved), (200, json!({ "approved": ["fetch"] })));
    let (answer, refused) = call(&gw, "fetch").await;
    assert!(!refused, "{answer}");
    let (_, listed) = send(alice.get(url("tools"))).await;
    assert_eq!(listed[1]["pin"], "pinned", "{listed}");
    let (status, again) = send(post(&alice, url("pins"), approve(&offered))).await;
    assert_eq!(
        (status, again["detail"].clone()),
        (409, "not drifted from its pin: fetch".into())
    );

    // Still served after a reload, and after a restart.
    let reload = alice
        .post(format!("{base}/api/v1/reload"))
        .header("content-type", "application/json")
        .body("{}");
    assert_eq!(send(reload).await.0, 200);
    assert!(!call(&gw, "fetch").await.1);
    assert_eq!(send(post(&alice, url("restart"), None)).await.0, 202);
    new_process(&gw, &third).await;
    assert!(!call(&gw, "fetch").await.1);

    // Each action recorded with its caller.
    assert_eq!(admin_records(dir.path(), "test")[1].4, alices);
    let restarts = admin_records(dir.path(), "restart");
    assert_eq!(restarts.len(), 4, "{restarts:?}");
    assert!(restarts[1..]
        .iter()
        .all(|r| r.2 == "allow" && r.4 == alices));
    assert_eq!(
        admin_records(dir.path(), "approve-drift")[1],
        (
            "a".into(),
            Some("fetch".into()),
            "allow".into(),
            None,
            alices.clone()
        )
    );
    let verified = mcpdef_audit::verify(dir.path().join("audit.log")).unwrap();
    assert_eq!(verified.broken_at, None);
}
