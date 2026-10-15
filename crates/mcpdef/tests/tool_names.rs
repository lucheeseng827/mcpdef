// SPDX-License-Identifier: Apache-2.0
//! Tool names. `tools/list` gives each name once: a name two servers offer is
//! listed from the first of them in config order, a call to it goes there, and
//! the gateway says so at startup, in `validate` and on the admin servers
//! view, and under `strict` does not start. With `[gateway] tool_namespace =
//! "prefix"` each tool is listed, and called, as `<prefix>__<name>`, while the
//! pins, the allowlist, roles, rules, rate limits and the audit know it as its
//! server does.

use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::reload::{self, Reloader, Snapshot, Trigger};
use mcpdef::{
    serve_admin_on, AdminState, Config, Connect, Gateway, Metrics, Planned, Reconfig, Startup,
    Supervised, ToolCollision, UpstreamOptions,
};
use mcpdef_audit::{read_all, Ledger};
use mcpdef_auth::Principal;
use mcpdef_core::wire::{error_code, header, meta_key, WireMode, SPEC_2026_07_28};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, PinStore};
use mcpdef_transport::{duplex_pair, Duplex, StdioChild, Transport};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// Every call an upstream got: (upstream, the tool name it was sent).
type Calls = Arc<Mutex<Vec<(String, String)>>>;

/// The definition an upstream lists for `name`.
fn tool(name: &str) -> Value {
    json!({
        "name": name,
        "description": format!("does {name}"),
        "inputSchema": { "type": "object" },
    })
}

/// An upstream that lists `tools` and answers a call with `<label>:<name>`,
/// the name as it was sent.
fn spawn(label: &str, tools: &[&str], calls: Calls) -> Duplex {
    let label = label.to_string();
    let tools: Vec<Value> = tools.iter().map(|t| tool(t)).collect();
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let reply = match msg.method().unwrap_or_default() {
                method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": label, "version": "0" },
                    }),
                ),
                method::TOOLS_LIST => Message::result(id, json!({ "tools": tools })),
                method::TOOLS_CALL => {
                    let name = msg.tool_name().unwrap_or_default().to_string();
                    calls.lock().unwrap().push((label.clone(), name.clone()));
                    Message::result(
                        id,
                        json!({
                            "isError": false,
                            "content": [{ "type": "text", "text": format!("{label}:{name}") }],
                        }),
                    )
                }
                _ => Message::error(id, -32601, "method not found"),
            };
            if far.send(reply).await.is_err() {
                break;
            }
        }
    });
    near
}

/// Opens [`spawn`]'s upstream, afresh for every start.
fn serving(label: &str, tools: &[&str], calls: &Calls) -> Connect {
    let label = label.to_string();
    let tools: Vec<String> = tools.iter().map(|t| t.to_string()).collect();
    let calls = Arc::clone(calls);
    Arc::new(move || {
        let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
        let up = spawn(&label, &tools, Arc::clone(&calls));
        Box::pin(async move { Ok(Box::new(up) as Box<dyn Transport>) })
    })
}

/// An upstream that never opens.
fn refused() -> Connect {
    Arc::new(|| {
        Box::pin(async { Err::<Box<dyn Transport>, _>(anyhow::anyhow!("connection refused")) })
    })
}

fn supervised(id: &str, connect: Connect) -> Supervised {
    Supervised {
        id: id.into(),
        connect,
        options: UpstreamOptions::default(),
    }
}

/// A `[[server]]` table: a stdio server that is never started here, with
/// `extra` lines.
fn server(id: &str, extra: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [\"unused\"]\n{extra}\n\n")
}

/// Listed tools as (name, the server `_meta` names).
fn listed(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, server)| (name.to_string(), server.to_string()))
        .collect()
}

/// A tools/call record: (server, decision, rule, tool).
type Outcome = (String, String, Option<String>, Option<String>);

fn outcome(server: &str, decision: &str, rule: Option<&str>, tool: &str) -> Outcome {
    (
        server.into(),
        decision.into(),
        rule.map(str::to_string),
        Some(tool.into()),
    )
}

fn text(reply: &Message) -> String {
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn is_error(reply: &Message) -> bool {
    reply.result.as_ref().is_some_and(|r| r["isError"] == true)
}

fn collision(tool: &str, servers: &[&str]) -> ToolCollision {
    ToolCollision {
        tool: tool.into(),
        servers: servers.iter().map(|s| s.to_string()).collect(),
    }
}

fn principal(roles: &[&str]) -> Principal {
    Principal {
        subject: "alice".into(),
        scopes: vec![],
        roles: roles.iter().map(|r| r.to_string()).collect(),
        client_id: None,
        issuer: "https://auth.example.com".into(),
    }
}

struct Setup {
    gw: Gateway,
    cfg: Config,
    dir: TempDir,
    calls: Calls,
}

impl Setup {
    /// A gateway as `build_gateway` makes it from `[gateway]` and `config`,
    /// over in-process upstreams, each listing the tools named.
    async fn new(config: &str, upstreams: &[(&str, &[&str])]) -> Self {
        Self::pinned(config, upstreams, None).await
    }

    async fn pinned(config: &str, upstreams: &[(&str, &[&str])], pins: Option<PinStore>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(&path, format!("[gateway]\n{config}")).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
        let (per_tool, global) = cfg.gateway.rate_limit_settings();
        let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:test")
            .with_rate_limit(per_tool, global)
            .with_rbac(Some(cfg.rbac()))
            .with_policy_rules(cfg.policy_rules())
            .with_tool_prefixes(cfg.tool_prefixes());
        if let Some(store) = pins {
            let path = dir.path().join("pins.toml");
            store.save(&path).unwrap();
            gw = gw.with_pins(PinStore::load(&path).unwrap(), path);
        }
        let calls = Calls::default();
        let servers = upstreams
            .iter()
            .map(|(id, tools)| supervised(id, serving(id, tools, &calls)))
            .collect();
        gw.start_supervised(servers, Startup::FailFast)
            .await
            .unwrap();
        Setup {
            gw,
            cfg,
            dir,
            calls,
        }
    }

    async fn send(&self, method: &str, params: Option<Value>) -> Message {
        self.gw
            .handle(Message::request(Id::Num(7), method, params))
            .await
            .unwrap()
            .unwrap()
    }

    async fn list(&self) -> Vec<(String, String)> {
        let resp = self.send(method::TOOLS_LIST, None).await;
        resp.result.expect("a list")["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["name"].as_str().unwrap().to_string(),
                    t["_meta"]["mcpdef/server"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    async fn call(&self, name: &str) -> Message {
        self.call_with(name, json!({})).await
    }

    async fn call_with(&self, name: &str, arguments: Value) -> Message {
        self.send(
            method::TOOLS_CALL,
            Some(json!({ "name": name, "arguments": arguments })),
        )
        .await
    }

    /// A call by an authenticated caller, as the HTTP listener hands it on.
    async fn call_as(&self, name: &str, arguments: Value, principal: &Principal) -> Message {
        let msg = Message::request(
            Id::Num(7),
            method::TOOLS_CALL,
            Some(json!({ "name": name, "arguments": arguments })),
        );
        self.gw
            .handle_authed(msg, Some(principal))
            .await
            .unwrap()
            .unwrap()
    }

    /// The calls the upstreams got: (upstream, the name it was sent).
    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }

    fn outcomes(&self) -> Vec<Outcome> {
        read_all(self.dir.path().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_deref() == Some(method::TOOLS_CALL))
            .map(|r| (r.server, r.decision, r.rule, r.tool))
            .collect()
    }

    /// `config` applied as a reload applies it, every upstream kept.
    async fn reload(&self, config: &str, upstreams: &[(&str, &[&str])]) {
        let cfg = Config::parse(&format!("[gateway]\n{config}")).unwrap();
        let pins = self.dir.path().join("pins.toml");
        let pins = pins
            .exists()
            .then(|| (PinStore::load(&pins).unwrap(), pins));
        let upstreams = upstreams
            .iter()
            .map(|(id, tools)| Planned {
                server: supervised(id, serving(id, tools, &self.calls)),
                changed: false,
            })
            .collect();
        self.gw
            .reconfigure(Reconfig {
                policy: cfg.to_policy(),
                rbac: cfg.rbac(),
                rules: cfg.policy_rules(),
                upstream_timeout: None,
                rate_limit: None,
                inspect: None,
                pins,
                tool_prefixes: cfg.tool_prefixes(),
                upstreams,
            })
            .await;
    }
}

#[tokio::test]
async fn a_name_more_than_one_server_offers_is_listed_once_from_the_first_and_called_there() {
    let config = ["a", "b", "c", "d"].map(|id| server(id, "")).concat();
    let s = Setup::new(
        &config,
        &[
            ("a", &["echo", "a_only"]),
            ("b", &["b_only", "echo"]),
            ("c", &["echo"]),
            ("d", &["d_only"]),
        ],
    )
    .await;

    assert_eq!(
        s.list().await,
        listed(&[
            ("echo", "a"),
            ("a_only", "a"),
            ("b_only", "b"),
            ("d_only", "d")
        ])
    );
    assert_eq!(text(&s.call("echo").await), "a:echo");
    assert_eq!(text(&s.call("b_only").await), "b:b_only");

    // Reported, naming every server that offers it, the first first.
    let echo = collision("echo", &["a", "b", "c"]);
    assert_eq!(
        echo.to_string(),
        "tool 'echo' is offered by 'a', 'b' and 'c': it is listed once, from 'a', and a call \
         to it goes there"
    );
    assert_eq!(s.gw.tool_warnings(), [echo.to_string()]);
    let reported: Vec<(String, Vec<ToolCollision>)> =
        s.gw.upstream_status()
            .into_iter()
            .map(|u| (u.id, u.tool_collisions))
            .collect();
    assert_eq!(
        reported,
        [
            ("a".into(), vec![echo.clone()]),
            ("b".into(), vec![echo.clone()]),
            ("c".into(), vec![echo]),
            ("d".into(), vec![]),
        ]
    );
}

/// The name belongs to the first server that offers it, not to the first that
/// lists it: before, `tools/list` showed `b`'s `echo` while a call to it went
/// to `a`, whose allowlist refused it.
#[tokio::test]
async fn a_name_the_first_server_hides_is_listed_and_called_from_the_one_that_offers_it() {
    let config = server("a", "tools = [\"a_only\"]") + &server("b", "");
    let s = Setup::new(&config, &[("a", &["echo", "a_only"]), ("b", &["echo"])]).await;

    assert_eq!(s.list().await, listed(&[("a_only", "a"), ("echo", "b")]));
    assert_eq!(text(&s.call("echo").await), "b:echo");
    assert_eq!(s.outcomes(), [outcome("b", "allow", None, "echo")]);
    // `a` does not offer it, so nothing collides.
    assert!(s.gw.tool_warnings().is_empty());
}

/// A tool that drifts from its pin keeps its name: it is hidden and refused,
/// and the name is not handed to the next server that offers it.
#[tokio::test]
async fn a_tool_that_drifts_is_refused_and_its_name_not_handed_on() {
    let config = server("a", "") + &server("b", "");
    let mut pins = PinStore::default();
    pins.record(
        "a",
        "echo",
        tool_hash(&json!({ "name": "echo", "description": "before" })),
    );
    pins.record("b", "echo", tool_hash(&tool("echo")));
    let s = Setup::pinned(&config, &[("a", &["echo"]), ("b", &["echo"])], Some(pins)).await;

    assert_eq!(s.gw.drift_count(), 1);
    assert_eq!(s.list().await, listed(&[]));
    let reply = s.call("echo").await;
    assert!(is_error(&reply));
    assert!(
        text(&reply).contains("tool 'echo' on 'a' changed since it was pinned"),
        "{}",
        text(&reply)
    );
    assert!(s.calls().is_empty());
    assert_eq!(
        s.outcomes(),
        [outcome("a", "deny", Some("rug-pull"), "echo")]
    );
    // Both still offer it, drifted or not.
    assert_eq!(
        s.gw.tool_warnings(),
        [collision("echo", &["a", "b"]).to_string()]
    );
}

#[tokio::test]
async fn with_prefixes_a_tool_is_listed_and_called_as_prefix_and_name() {
    let config = "tool_namespace = \"prefix\"\n\n".to_string()
        + &server("github", "prefix = \"gh\"")
        + &server("files", "tools = [\"search\"]");
    let s = Setup::new(
        &config,
        &[
            ("github", &["create_issue", "search"]),
            ("files", &["search", "delete"]),
        ],
    )
    .await;

    assert_eq!(
        s.list().await,
        listed(&[
            ("gh__create_issue", "github"),
            ("gh__search", "github"),
            ("files__search", "files"),
        ])
    );
    // Two tools named alike are two names, and neither collides.
    assert!(s.gw.tool_warnings().is_empty());

    // Called as listed, and sent as the server names it.
    assert_eq!(text(&s.call("gh__search").await), "github:search");
    assert_eq!(text(&s.call("files__search").await), "files:search");
    assert_eq!(
        text(&s.call("gh__create_issue").await),
        "github:create_issue"
    );
    // The server's own allowlist still judges the tool by its own name.
    let hidden = s.call("files__delete").await;
    assert!(is_error(&hidden));
    assert!(text(&hidden).contains("tool 'delete' is not on the allowlist"));
    // A name no server lists that way is no tool.
    for name in [
        "search",
        "github__search",
        "gh_search",
        "gh__",
        "files__create_issue",
    ] {
        let reply = s.call(name).await;
        assert!(
            text(&reply).contains(&format!("no governed server exposes tool '{name}'")),
            "{name}: {}",
            text(&reply)
        );
    }
    assert_eq!(
        s.calls(),
        [
            ("github".into(), "search".into()),
            ("files".into(), "search".into()),
            ("github".into(), "create_issue".into()),
        ]
    );
    let unknown = |name: &str| {
        (
            "(unrouted)".to_string(),
            "deny".to_string(),
            Some("unknown-tool".to_string()),
            Some(name.to_string()),
        )
    };
    assert_eq!(
        s.outcomes(),
        [
            outcome("github", "allow", None, "search"),
            outcome("files", "allow", None, "search"),
            outcome("github", "allow", None, "create_issue"),
            outcome("files", "deny", Some("not-on-allowlist"), "delete"),
            unknown("search"),
            unknown("github__search"),
            unknown("gh_search"),
            unknown("gh__"),
            unknown("files__create_issue"),
        ]
    );
}

/// Rules, roles and rate limits name a tool as its server does, and judge a
/// call to it by whatever name it was listed under.
#[tokio::test]
async fn with_prefixes_rules_roles_and_rate_limits_judge_the_tool_as_its_server_names_it() {
    let config = r#"tool_namespace = "prefix"

[gateway.rate_limit]
per_tool_per_sec = 0.001
per_tool_burst   = 1

[[policy]]
name    = "no-prod-issues"
effect  = "deny"
servers = ["github"]
tools   = ["create_issue"]
args    = [ { path = "repo", equals = "prod" } ]

[[role]]
name   = "reader"
grants = ["github:search", "files:search"]

"#
    .to_string()
        + &server("github", "")
        + &server("files", "");
    let s = Setup::new(
        &config,
        &[
            ("github", &["create_issue", "search"]),
            ("files", &["search"]),
        ],
    )
    .await;

    let prod = s
        .call_with("github__create_issue", json!({ "repo": "prod" }))
        .await;
    assert!(is_error(&prod));
    let reader = principal(&["reader"]);
    let ungranted = s
        .call_as("github__create_issue", json!({ "repo": "dev" }), &reader)
        .await;
    assert!(is_error(&ungranted));
    let granted = s.call_as("github__search", json!({}), &reader).await;
    assert_eq!(text(&granted), "github:search");
    // Its bucket is spent; the other server's `search` has its own.
    let limited = s.call("github__search").await;
    assert!(text(&limited).contains("tool rate limit exceeded for 'search'"));
    assert_eq!(text(&s.call("files__search").await), "files:search");
    assert_eq!(
        text(
            &s.call_with("github__create_issue", json!({ "repo": "dev" }))
                .await
        ),
        "github:create_issue"
    );
    assert_eq!(
        s.outcomes(),
        [
            outcome("github", "deny", Some("no-prod-issues"), "create_issue"),
            outcome("github", "deny", Some("rbac"), "create_issue"),
            outcome("github", "allow", None, "search"),
            outcome("github", "deny", Some("rate-limited"), "search"),
            outcome("files", "allow", None, "search"),
            outcome("github", "allow", None, "create_issue"),
        ]
    );
}

/// Pins are recorded as each server names its tools, by `mcpdef pin` and at
/// first sight alike, so switching prefixes on, at startup or by a reload,
/// drifts nothing and pins nothing new.
#[tokio::test]
async fn pins_hold_when_prefixes_are_switched_on() {
    let upstreams: &[(&str, &[&str])] = &[("github", &["search"]), ("files", &["lookup"])];
    let mut pins = PinStore::default();
    pins.record("github", "search", tool_hash(&tool("search")));
    pins.record("files", "lookup", tool_hash(&tool("lookup")));
    let servers = server("github", "prefix = \"gh\"") + &server("files", "");
    let on = format!("tool_namespace = \"prefix\"\n\n{servers}");

    // On from the start.
    let mut s = Setup::pinned(&on, upstreams, Some(pins.clone())).await;
    assert_eq!(s.gw.drift_count(), 0);
    assert_eq!(
        s.list().await,
        listed(&[("gh__search", "github"), ("files__lookup", "files")])
    );
    assert_eq!(text(&s.call("gh__search").await), "github:search");
    s.gw.persist_pins().unwrap();
    let saved = PinStore::load(s.dir.path().join("pins.toml")).unwrap();
    assert_eq!(saved.len(), 2);
    assert_eq!(
        saved.pinned_hash("github", "search"),
        Some(tool_hash(&tool("search")).as_str())
    );

    // Off at the start, then on by a reload, and off again.
    let mut s = Setup::pinned(&servers, upstreams, Some(pins)).await;
    assert_eq!(
        s.list().await,
        listed(&[("search", "github"), ("lookup", "files")])
    );
    s.reload(&on, upstreams).await;
    assert_eq!(s.gw.drift_count(), 0);
    assert_eq!(
        s.list().await,
        listed(&[("gh__search", "github"), ("files__lookup", "files")])
    );
    assert_eq!(text(&s.call("files__lookup").await), "files:lookup");
    let bare = s.call("lookup").await;
    assert!(text(&bare).contains("no governed server exposes tool 'lookup'"));
    s.reload(&servers, upstreams).await;
    assert_eq!(s.gw.drift_count(), 0);
    assert_eq!(text(&s.call("lookup").await), "files:lookup");
    s.gw.persist_pins().unwrap();
    assert_eq!(
        PinStore::load(s.dir.path().join("pins.toml"))
            .unwrap()
            .len(),
        2
    );
}

/// As `mcpdef run` starts a gateway from its config, and as its reloader
/// applies the file changed: prefixes on, off, and on again.
#[tokio::test]
async fn the_config_switches_prefixes_at_startup_and_by_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let write = |namespace: &str| {
        let text = format!(
            "[gateway]\naudit = {:?}\ntool_namespace = {namespace:?}\n\n[[server]]\n\
             id = \"mock\"\nprefix = \"m\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
             tools = [\"echo\"]\n",
            dir.path().join("audit.log")
        );
        std::fs::write(&path, text).unwrap();
    };
    write("prefix");
    let (config, raw) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(raw.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);
    let names = || {
        let gw = gw.clone();
        async move {
            let msg = Message::request(Id::Num(1), method::TOOLS_LIST, None);
            let listed = gw.handle(msg).await.unwrap().unwrap().result.unwrap();
            listed["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        }
    };
    let call = |name: &str| {
        let msg = Message::request(
            Id::Num(2),
            method::TOOLS_CALL,
            Some(json!({ "name": name, "arguments": {} })),
        );
        let gw = gw.clone();
        async move { text(&gw.handle(msg).await.unwrap().unwrap()) }
    };

    assert_eq!(names().await, ["m__echo"]);
    // The mock answers with the name it was sent.
    assert_eq!(call("m__echo").await, "echo: {}");
    for (namespace, listed) in [("off", "echo"), ("prefix", "m__echo")] {
        write(namespace);
        let outcome = reloader.reload(Trigger::Signal).await;
        assert!(
            matches!(outcome, reload::Outcome::Applied(_)),
            "{outcome:?}"
        );
        assert_eq!(names().await, [listed], "{namespace}");
        assert_eq!(call(listed).await, "echo: {}", "{namespace}");
    }
}

/// Two servers can still meet on a name when a prefix or a tool name has the
/// separator in it: that is a collision like any other.
#[tokio::test]
async fn prefixed_names_that_still_meet_are_reported_like_any_other_collision() {
    let config = "tool_namespace = \"prefix\"\n\n".to_string()
        + &server("gh", "tools = [\"x__y\"]")
        + &server("gh__x", "tools = [\"y\"]");
    let met = collision("gh__x__y", &["gh", "gh__x"]);
    let cfg = Config::parse(&format!("[gateway]\n{config}")).unwrap();
    assert_eq!(cfg.warnings(), [met.to_string()]);

    let s = Setup::new(&config, &[("gh", &["x__y"]), ("gh__x", &["y"])]).await;
    assert_eq!(s.list().await, listed(&[("gh__x__y", "gh")]));
    assert_eq!(text(&s.call("gh__x__y").await), "gh:x__y");
    assert_eq!(s.gw.tool_warnings(), [met.to_string()]);
}

/// A server that has never opened has listed nothing, so its allowlist says
/// which names are its, under its prefix: a call to one fails as the server
/// is down, not as an unknown tool.
#[tokio::test]
async fn a_server_that_never_opened_is_called_by_its_prefixed_names() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(
        &("[gateway]\ntool_namespace = \"prefix\"\n\n".to_string()
            + &server("github", "prefix = \"gh\"\ntools = [\"create_issue\"]")
            + &server("files", "")),
    )
    .unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let gw =
        Gateway::new(cfg.to_policy(), ledger, "agent:test").with_tool_prefixes(cfg.tool_prefixes());
    let calls = Calls::default();
    gw.start_supervised(
        vec![
            supervised("github", refused()),
            supervised("files", serving("files", &["search"], &calls)),
        ],
        Startup::Degraded,
    )
    .await
    .unwrap();

    let call = |name: &str| {
        let msg = Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": name, "arguments": {} })),
        );
        let gw = gw.clone();
        async move { text(&gw.handle(msg).await.unwrap().unwrap()) }
    };
    assert!(call("gh__create_issue")
        .await
        .starts_with("MCPdef error: upstream 'github' is down"));
    for name in [
        "create_issue",
        "github__create_issue",
        "files__create_issue",
    ] {
        assert!(
            call(name).await.contains("no governed server exposes tool"),
            "{name}"
        );
    }
    assert_eq!(call("files__search").await, "files:search");
}

#[tokio::test]
async fn with_prefixes_a_listed_name_longer_than_fifty_is_warned_about() {
    // `p__` and 47 characters is 50; one more is 51.
    let fits = "a".repeat(47);
    let long = "b".repeat(48);
    let config = format!(
        "tool_namespace = \"prefix\"\n\n{}",
        server(
            "s",
            &format!("prefix = \"p\"\ntools = [{fits:?}, {long:?}]")
        )
    );
    let warning = format!(
        "tool '{long}' of 's' is listed as 'p__{long}', 51 characters: some clients cut or \
         refuse a name longer than 50 once they add a prefix of their own"
    );
    let cfg = Config::parse(&format!("[gateway]\n{config}")).unwrap();
    assert_eq!(cfg.warnings(), std::slice::from_ref(&warning));

    let s = Setup::new(&config, &[("s", &[fits.as_str(), long.as_str()])]).await;
    assert_eq!(s.gw.tool_warnings(), [warning]);
    // Listed, and called, all the same.
    assert_eq!(s.list().await.len(), 2);
    assert_eq!(
        text(&s.call(&format!("p__{long}")).await),
        format!("s:{long}")
    );
}

#[test]
fn validate_refuses_a_prefix_no_tool_name_may_start_with() {
    let parse = |text: String| Config::parse(&format!("[gateway]\n{text}")).unwrap();
    let cfg = parse(
        "tool_namespace = \"prefix\"\n\n".to_string()
            + &server("my server", "")
            + &server("b", "prefix = \"\"")
            + &server("c", "prefix = \"c/d\""),
    );
    let rule = "is not one a tool name may start with: use letters, digits, '_', '-' and '.'";
    assert_eq!(
        cfg.validate(),
        [
            format!("server 'my server': tool prefix 'my server', its id, {rule}, or set `prefix`"),
            format!("server 'b': tool prefix '' {rule}"),
            format!("server 'c': tool prefix 'c/d' {rule}"),
        ]
    );
    // An id no tool name may start with is fine with a prefix of its own, or
    // with no prefixes at all.
    let own = parse(
        "tool_namespace = \"prefix\"\n\n".to_string() + &server("my server", "prefix = \"mine\""),
    );
    assert_eq!(own.validate(), Vec::<String>::new());
    assert_eq!(
        parse(server("my server", "")).validate(),
        Vec::<String>::new()
    );
}

#[test]
fn validate_warns_about_names_two_allowlists_give_and_prefixes_that_do_nothing() {
    let warnings = |text: String| {
        Config::parse(&format!("[gateway]\n{text}"))
            .unwrap()
            .warnings()
    };
    // Named outright by both allowlists. A pattern names no one tool, and a
    // name the allowlist's own deny takes back is not offered.
    let named = server(
        "a",
        "tools = [\"echo\", \"a_*\", \"get_*\", \"gone\"]\ndeny = [\"gone\"]",
    ) + &server("b", "tools = [\"echo\", \"a_one\", \"get_*\", \"gone\"]");
    assert_eq!(
        warnings(named.clone()),
        [collision("echo", &["a", "b"]).to_string()]
    );
    // With prefixes they are two names.
    assert_eq!(
        warnings(format!("tool_namespace = \"prefix\"\n\n{named}")),
        Vec::<String>::new()
    );
    // A prefix that nothing uses, and one two servers share.
    assert_eq!(
        warnings(server("a", "prefix = \"x\"")),
        ["[[server]] 'a' sets `prefix`, which only `[gateway] tool_namespace = \"prefix\"` uses"]
    );
    assert_eq!(
        warnings(
            "tool_namespace = \"prefix\"\n\n".to_string()
                + &server("a", "prefix = \"p\"\ntools = [\"one\"]")
                + &server("b", "prefix = \"p\"\ntools = [\"two\"]")
        ),
        [
            "servers 'a' and 'b' share the tool prefix 'p': a tool both offer is listed once, \
             from 'a', and a call to it goes there"
        ]
    );
    // Under strict, each is an error.
    let cfg = Config::parse(&format!("[gateway]\n{named}")).unwrap();
    let checked = cfg.check(true);
    assert_eq!(
        checked.errors,
        [format!("strict: {}", collision("echo", &["a", "b"]))]
    );
    assert!(checked.warnings.is_empty());
}

/// A running gateway, the one `mcpdef call` starts, reports what it finds the
/// servers offer: a warning, or under `strict` a start refused. A collision
/// the config already shows is said once.
#[test]
fn a_collision_found_at_startup_is_a_warning_and_under_strict_refuses_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    let write = |strict: bool, tools: &str| {
        let upstream = |id: &str| {
            format!(
                "[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \
                 \"--label\", \"{id}:\"]\ntools = [{tools:?}]\n\n"
            )
        };
        let text = format!(
            "[gateway]\naudit = {:?}\nstrict = {strict}\n\n{}{}",
            dir.path().join("audit.log"),
            upstream("a"),
            upstream("b")
        );
        std::fs::write(&cfg, text).unwrap();
    };
    let call_echo = || {
        let out = Command::new(BIN)
            .args(["call", "echo", "--config"])
            .arg(&cfg)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (out.status.success(), stdout, stderr)
    };
    let reported = collision("echo", &["a", "b"]).to_string();

    // Only the running servers show it: each allowlist is a pattern.
    write(false, "ec*");
    let (ok, stdout, stderr) = call_echo();
    assert!(ok, "{stderr}");
    assert!(stdout.contains("a:echo"), "{stdout}");
    assert_eq!(
        stderr
            .matches(&format!("mcpdef: warning — {reported}"))
            .count(),
        1,
        "{stderr}"
    );
    write(true, "ec*");
    let (ok, _, stderr) = call_echo();
    assert!(!ok);
    assert!(stderr.contains(&format!("strict: {reported}")), "{stderr}");

    // The config shows it too: said once, and refused before anything starts.
    write(false, "echo");
    let (ok, stdout, stderr) = call_echo();
    assert!(ok, "{stderr}");
    assert!(stdout.contains("a:echo"), "{stdout}");
    assert_eq!(stderr.matches(&reported).count(), 1, "{stderr}");
    write(true, "echo");
    let (ok, _, stderr) = call_echo();
    assert!(!ok);
    assert!(
        stderr.contains(&format!("✗ strict: {reported}")) && stderr.contains("invalid config"),
        "{stderr}"
    );
}

#[test]
fn mcpdef_validate_warns_about_a_collision_and_strict_refuses_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        "[gateway]\n".to_string()
            + &server("a", "tools = [\"echo\"]")
            + &server("b", "tools = [\"echo\"]"),
    )
    .unwrap();
    let validate = |strict: bool| {
        let mut command = Command::new(BIN);
        command.args(["validate", "--config"]).arg(&cfg);
        if strict {
            command.arg("--strict");
        }
        let out = command.output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let reported = collision("echo", &["a", "b"]).to_string();
    let (ok, stderr) = validate(false);
    assert!(ok, "{stderr}");
    assert!(stderr.contains(&format!("⚠ {reported}")), "{stderr}");
    let (ok, stderr) = validate(true);
    assert!(!ok);
    assert!(
        stderr.contains(&format!("✗ strict: {reported}")),
        "{stderr}"
    );
}

/// `/api/v1/servers`, from an admin server on `s`, as `mcpdef run` serves it.
async fn admin_servers(s: &Setup) -> Value {
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap().to_string();
    let state = Arc::new(AdminState::new(
        &s.cfg,
        Arc::new(Metrics::new(s.cfg.servers.len() as u64)),
        s.gw.clone(),
        "test",
    ));
    tokio::spawn(serve_admin_on(state, bound, None));
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match client
            .get(format!("http://{listen}/api/v1/servers"))
            .send()
            .await
        {
            Ok(response) => return serde_json::from_str(&response.text().await.unwrap()).unwrap(),
            Err(e) if Instant::now() > until => panic!("{e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

#[tokio::test]
async fn the_admin_servers_view_names_each_collision_on_every_server_in_it() {
    let config = ["a", "b", "c"].map(|id| server(id, "")).concat();
    let s = Setup::new(
        &config,
        &[
            ("a", &["echo", "lookup"]),
            ("b", &["echo"]),
            ("c", &["other"]),
        ],
    )
    .await;
    let servers = admin_servers(&s).await;
    let expected = json!([{ "tool": "echo", "servers": ["a", "b"] }]);
    assert_eq!(servers[0]["tool_collisions"], expected);
    assert_eq!(servers[1]["tool_collisions"], expected);
    // None to name: not there at all.
    assert!(
        servers[2].get("tool_collisions").is_none(),
        "{}",
        servers[2]
    );
}

/// On the 2026-07-28 wire `Mcp-Name` mirrors the name in the body, which is
/// the prefixed one: the listener checks the two agree before anything
/// routes, and the upstream is sent the name as it knows the tool.
#[tokio::test]
async fn on_the_modern_wire_mcp_name_mirrors_the_prefixed_name() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(
        &("[gateway]\ntool_namespace = \"prefix\"\n\n".to_string()
            + &server("mock", "prefix = \"m\"\ntools = [\"echo\"]")),
    )
    .unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:test")
        .with_wire(WireMode::Dual)
        .with_tool_prefixes(cfg.tool_prefixes());
    gw.add_upstream(
        "mock",
        Box::new(StdioChild::spawn(&[MOCK.to_string()]).unwrap()),
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let http = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::Dual,
    };
    tokio::spawn(serve_http_on(listener, gw, http, None));
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let post = |name_header: &'static str| {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "m__echo",
                "arguments": { "msg": "hi" },
                "_meta": {
                    meta_key::PROTOCOL_VERSION: SPEC_2026_07_28,
                    meta_key::CLIENT_INFO: { "name": "test", "version": "0" },
                    meta_key::CLIENT_CAPABILITIES: {},
                }
            }
        });
        let request = client
            .post(format!("http://{addr}/mcp"))
            .header("content-type", "application/json")
            .header(header::PROTOCOL_VERSION, SPEC_2026_07_28)
            .header(header::METHOD, "tools/call")
            .header(header::NAME, name_header)
            .body(body.to_string());
        async move {
            let resp = request.send().await.unwrap();
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap();
            (status, serde_json::from_str::<Value>(&text).unwrap())
        }
    };

    let (status, v) = post("m__echo").await;
    assert_eq!(status, 200, "{v}");
    // The mock answers with the name it was sent.
    assert_eq!(
        v["result"]["content"][0]["text"], "echo: {\"msg\":\"hi\"}",
        "{v}"
    );
    // The server's own name is not the one the body calls.
    let (status, v) = post("echo").await;
    assert_eq!(status, 400, "{v}");
    assert_eq!(v["error"]["code"], error_code::HEADER_MISMATCH);
}
