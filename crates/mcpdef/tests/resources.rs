// SPDX-License-Identifier: Apache-2.0
//! Resources through the gateway. Each server's `resources` allowlist decides
//! what it may expose; lists come from every server that exposes any; a read
//! goes to the server that has the URI, and is sent the URI in normal form.
//! Before, every `resources/*` call went to the first server, ungoverned.

use mcpdef::{Config, Gateway};
use mcpdef_audit::{read_all, Ledger, Record};
use mcpdef_auth::Principal;
use mcpdef_core::wire::meta_key;
use mcpdef_core::{method, Id, Message};
use mcpdef_transport::{duplex_pair, Duplex, Transport};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// What one upstream serves.
#[derive(Clone, Default)]
struct Serves {
    /// The URIs it lists.
    resources: Vec<&'static str>,
    /// How many entries a page of its list holds; `None` lists all at once.
    page: Option<usize>,
    /// The templates it lists.
    templates: Vec<&'static str>,
    /// A `resource_link` its tool results carry.
    link: Option<&'static str>,
    /// Answers every `resources/*` with `-32601`, like a server without them.
    no_resources: bool,
    /// What a read of any URI holds; `None` answers `<upstream>:<uri>`.
    text: Option<String>,
}

/// Every request an upstream got: which upstream, the method, and for a read
/// the URI it was sent.
type Log = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

fn spawn(label: &'static str, serves: Serves, log: Log) -> Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let method = msg.method().unwrap_or_default().to_string();
            let uri = msg
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(Value::as_str)
                .map(str::to_string);
            log.lock()
                .unwrap()
                .push((label.to_string(), method.clone(), uri.clone()));
            let resources_refused = serves.no_resources && method.starts_with("resources/");
            let reply = match method.as_str() {
                _ if resources_refused => Message::error(id, -32601, "method not found"),
                method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {}, "resources": {} },
                        "serverInfo": { "name": label, "version": "0" },
                    }),
                ),
                method::TOOLS_LIST => Message::result(
                    id,
                    json!({ "tools": [{
                        "name": format!("{label}_tool"),
                        "inputSchema": { "type": "object" },
                    }] }),
                ),
                method::TOOLS_CALL => {
                    let mut content = vec![json!({ "type": "text", "text": "ok" })];
                    if let Some(link) = serves.link {
                        content.push(
                            json!({ "type": "resource_link", "uri": link, "name": "linked" }),
                        );
                    }
                    Message::result(id, json!({ "isError": false, "content": content }))
                }
                method::RESOURCES_LIST => {
                    let start: usize = msg
                        .params
                        .as_ref()
                        .and_then(|p| p["cursor"].as_str())
                        .map_or(0, |c| c.parse().unwrap());
                    let size = serves.page.unwrap_or(usize::MAX);
                    let page: Vec<Value> = serves
                        .resources
                        .iter()
                        .skip(start)
                        .take(size)
                        .map(|uri| {
                            json!({
                                "uri": uri,
                                "name": uri,
                                "_meta": { "mcpdef/server": "spoofed", "own": true },
                            })
                        })
                        .collect();
                    let mut result = json!({ "resources": page });
                    if start.saturating_add(size) < serves.resources.len() {
                        result["nextCursor"] = json!((start + size).to_string());
                    }
                    Message::result(id, result)
                }
                method::RESOURCES_TEMPLATES_LIST => {
                    let templates: Vec<Value> = serves
                        .templates
                        .iter()
                        .map(|t| json!({ "uriTemplate": t, "name": t }))
                        .collect();
                    Message::result(id, json!({ "resourceTemplates": templates }))
                }
                method::RESOURCES_READ => {
                    let uri = uri.unwrap_or_default();
                    Message::result(
                        id,
                        json!({ "contents": [{
                            "uri": uri,
                            "mimeType": "text/plain",
                            "text": serves.text.clone().unwrap_or_else(|| format!("{label}:{uri}")),
                        }] }),
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

struct Setup {
    gw: Gateway,
    dir: TempDir,
    log: Log,
}

impl Setup {
    async fn new(config: &str, upstreams: Vec<(&'static str, Serves)>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(&path, format!("[gateway]\n{config}")).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
        // Every gate the config sets, as `build_gateway` applies them.
        let (per_tool, global) = cfg.gateway.rate_limit_settings();
        let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:test")
            .with_rate_limit(per_tool, global)
            .with_rbac(Some(cfg.rbac()))
            .with_policy_rules(cfg.policy_rules())
            .with_inspect(cfg.gateway.inspect_scanner());
        let log = Log::default();
        for (label, serves) in upstreams {
            gw.add_upstream(label, Box::new(spawn(label, serves, Arc::clone(&log))))
                .await
                .unwrap();
        }
        Setup { gw, dir, log }
    }

    async fn send(&self, method: &str, params: Option<Value>) -> Message {
        self.gw
            .handle(Message::request(Id::Num(7), method, params))
            .await
            .unwrap()
            .unwrap()
    }

    async fn list(&self) -> Vec<Value> {
        let resp = self.send(method::RESOURCES_LIST, None).await;
        resp.result.expect("a list")["resources"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn read(&self, uri: &str) -> Message {
        self.send(method::RESOURCES_READ, Some(json!({ "uri": uri })))
            .await
    }

    /// A read by an authenticated caller, as the HTTP listener hands it on.
    async fn read_as(&self, uri: &str, principal: &Principal) -> Message {
        let msg = Message::request(
            Id::Num(7),
            method::RESOURCES_READ,
            Some(json!({ "uri": uri })),
        );
        self.gw
            .handle_authed(msg, Some(principal))
            .await
            .unwrap()
            .unwrap()
    }

    /// The reads upstreams were sent: (upstream, URI).
    fn reads(&self) -> Vec<(String, String)> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m, _)| m == method::RESOURCES_READ)
            .map(|(label, _, uri)| (label.clone(), uri.clone().unwrap()))
            .collect()
    }

    /// How many times each upstream was sent `method`.
    fn asked(&self, method: &str) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m, _)| m == method)
            .map(|(label, _, _)| label.clone())
            .collect()
    }

    /// The ledger's records of reads, once the gateway is done.
    fn read_records(self) -> Vec<Record> {
        drop(self.gw);
        read_all(self.dir.path().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_deref() == Some(method::RESOURCES_READ))
            .collect()
    }
}

fn server(id: &str, extra: &str) -> String {
    format!("[[server]]\nid = \"{id}\"\ntransport = \"stdio\"\ncommand = [\"unused\"]\n{extra}\n")
}

fn text(resp: &Message) -> String {
    resp.result.as_ref().expect("a result")["contents"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

fn error(resp: &Message) -> (i64, String) {
    let error = resp.error.as_ref().expect("an error");
    (
        error["code"].as_i64().unwrap(),
        error["message"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn a_resource_on_the_second_server_is_read_from_it_in_normal_form() {
    let config = [
        server("a", r#"resources = ["file:///a/**"]"#),
        server("b", r#"resources = ["file:///b/**"]"#),
    ]
    .concat();
    let up = |resources| Serves {
        resources,
        ..Serves::default()
    };
    let s = Setup::new(
        &config,
        vec![
            ("a", up(vec!["file:///a/1"])),
            ("b", up(vec!["file:///b/%7Ebob/2"])),
        ],
    )
    .await;

    // Both servers' resources, in config order, each naming its server, and
    // each shown as it will be judged and sent.
    let listed = s.list().await;
    let uris: Vec<&str> = listed.iter().map(|r| r["uri"].as_str().unwrap()).collect();
    assert_eq!(uris, ["file:///a/1", "file:///b/~bob/2"]);
    let servers: Vec<&str> = listed
        .iter()
        .map(|r| r["_meta"]["mcpdef/server"].as_str().unwrap())
        .collect();
    assert_eq!(servers, ["a", "b"]);
    // The server's own `_meta` is kept, and its claim to be another is not.
    assert_eq!(listed[1]["_meta"]["own"], json!(true));

    let resp = s.read("FILE:///b/x/../%7ebob/2").await;
    assert_eq!(text(&resp), "b:file:///b/~bob/2");
    assert_eq!(s.reads(), [("b".into(), "file:///b/~bob/2".into())]);

    let records = s.read_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].server, "b");
    assert_eq!(records[0].decision, "allow");
    assert_eq!(records[0].uri.as_deref(), Some("file:///b/~bob/2"));
}

#[tokio::test]
async fn a_uri_no_allowlist_takes_is_denied_as_not_found_and_audited_with_it() {
    let config = [
        server("a", r#"resources = ["file:///a/**"]"#),
        server("b", r#"resources = ["file:///b/**"]"#),
    ]
    .concat();
    let s = Setup::new(
        &config,
        vec![("a", Serves::default()), ("b", Serves::default())],
    )
    .await;

    let (code, message) = error(&s.read("file:///etc/passwd").await);
    assert_eq!(code, -32002);
    assert_eq!(
        message,
        "MCPdef denied: no server's resource allowlist takes 'file:///etc/passwd'"
    );
    assert!(s.reads().is_empty(), "no upstream was asked");

    let records = s.read_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].server, "(unrouted)");
    assert_eq!(records[0].decision, "deny");
    assert_eq!(records[0].rule.as_deref(), Some("resource-not-allowed"));
    assert_eq!(records[0].uri.as_deref(), Some("file:///etc/passwd"));
}

/// URIs under `/srv/docs/` that try to leave it, against an upstream that
/// would serve whatever it is sent.
#[tokio::test]
async fn the_traversal_corpus_is_denied_end_to_end() {
    let config = server("docs", r#"resources = ["file:///srv/docs/*"]"#);
    let s = Setup::new(&config, vec![("docs", Serves::default())]).await;
    let corpus = [
        "file:///srv/docs/../secret",
        "file:///srv/docs/../../etc/passwd",
        "file:///srv/docs/%2e%2e/secret",
        "file:///srv/docs/%2E%2e/secret",
        "file:///srv/docs/.%2e/secret",
        "file:///srv/docs/a/../../secret",
        "file:///srv/docs/..",
        "file:///srv/docs/%2e%2e",
        "file:///srv/docs/a/..",
        "file:///srv/docs/..%2Fsecret",
        "file:///srv/docs/..%5Csecret",
        "file:///srv/docs/..\\secret",
        "file:///srv/docs/%252e%252e/secret",
        "file:///srv/docs/%25%32%65%25%32%65",
        "file:///srv/docs/%25%32%66secret",
        "file:///srv/docs/a%00.txt",
        "file:///srv/docs//etc/passwd",
        "file:///srv/docs/a?../../etc/passwd",
        "file://evil/srv/docs/a",
        "/srv/docs/a",
    ];
    for uri in corpus {
        let (code, message) = error(&s.read(uri).await);
        assert_eq!(code, -32002, "{uri}");
        assert!(message.starts_with("MCPdef denied: "), "{uri}: {message}");
    }
    assert!(s.reads().is_empty(), "sent upstream: {:?}", s.reads());

    // What the allowlist does take still reads.
    assert_eq!(
        text(&s.read("file:///srv/docs/guide.md").await),
        "docs:file:///srv/docs/guide.md"
    );

    let records = s.read_records();
    assert_eq!(records.len(), corpus.len() + 1);
    for (record, uri) in records.iter().zip(corpus) {
        assert_eq!(record.decision, "deny", "{uri}");
        assert!(record.uri.is_some(), "{uri} audited without its URI");
    }
    let refused = records
        .iter()
        .filter(|r| r.rule.as_deref() == Some("uri-refused"))
        .count();
    // The encoded separators, the backslash, the double encodings, the NUL,
    // the empty segment and the missing scheme.
    assert_eq!(refused, 9);
}

#[tokio::test]
async fn a_server_with_no_resources_list_exposes_none() {
    let config = server("fs", "");
    let serves = Serves {
        resources: vec!["file:///x"],
        templates: vec!["file:///{path}"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("fs", serves)]).await;

    let init = s.send(method::INITIALIZE, Some(json!({}))).await;
    assert_eq!(
        init.result.unwrap()["capabilities"],
        json!({ "tools": {} }),
        "resources are not offered"
    );
    assert!(s.list().await.is_empty());
    let templates = s.send(method::RESOURCES_TEMPLATES_LIST, None).await;
    assert_eq!(templates.result.unwrap()["resourceTemplates"], json!([]));
    assert_eq!(error(&s.read("file:///x").await).0, -32002);
    // Its lists were never asked for, and nothing was read.
    assert!(s.asked(method::RESOURCES_LIST).is_empty());
    assert!(s.asked(method::RESOURCES_TEMPLATES_LIST).is_empty());
    assert!(s.reads().is_empty());
}

#[tokio::test]
async fn a_list_follows_pages_and_shows_only_what_the_allowlist_takes() {
    let config = server("a", r#"resources = ["file:///a/keep/*"]"#);
    let serves = Serves {
        resources: vec![
            "file:///a/keep/1",
            "file:///a/drop/2",
            "file:///a/keep/3",
            "file:///a/keep/%2e%2e/escaped",
            "file:///a/keep/4",
        ],
        page: Some(2),
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", serves)]).await;

    let listed = s.list().await;
    let uris: Vec<&str> = listed.iter().map(|r| r["uri"].as_str().unwrap()).collect();
    assert_eq!(
        uris,
        ["file:///a/keep/1", "file:///a/keep/3", "file:///a/keep/4"]
    );
    assert_eq!(s.asked(method::RESOURCES_LIST).len(), 3, "three pages");

    // All of it in one page: a client has no cursor to send, and one sent is refused.
    let resp = s.send(method::RESOURCES_LIST, None).await;
    assert!(resp.result.unwrap().get("nextCursor").is_none());
    let resp = s
        .send(method::RESOURCES_LIST, Some(json!({ "cursor": "2" })))
        .await;
    assert_eq!(error(&resp).0, -32602);
}

#[tokio::test]
async fn a_read_goes_to_the_server_that_listed_or_linked_its_uri() {
    let shared = r#"resources = ["file:///shared/**"]"#;
    let config = [server("a", shared), server("b", shared)].concat();
    let b = Serves {
        resources: vec!["file:///shared/listed"],
        link: Some("file:///shared/linked"),
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", Serves::default()), ("b", b)]).await;

    // Unseen, it goes to the first server whose allowlist takes it.
    s.read("file:///shared/unseen").await;
    // Listed by b, it goes to b.
    s.list().await;
    s.read("file:///shared/listed").await;
    // Linked by one of b's tool results, it goes to b.
    let call = s
        .send(
            method::TOOLS_CALL,
            Some(json!({ "name": "b_tool", "arguments": {} })),
        )
        .await;
    assert_eq!(call.result.unwrap()["isError"], json!(false));
    s.read("file:///shared/linked").await;

    assert_eq!(
        s.reads(),
        [
            ("a".into(), "file:///shared/unseen".into()),
            ("b".into(), "file:///shared/listed".into()),
            ("b".into(), "file:///shared/linked".into()),
        ]
    );
}

#[tokio::test]
async fn templates_are_shown_only_when_listed_and_allow_no_read() {
    let config = server("a", r#"resource_templates = ["file:///docs/{*}"]"#);
    let serves = Serves {
        templates: vec!["file:///docs/{path}", "file:///secret/{path}"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", serves)]).await;

    let init = s.send(method::INITIALIZE, Some(json!({}))).await;
    assert_eq!(init.result.unwrap()["capabilities"]["resources"], json!({}));
    let resp = s.send(method::RESOURCES_TEMPLATES_LIST, None).await;
    let templates = resp.result.unwrap()["resourceTemplates"].clone();
    assert_eq!(
        templates,
        json!([{
            "uriTemplate": "file:///docs/{path}",
            "name": "file:///docs/{path}",
            "_meta": { "mcpdef/server": "a" },
        }])
    );
    // Templates only: there is no URI list to ask for, and a URI filled in
    // from the template is not on any `resources` allowlist.
    assert!(s.list().await.is_empty());
    assert!(s.asked(method::RESOURCES_LIST).is_empty());
    assert_eq!(error(&s.read("file:///docs/readme").await).0, -32002);
}

#[tokio::test]
async fn a_modern_client_gets_caching_hints_and_a_legacy_one_does_not() {
    let config = server("a", r#"resources = ["file:///a/*"]"#);
    let serves = Serves {
        resources: vec!["file:///a/1"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", serves)]).await;
    let modern = |more: Value| {
        let mut params = json!({ "_meta": { meta_key::PROTOCOL_VERSION: "2026-07-28" } });
        if let (Some(params), Some(more)) = (params.as_object_mut(), more.as_object()) {
            params.extend(more.clone());
        }
        Some(params)
    };

    let list = s.send(method::RESOURCES_LIST, modern(json!({}))).await;
    let list = list.result.unwrap();
    assert_eq!(
        (&list["resultType"], &list["ttlMs"], &list["cacheScope"]),
        (&json!("complete"), &json!(0), &json!("private"))
    );
    let read = s
        .send(
            method::RESOURCES_READ,
            modern(json!({ "uri": "file:///a/1" })),
        )
        .await;
    let read = read.result.unwrap();
    assert_eq!(
        (&read["resultType"], &read["ttlMs"], &read["cacheScope"]),
        (&json!("complete"), &json!(0), &json!("private"))
    );

    let legacy = s.send(method::RESOURCES_LIST, None).await.result.unwrap();
    assert!(legacy.get("ttlMs").is_none() && legacy.get("resultType").is_none());
}

#[tokio::test]
async fn subscriptions_are_refused_and_never_forwarded() {
    let config = server("a", r#"resources = ["file:///a/*"]"#);
    let s = Setup::new(&config, vec![("a", Serves::default())]).await;
    for method in [method::RESOURCES_SUBSCRIBE, method::RESOURCES_UNSUBSCRIBE] {
        let (code, message) = error(&s.send(method, Some(json!({ "uri": "file:///a/1" }))).await);
        assert_eq!(code, -32601);
        assert!(message.contains("subscriptions"), "{message}");
        assert!(s.asked(method).is_empty());
    }
}

/// Two servers whose allowlists overlap both list one URI: the first in config
/// order has it. It is shown once, from there, and read from there.
#[tokio::test]
async fn a_uri_two_servers_list_is_shown_once_from_the_first_and_read_there() {
    let shared = r#"resources = ["file:///shared/**"]"#;
    let config = [server("a", shared), server("b", shared)].concat();
    let a = Serves {
        resources: vec!["file:///shared/x"],
        ..Serves::default()
    };
    let b = Serves {
        resources: vec!["file:///shared/x", "file:///shared/b_only"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", a), ("b", b)]).await;

    let listed: Vec<(String, String)> = s
        .list()
        .await
        .iter()
        .map(|r| {
            (
                r["uri"].as_str().unwrap().to_string(),
                r["_meta"]["mcpdef/server"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("file:///shared/x".into(), "a".into()),
            ("file:///shared/b_only".into(), "b".into()),
        ]
    );
    assert_eq!(
        text(&s.read("file:///shared/x").await),
        "a:file:///shared/x"
    );
    assert_eq!(
        text(&s.read("file:///shared/b_only").await),
        "b:file:///shared/b_only"
    );
}

#[tokio::test]
async fn a_server_without_resources_adds_nothing_to_a_list() {
    let any = r#"resources = ["file:///**"]"#;
    let config = [server("a", any), server("b", any)].concat();
    let a = Serves {
        no_resources: true,
        ..Serves::default()
    };
    let b = Serves {
        resources: vec!["file:///b/1"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", a), ("b", b)]).await;
    let listed = s.list().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["uri"], json!("file:///b/1"));
}

#[test]
fn a_resources_entry_that_is_not_a_uri_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let config = server(
        "a",
        r#"resources = ["file:///ok/*", "/srv/*", "file:///a%2Fb/*"]"#,
    );
    std::fs::write(&path, format!("[gateway]\n{config}")).unwrap();
    let errors = Config::load(&path).unwrap().validate();
    assert_eq!(
        errors,
        [
            "server 'a': resources entry '/srv/*' has no scheme",
            "server 'a': resources entry 'file:///a%2Fb/*' encodes a path separator (`%2F` or `%5C`)",
        ]
    );
}

#[test]
fn overlapping_allowlists_are_warned_about_and_refused_strictly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let config = [
        server("a", r#"resources = ["file:///shared/**"]"#),
        server(
            "b",
            r#"resources = ["file:///b/*", "file:///shared/docs/*"]"#,
        ),
        server("c", r#"resources = ["file:///c/*"]"#),
    ]
    .concat();
    std::fs::write(&path, format!("[gateway]\n{config}")).unwrap();
    let cfg = Config::load(&path).unwrap();
    let overlap = "servers 'a' and 'b' can both serve one resource: 'file:///shared/**' and \
                   'file:///shared/docs/*' overlap. A read goes to the server that listed or \
                   linked its URI, and otherwise to 'a', the first";
    assert_eq!(cfg.warnings(), [overlap]);
    assert_eq!(cfg.check(false).errors, Vec::<String>::new());
    assert_eq!(cfg.check(true).errors, [format!("strict: {overlap}")]);
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

/// What each read record says: (decision, rule, URI).
fn outcomes(records: &[Record]) -> Vec<(String, Option<String>, Option<String>)> {
    records
        .iter()
        .map(|r| (r.decision.clone(), r.rule.clone(), r.uri.clone()))
        .collect()
}

fn allowed(uri: &str) -> (String, Option<String>, Option<String>) {
    ("allow".into(), None, Some(uri.into()))
}

fn denied_by(rule: &str, uri: &str) -> (String, Option<String>, Option<String>) {
    ("deny".into(), Some(rule.into()), Some(uri.into()))
}

#[tokio::test]
async fn a_uris_rule_denies_a_read_and_a_tools_rule_does_not() {
    let config = format!(
        "{}{}",
        server("fs", r#"resources = ["file:///srv/**"]"#),
        r#"
[[policy]]
name   = "no-secret-files"
effect = "deny"
uris   = ["file:///srv/secret/**"]

[[policy]]
name   = "no-tools"
effect = "deny"
tools  = ["*"]
"#
    );
    let s = Setup::new(&config, vec![("fs", Serves::default())]).await;

    let (code, message) = error(&s.read("file:///srv/secret/key").await);
    assert_eq!(code, -32002);
    assert_eq!(
        message,
        "MCPdef denied: policy rule 'no-secret-files' denied 'file:///srv/secret/key' on 'fs'"
    );
    // A rule about tools, even one for every tool, is not about reads.
    assert_eq!(
        text(&s.read("file:///srv/docs/a").await),
        "fs:file:///srv/docs/a"
    );
    assert_eq!(s.reads(), [("fs".into(), "file:///srv/docs/a".into())]);
    assert_eq!(
        outcomes(&s.read_records()),
        [
            denied_by("no-secret-files", "file:///srv/secret/key"),
            allowed("file:///srv/docs/a"),
        ]
    );
}

#[tokio::test]
async fn an_authenticated_read_needs_a_role_that_grants_its_uri() {
    let config = format!(
        "{}{}",
        server("fs", r#"resources = ["file:///srv/**"]"#),
        r#"
[[role]]
name            = "reader"
grants          = ["fs:*"]
resource_grants = ["fs:file:///srv/docs/**"]
"#
    );
    let s = Setup::new(&config, vec![("fs", Serves::default())]).await;
    let reader = principal(&["reader"]);
    let nobody = principal(&[]);

    assert_eq!(
        text(&s.read_as("file:///srv/docs/a", &reader).await),
        "fs:file:///srv/docs/a"
    );
    let (code, message) = error(&s.read_as("file:///srv/other/b", &reader).await);
    assert_eq!(code, -32002);
    assert_eq!(
        message,
        "MCPdef denied: no role grants 'file:///srv/other/b' on 'fs'"
    );
    assert_eq!(
        error(&s.read_as("file:///srv/docs/a", &nobody).await).0,
        -32002
    );
    // RBAC judges authenticated callers, as for tools: stdio has none.
    assert_eq!(
        text(&s.read("file:///srv/other/b").await),
        "fs:file:///srv/other/b"
    );
    assert_eq!(
        outcomes(&s.read_records()),
        [
            allowed("file:///srv/docs/a"),
            denied_by("rbac", "file:///srv/other/b"),
            denied_by("rbac", "file:///srv/docs/a"),
            allowed("file:///srv/other/b"),
        ]
    );
}

#[tokio::test]
async fn each_servers_reads_share_one_bucket_of_their_own() {
    let any = r#"resources = ["file:///**"]"#;
    let config = format!(
        "{}{}{}",
        server("a", any),
        server("b", any),
        r#"
[gateway.rate_limit]
per_tool_per_sec = 0.001
per_tool_burst   = 1
"#
    );
    let s = Setup::new(
        &config,
        vec![("a", Serves::default()), ("b", Serves::default())],
    )
    .await;

    assert!(s.read("file:///x/1").await.result.is_some());
    let (code, message) = error(&s.read("file:///x/2").await);
    assert_eq!(code, -32002);
    assert_eq!(
        message,
        "MCPdef denied: resource read rate limit exceeded for 'a' — retry shortly"
    );
    // A tool call on the same server has its own bucket.
    let call = s
        .send(
            method::TOOLS_CALL,
            Some(json!({ "name": "a_tool", "arguments": {} })),
        )
        .await;
    assert_eq!(call.result.unwrap()["isError"], json!(false));
    assert_eq!(
        outcomes(&s.read_records()),
        [
            allowed("file:///x/1"),
            denied_by("rate-limited", "file:///x/2"),
        ]
    );
}

#[tokio::test]
async fn a_secret_in_a_resource_is_refused_in_enforce_mode_and_passed_in_warn() {
    // An AWS access-key id's shape, put together here so no source file holds it.
    let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let leaky = Serves {
        text: Some(format!("aws_access_key_id = {key}")),
        ..Serves::default()
    };
    for (mode, blocked) in [("enforce", true), ("warn", false)] {
        let config = format!(
            "{}{}",
            server("fs", r#"resources = ["file:///srv/**"]"#),
            format_args!("[gateway.inspect]\nmode = {mode:?}\n"),
        );
        let s = Setup::new(&config, vec![("fs", leaky.clone())]).await;
        let resp = s.read("file:///srv/creds").await;
        let expected = if blocked {
            let (code, message) = error(&resp);
            assert_eq!(code, -32002);
            assert!(message.starts_with("MCPdef blocked: "), "{message}");
            assert!(!message.contains(&key), "the refusal repeats the secret");
            denied_by("secret-exfil", "file:///srv/creds")
        } else {
            assert!(text(&resp).contains(&key), "warn passes the resource on");
            allowed("file:///srv/creds")
        };
        assert_eq!(outcomes(&s.read_records()), [expected], "{mode}");
    }
}

/// A read tripping two gates is denied by the one a tool call would meet
/// first: the allowlist, then the policy rules, then RBAC, then the rate
/// limit, which a denied read leaves untouched.
#[tokio::test]
async fn the_gates_judge_a_read_in_the_order_they_judge_a_tool_call() {
    let config = format!(
        "{}{}",
        server("fs", r#"resources = ["file:///srv/**"]"#),
        r#"
[gateway.rate_limit]
per_tool_per_sec = 0.001
per_tool_burst   = 1

[[policy]]
name   = "no-secret-files"
effect = "deny"
uris   = ["file:///**/secret/**"]

[[role]]
name            = "reader"
resource_grants = ["fs:file:///srv/docs/**"]
"#
    );
    let s = Setup::new(&config, vec![("fs", Serves::default())]).await;
    let reader = principal(&["reader"]);
    let nobody = principal(&[]);

    // Off the allowlist, and a policy rule's URI too: the allowlist says so.
    s.read_as("file:///etc/secret/x", &nobody).await;
    // A policy rule's URI, and no role grants it: the rule says so.
    s.read_as("file:///srv/secret/x", &nobody).await;
    // No role grants it: RBAC says so, and spends no token...
    s.read_as("file:///srv/docs/a", &nobody).await;
    // ...so the bucket's one token is still there for a caller RBAC allows.
    assert!(s
        .read_as("file:///srv/docs/a", &reader)
        .await
        .result
        .is_some());
    s.read_as("file:///srv/docs/b", &reader).await;
    // The bucket is empty now, and no role grants it: RBAC says so.
    s.read_as("file:///srv/docs/c", &nobody).await;

    assert_eq!(
        outcomes(&s.read_records()),
        [
            denied_by("resource-not-allowed", "file:///etc/secret/x"),
            denied_by("no-secret-files", "file:///srv/secret/x"),
            denied_by("rbac", "file:///srv/docs/a"),
            allowed("file:///srv/docs/a"),
            denied_by("rate-limited", "file:///srv/docs/b"),
            denied_by("rbac", "file:///srv/docs/c"),
        ]
    );
}

#[test]
fn resource_grants_and_uris_rules_are_checked_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let config = format!(
        "[gateway]\n{}{}",
        server("fs", r#"resources = ["file:///srv/**"]"#),
        r#"
[[role]]
name            = "r"
resource_grants = ["file:///srv/**", "fs:/srv/*", "urn:isbn:1", "fs:file:///srv/docs/**"]

[[policy]]
name   = "both"
effect = "deny"
tools  = ["x"]
uris   = ["file:///srv/**"]

[[policy]]
name   = "empty"
effect = "deny"
uris   = []

[[policy]]
name   = "bad"
effect = "deny"
uris   = ["/srv/*"]

[[policy]]
name   = "args"
effect = "deny"
uris   = ["file:///srv/**"]
args   = [ { path = "name", exists = true } ]
"#
    );
    std::fs::write(&path, config).unwrap();
    let cfg = Config::load(&path).unwrap();
    assert_eq!(
        cfg.validate(),
        [
            "[[role]] 'r': resource grant 'file:///srv/**' names no server: write it as \
             'server-glob:uri-pattern', such as '*:file:///srv/**'",
            "[[role]] 'r': resource grant 'fs:/srv/*' has a URI pattern that has no scheme",
            "[[policy]] rule 'both' names both `tools` and `uris`, and so matches nothing: \
             a tool call has no URI, and a read no tool",
            "[[policy]] rule 'empty' has an empty `uris` list — omit it to match any, or list entries",
            "[[policy]] rule 'bad' uris entry '/srv/*' has no scheme",
            "[[policy]] rule 'args' names both `uris` and `args`, and so matches nothing: \
             a read has no arguments",
        ]
    );
    assert_eq!(
        cfg.warnings(),
        [
            "[[role]] 'r': resource grant 'urn:isbn:1' is for server 'urn', which no [[server]] \
          is: a grant is 'server-glob:uri-pattern'"
        ]
    );
}
