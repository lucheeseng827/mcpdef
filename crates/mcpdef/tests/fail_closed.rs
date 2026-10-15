// SPDX-License-Identifier: Apache-2.0
//! Fail closed. The gateway answers or routes a fixed set of methods, and
//! refuses any other with `-32601`, audited, sending it nowhere. Before, a
//! method it did not know went to the first server, ungoverned.
//! `completion/complete` is one it routes: to the server that has the prompt
//! or the resource template it names, judged as a request for that.

use mcpdef::{Config, Gateway};
use mcpdef_audit::{read_all, Ledger, Record};
use mcpdef_auth::Principal;
use mcpdef_core::{method, Id, Message};
use mcpdef_transport::{duplex_pair, Duplex, Transport};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// What one upstream serves.
#[derive(Clone, Default)]
struct Serves {
    prompts: Vec<&'static str>,
    templates: Vec<&'static str>,
    /// What a completion suggests; `None` suggests `<upstream>:<what>`.
    suggests: Option<String>,
}

/// Every request an upstream got: which upstream, the method, its params.
type Log = Arc<Mutex<Vec<(String, String, Value)>>>;

/// What an upstream is sent to open it; anything else it gets was routed.
const OPENING: [&str; 3] = [method::INITIALIZE, method::INITIALIZED, method::TOOLS_LIST];

fn spawn(label: &'static str, serves: Serves, log: Log) -> Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let method = msg.method().unwrap_or_default().to_string();
            let params = msg.params.clone().unwrap_or(Value::Null);
            log.lock()
                .unwrap()
                .push((label.to_string(), method.clone(), params.clone()));
            let Some(id) = msg.id.clone() else { continue };
            let reply = match method.as_str() {
                method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {}, "prompts": {}, "resources": {}, "completions": {} },
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
                method::PROMPTS_LIST => {
                    let prompts: Vec<Value> = serves
                        .prompts
                        .iter()
                        .map(|n| json!({ "name": n }))
                        .collect();
                    Message::result(id, json!({ "prompts": prompts }))
                }
                method::RESOURCES_TEMPLATES_LIST => {
                    let templates: Vec<Value> = serves
                        .templates
                        .iter()
                        .map(|t| json!({ "uriTemplate": t, "name": t }))
                        .collect();
                    Message::result(id, json!({ "resourceTemplates": templates }))
                }
                method::COMPLETION_COMPLETE => {
                    let what = params["ref"]["name"]
                        .as_str()
                        .or(params["ref"]["uri"].as_str())
                        .unwrap_or_default();
                    let value = serves
                        .suggests
                        .clone()
                        .unwrap_or_else(|| format!("{label}:{what}"));
                    Message::result(
                        id,
                        json!({ "completion": { "values": [value], "total": 1, "hasMore": false } }),
                    )
                }
                // Anything else would have to have been passed through.
                _ => Message::result(id, json!({ "passedThrough": label })),
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

    async fn send(&self, method: &str, params: Option<Value>) -> Option<Message> {
        self.gw
            .handle(Message::request(Id::Num(7), method, params))
            .await
            .unwrap()
    }

    async fn complete(&self, reference: Value) -> Message {
        self.complete_with(reference, Value::Null, None).await
    }

    /// A completion, with the arguments resolved so far, by an authenticated
    /// caller if one is given.
    async fn complete_with(
        &self,
        reference: Value,
        arguments: Value,
        principal: Option<&Principal>,
    ) -> Message {
        let msg = Message::request(
            Id::Num(7),
            method::COMPLETION_COMPLETE,
            Some(json!({
                "ref": reference,
                "argument": { "name": "x", "value": "" },
                "context": { "arguments": arguments },
            })),
        );
        self.gw
            .handle_authed(msg, principal)
            .await
            .unwrap()
            .unwrap()
    }

    /// What each upstream was sent beyond its opening: (upstream, method).
    fn routed(&self) -> Vec<(String, String)> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m, _)| !OPENING.contains(&m.as_str()))
            .map(|(label, m, _)| (label.clone(), m.clone()))
            .collect()
    }

    fn records(self) -> Vec<Record> {
        drop(self.gw);
        read_all(self.dir.path().join("audit.log")).unwrap()
    }
}

fn server(id: &str, extra: &str) -> String {
    format!("[[server]]\nid = \"{id}\"\ntransport = \"stdio\"\ncommand = [\"unused\"]\n{extra}\n")
}

fn error(resp: &Message) -> (i64, String) {
    let error = resp.error.as_ref().expect("an error");
    (
        error["code"].as_i64().unwrap(),
        error["message"].as_str().unwrap().to_string(),
    )
}

fn suggested(resp: &Message) -> String {
    resp.result.as_ref().expect("a result")["completion"]["values"][0]
        .as_str()
        .unwrap()
        .to_string()
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

/// A completion record: (server, decision, rule, tool, uri).
type Outcome = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn completions(records: &[Record]) -> Vec<Outcome> {
    records
        .iter()
        .filter(|r| r.method.as_deref() == Some(method::COMPLETION_COMPLETE))
        .map(|r| {
            (
                r.server.clone(),
                r.decision.clone(),
                r.rule.clone(),
                r.tool.clone(),
                r.uri.clone(),
            )
        })
        .collect()
}

fn prompt_outcome(server: &str, rule: Option<&str>, name: &str) -> Outcome {
    let decision = if rule.is_some() { "deny" } else { "allow" };
    (
        server.into(),
        decision.into(),
        rule.map(Into::into),
        Some(name.into()),
        None,
    )
}

fn template_outcome(server: &str, rule: Option<&str>, template: &str) -> Outcome {
    let decision = if rule.is_some() { "deny" } else { "allow" };
    (
        server.into(),
        decision.into(),
        rule.map(Into::into),
        None,
        Some(template.into()),
    )
}

/// The methods the gateway used to pass to the first server, and a few no
/// client should send it at all: each is refused, audited, and sent nowhere.
const REFUSED: [&str; 13] = [
    "logging/setLevel",
    "tasks/get",
    "tasks/list",
    "tasks/result",
    "tasks/cancel",
    "subscriptions/listen",
    "sampling/createMessage",
    "roots/list",
    "elicitation/create",
    method::RESOURCES_SUBSCRIBE,
    method::RESOURCES_UNSUBSCRIBE,
    "made/up",
    "",
];

#[tokio::test]
async fn a_method_mcpdef_does_not_serve_is_refused_audited_and_sent_nowhere() {
    let config = [
        server("a", r#"prompts = ["*"]"#),
        server("b", r#"resources = ["file:///**"]"#),
    ]
    .concat();
    let s = Setup::new(
        &config,
        vec![("a", Serves::default()), ("b", Serves::default())],
    )
    .await;

    for method in REFUSED {
        let resp = s
            .send(method, Some(json!({ "level": "debug" })))
            .await
            .expect("a reply");
        let (code, message) = error(&resp);
        assert_eq!(code, -32601, "{method}");
        assert!(
            message.starts_with(&format!("MCPdef denied: method '{method}' ")),
            "{message}"
        );
    }
    // A client's notifications are absorbed, as ever.
    for notification in [
        "notifications/cancelled",
        "notifications/roots/list_changed",
        "notifications/progress",
    ] {
        let absorbed =
            s.gw.handle(Message::notification(notification, Some(json!({}))))
                .await
                .unwrap();
        assert!(absorbed.is_none(), "{notification}");
    }
    // A caller's made-up method is kept, but not at any length.
    let long = "x/".repeat(500);
    assert_eq!(error(&s.send(&long, None).await.unwrap()).0, -32601);

    assert_eq!(
        s.routed(),
        Vec::<(String, String)>::new(),
        "something went upstream"
    );
    let refused: Vec<(Option<String>, String, Option<String>, String)> = s
        .records()
        .into_iter()
        .filter(|r| r.kind.is_none())
        .map(|r| (r.method, r.decision, r.rule, r.server))
        .collect();
    let mut expected: Vec<_> = REFUSED
        .iter()
        .map(|m| {
            (
                Some(m.to_string()),
                "deny".to_string(),
                Some("method-not-found".to_string()),
                "(unrouted)".to_string(),
            )
        })
        .collect();
    expected.push((
        Some(long[..128].to_string()),
        "deny".into(),
        Some("method-not-found".into()),
        "(unrouted)".into(),
    ));
    assert_eq!(refused, expected);
}

/// No method reaches the first server by default. The first server exposes
/// nothing but a tool; every other method the gateway serves goes to the
/// second, or to no server at all.
#[tokio::test]
async fn no_method_reaches_the_first_server_by_default() {
    let config = [
        server("first", ""),
        server(
            "second",
            r#"prompts = ["*"]
resources = ["file:///**"]
resource_templates = ["file:///{*}"]"#,
        ),
    ]
    .concat();
    let second = Serves {
        prompts: vec!["summarize"],
        templates: vec!["file:///{path}"],
        ..Serves::default()
    };
    let s = Setup::new(
        &config,
        vec![("first", Serves::default()), ("second", second)],
    )
    .await;

    for (method, params) in [
        (method::INITIALIZE, json!({})),
        (method::PING, json!({})),
        (method::SERVER_DISCOVER, json!({})),
        (method::TOOLS_LIST, json!({})),
        (method::PROMPTS_LIST, json!({})),
        (method::PROMPTS_GET, json!({ "name": "summarize" })),
        (method::RESOURCES_LIST, json!({})),
        (method::RESOURCES_TEMPLATES_LIST, json!({})),
        (method::RESOURCES_READ, json!({ "uri": "file:///x" })),
        (
            method::COMPLETION_COMPLETE,
            json!({ "ref": { "type": "ref/prompt", "name": "summarize" }, "argument": { "name": "a", "value": "" } }),
        ),
        (
            method::COMPLETION_COMPLETE,
            json!({ "ref": { "type": "ref/resource", "uri": "file:///{path}" }, "argument": { "name": "path", "value": "" } }),
        ),
        ("logging/setLevel", json!({ "level": "debug" })),
    ] {
        let resp = s.send(method, Some(params)).await.expect("a reply");
        assert!(resp.result.is_some() || resp.error.is_some(), "{method}");
    }
    let routed = s.routed();
    assert!(
        routed.iter().all(|(label, _)| label == "second"),
        "the first server was sent {routed:?}"
    );
    let methods: Vec<&str> = routed.iter().map(|(_, m)| m.as_str()).collect();
    assert_eq!(
        methods,
        [
            method::PROMPTS_LIST,
            method::PROMPTS_GET,
            method::RESOURCES_LIST,
            method::RESOURCES_TEMPLATES_LIST,
            method::RESOURCES_READ,
            method::COMPLETION_COMPLETE,
            method::COMPLETION_COMPLETE,
        ]
    );
}

#[tokio::test]
async fn a_prompts_completion_goes_to_its_server_and_is_judged_as_a_get() {
    let config = format!(
        "{}{}{}",
        server("a", r#"prompts = ["a_*"]"#),
        server("b", r#"prompts = ["release_*", "review_*"]"#),
        r#"
[[policy]]
name    = "no-prod-notes"
effect  = "deny"
prompts = ["release_*"]
args    = [ { path = "env", equals = "prod" } ]

[[role]]
name          = "reviewer"
prompt_grants = ["b:review_*"]
"#
    );
    let b = Serves {
        prompts: vec!["release_notes", "review_code"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", Serves::default()), ("b", b)]).await;
    let prompt = |name: &str| json!({ "type": "ref/prompt", "name": name });
    let reviewer = principal(&["reviewer"]);

    assert_eq!(
        suggested(&s.complete(prompt("review_code")).await),
        "b:review_code"
    );
    // One no allowlist takes.
    let (code, message) = error(&s.complete(prompt("secret_runbook")).await);
    assert_eq!(code, -32602);
    assert_eq!(
        message,
        "MCPdef denied: no server's prompt allowlist takes 'secret_runbook'"
    );
    // A rule on the prompt's arguments judges the ones resolved so far.
    let prod = s
        .complete_with(prompt("release_notes"), json!({ "env": "prod" }), None)
        .await;
    assert_eq!(
        error(&prod).1,
        "MCPdef denied: policy rule 'no-prod-notes' denied 'release_notes' on 'b'"
    );
    // RBAC, for an authenticated caller: a grant of the prompt.
    let granted = s
        .complete_with(prompt("review_code"), Value::Null, Some(&reviewer))
        .await;
    assert_eq!(suggested(&granted), "b:review_code");
    let not_granted = s
        .complete_with(prompt("release_notes"), Value::Null, Some(&reviewer))
        .await;
    assert_eq!(
        error(&not_granted).1,
        "MCPdef denied: no role grants prompt 'release_notes' on 'b'"
    );

    assert_eq!(
        s.routed(),
        [
            ("b".to_string(), method::COMPLETION_COMPLETE.to_string()),
            ("b".to_string(), method::COMPLETION_COMPLETE.to_string()),
        ]
    );
    assert_eq!(
        completions(&s.records()),
        [
            prompt_outcome("b", None, "review_code"),
            prompt_outcome("(unrouted)", Some("prompt-not-allowed"), "secret_runbook"),
            prompt_outcome("b", Some("no-prod-notes"), "release_notes"),
            prompt_outcome("b", None, "review_code"),
            prompt_outcome("b", Some("rbac"), "release_notes"),
        ]
    );
}

#[tokio::test]
async fn a_templates_completion_goes_to_the_server_that_shows_it() {
    let config = format!(
        "{}{}{}",
        server("a", r#"resource_templates = ["db://{*}"]"#),
        server("b", r#"resource_templates = ["file:///{*}"]"#),
        r#"
[[policy]]
name   = "no-bob"
effect = "deny"
agents = ["sub:bob"]

[[role]]
name            = "reader"
resource_grants = ["b:file:///srv/docs/**"]

[[role]]
name          = "writer"
prompt_grants = ["*"]
"#
    );
    let b = Serves {
        templates: vec!["file:///{path}"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", Serves::default()), ("b", b)]).await;
    let template = |uri: &str| json!({ "type": "ref/resource", "uri": uri });

    assert_eq!(
        suggested(&s.complete(template("file:///{path}")).await),
        "b:file:///{path}"
    );
    let (code, message) = error(&s.complete(template("https://h/{path}")).await);
    assert_eq!(code, -32602);
    assert_eq!(
        message,
        "MCPdef denied: no server's template allowlist takes 'https://h/{path}'"
    );
    // RBAC: a role that grants some resource on the server, and not a
    // role that grants prompts alone.
    let reader = s
        .complete_with(
            template("file:///{path}"),
            Value::Null,
            Some(&principal(&["reader"])),
        )
        .await;
    assert_eq!(suggested(&reader), "b:file:///{path}");
    let writer = s
        .complete_with(
            template("file:///{path}"),
            Value::Null,
            Some(&principal(&["writer"])),
        )
        .await;
    assert_eq!(
        error(&writer).1,
        "MCPdef denied: no role grants a resource on 'b' to complete 'file:///{path}'"
    );
    // A rule that names no kind judges a template's completion too.
    let bob = Principal {
        subject: "bob".into(),
        ..principal(&["reader"])
    };
    let denied = s
        .complete_with(template("file:///{path}"), Value::Null, Some(&bob))
        .await;
    assert_eq!(
        error(&denied).1,
        "MCPdef denied: policy rule 'no-bob' denied 'file:///{path}' on 'b'"
    );

    assert_eq!(
        completions(&s.records()),
        [
            template_outcome("b", None, "file:///{path}"),
            template_outcome(
                "(unrouted)",
                Some("template-not-allowed"),
                "https://h/{path}"
            ),
            template_outcome("b", None, "file:///{path}"),
            template_outcome("b", Some("rbac"), "file:///{path}"),
            template_outcome("b", Some("no-bob"), "file:///{path}"),
        ]
    );
}

#[tokio::test]
async fn completions_have_a_bucket_of_their_own_and_are_scanned() {
    let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let config = format!(
        "{}{}",
        server("a", r#"prompts = ["*"]"#),
        r#"
[gateway.rate_limit]
per_tool_per_sec = 0.001
per_tool_burst   = 1

[gateway.inspect]
mode = "enforce"
"#
    );
    let leaky = Serves {
        prompts: vec!["deploy"],
        suggests: Some(format!("aws_access_key_id={key}")),
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", leaky)]).await;
    let prompt = json!({ "type": "ref/prompt", "name": "deploy" });

    // A suggestion that leaks a secret is refused.
    let (code, message) = error(&s.complete(prompt.clone()).await);
    assert_eq!(code, -32602);
    assert!(message.starts_with("MCPdef blocked: "), "{message}");
    assert!(!message.contains(&key));
    // That spent the completions bucket; the next is refused before it goes.
    let (_, message) = error(&s.complete(prompt).await);
    assert_eq!(
        message,
        "MCPdef denied: completion rate limit exceeded for 'a' — retry shortly"
    );
    // The gets keep a bucket of their own.
    let get = s
        .send(method::PROMPTS_GET, Some(json!({ "name": "deploy" })))
        .await
        .unwrap();
    assert!(get.error.is_none(), "{get:?}");
}

#[tokio::test]
async fn a_completion_without_a_reference_is_invalid_and_goes_nowhere() {
    let config = server("a", r#"prompts = ["*"]"#);
    let s = Setup::new(&config, vec![("a", Serves::default())]).await;
    for params in [
        None,
        Some(json!({})),
        Some(json!({ "ref": { "type": "ref/prompt" } })),
        Some(json!({ "ref": { "type": "ref/tool", "name": "x" } })),
    ] {
        let resp = s
            .send(method::COMPLETION_COMPLETE, params.clone())
            .await
            .unwrap();
        let (code, message) = error(&resp);
        assert_eq!(code, -32602, "{params:?}");
        assert!(message.contains("needs `params.ref`"), "{message}");
    }
    assert!(s.routed().is_empty());
}

#[tokio::test]
async fn completions_are_offered_when_there_is_a_prompt_or_a_template() {
    for (extra, offered) in [
        ("", false),
        (r#"resources = ["file:///**"]"#, false),
        (r#"resource_templates = ["file:///{*}"]"#, true),
        (r#"prompts = ["*"]"#, true),
    ] {
        let s = Setup::new(&server("a", extra), vec![("a", Serves::default())]).await;
        let init = s.send(method::INITIALIZE, Some(json!({}))).await.unwrap();
        let capabilities = &init.result.unwrap()["capabilities"];
        assert_eq!(
            capabilities.get("completions").is_some(),
            offered,
            "{extra}: {capabilities}"
        );
    }
}

/// Two servers show one template pattern, and only the second has the
/// template. Unlisted, a completion goes to the first; once listed, to the
/// second.
#[tokio::test]
async fn a_template_only_the_second_server_lists_is_completed_there_once_listed() {
    let any = r#"resource_templates = ["file:///{*}"]"#;
    let config = [server("a", any), server("b", any)].concat();
    let b = Serves {
        templates: vec!["file:///{path}"],
        ..Serves::default()
    };
    let s = Setup::new(&config, vec![("a", Serves::default()), ("b", b)]).await;
    let template = json!({ "type": "ref/resource", "uri": "file:///{path}" });

    assert_eq!(
        suggested(&s.complete(template.clone()).await),
        "a:file:///{path}"
    );
    s.send(method::RESOURCES_TEMPLATES_LIST, None)
        .await
        .unwrap();
    assert_eq!(suggested(&s.complete(template).await), "b:file:///{path}");
}
