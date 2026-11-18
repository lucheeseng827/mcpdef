// SPDX-License-Identifier: Apache-2.0
//! Filter mode, `mcpdef filter`: the checks a proxy makes before it routes a
//! request itself, as Envoy's `ext_authz` filter sends them to an HTTP
//! service, answered over HTTP:
//!   * the request's path, less the proxy's `path_prefix`, names its server,
//!     by the longest `filter_path`, and a path that names none, or that a
//!     proxy could read otherwise, is refused;
//!   * a `tools/call`, a `resources/read` and a `prompts/get` meet the gates
//!     they would in the path: the allowlists, the policy rules, the
//!     transforms (refused when they would change the arguments), RBAC and
//!     the rate limit;
//!   * an allowed request gets a `200`, a refused one a `403` with a JSON-RPC
//!     error the proxy hands the client;
//!   * what is not judged (a list, a notification, a `GET`) passes;
//!   * a credential is checked as the listener checks it, and the resource's
//!     metadata, where a `401` sends a client, is served to anyone;
//!   * each decision is recorded, marked as `ext_authz`'s.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::connect::build_filter;
use mcpdef::filter::{router, Filter};
use mcpdef::listener::AuthState;
use mcpdef::Config;
use mcpdef_audit::{read_all, Record};
use mcpdef_auth::Verifier;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");

// The RSA key pair `mcpdef-auth` tests with: the private key to sign tokens,
// the public JWKS the verifier loads.
const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const ISSUER: &str = "https://auth.example.com";
/// The resource as clients reach it: through the proxy.
const RESOURCE: &str = "https://mcp.example.com/github/mcp";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `cfg`'s filter on a port of its own, taking credentials as `auth` says:
/// its base URL.
async fn serve(cfg: &Config, auth: Option<AuthState>) -> (String, Aborted) {
    mcpdef_transport::install_crypto_provider();
    let gw = build_filter(cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(Filter::new(gw, cfg, auth));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, Aborted(task))
}

/// What a check got.
#[derive(Debug)]
struct Answer {
    status: u16,
    decision: Option<String>,
    rule: Option<String>,
    record: Option<u64>,
    challenge: Option<String>,
    body: Option<Value>,
}

/// The check a proxy makes of a request `method path` with `body` and, when
/// there is one, the bearer token `token`.
async fn check(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> Answer {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut request = client.request(method.parse().unwrap(), format!("{base}{path}"));
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    let (decision, rule) = (header("x-mcpdef-decision"), header("x-mcpdef-rule"));
    let record = header("x-mcpdef-record").map(|seq| seq.parse().unwrap());
    let challenge = header("www-authenticate");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    Answer {
        status,
        decision,
        rule,
        record,
        challenge,
        body: serde_json::from_str(&text).ok(),
    }
}

/// A JSON-RPC request.
fn request(id: u64, method: &str, params: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

/// A `tools/call` of `tool` with `args`.
fn call(tool: &str, args: Value) -> String {
    request(1, "tools/call", json!({ "name": tool, "arguments": args }))
}

fn config(dir: &Path, extra: &str) -> Config {
    let text = format!(
        "[gateway]\naudit = {audit:?}\n\n\
         [gateway.rate_limit]\nper_tool_per_sec = 0.001\nper_tool_burst = 2\n\n\
         [[server]]\nid = \"github\"\ntransport = \"streamable-http\"\n\
         url = \"http://127.0.0.1:9/mcp\"\nfilter_path = \"/github\"\n\
         tools = [\"list_*\", \"get_*\", \"search_*\"]\n\n\
         [[server]]\nid = \"docs\"\ntransport = \"streamable-http\"\n\
         url = \"http://127.0.0.1:9/mcp\"\nfilter_path = \"/docs/\"\ntools = []\n\
         resources = [\"file:///srv/docs/**\"]\nprompts = [\"summarize\"]\n\n\
         [[policy]]\nname = \"no-prod\"\neffect = \"deny\"\ntools = [\"list_*\"]\n\
         args = [{{ path = \"repo\", equals = \"prod\" }}]\n\n\
         [[policy]]\nname = \"page-size\"\neffect = \"transform\"\ntools = [\"search_*\"]\n\
         set_args = [{{ path = \"per_page\", clamp = {{ min = 1, max = 100 }} }}]\n\n\
         {extra}",
        audit = dir.join("audit.log"),
    );
    let cfg = Config::parse(&text).unwrap();
    let errors = cfg.check(false).errors;
    assert!(errors.is_empty(), "{errors:?}");
    cfg
}

/// The ledger's records, in order.
fn records(dir: &Path) -> Vec<Record> {
    read_all(dir.join("audit.log")).unwrap()
}

#[tokio::test]
async fn a_request_is_judged_by_the_server_its_path_names() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let (base, _served) = serve(&cfg, None).await;

    // On its allowlist.
    let allowed = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    assert_eq!(allowed.decision.as_deref(), Some("allow"));
    assert_eq!(allowed.record, Some(0));

    // Off it: a 403 with a JSON-RPC error for the client, its id kept.
    let denied = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("delete_repo", json!({}))),
        &[],
    )
    .await;
    assert_eq!(denied.status, 403, "{denied:?}");
    assert_eq!(denied.decision.as_deref(), Some("deny"));
    let body = denied.body.unwrap();
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32001);
    let rule = denied.rule.unwrap();
    assert_eq!(body["error"]["data"]["rule"], rule.as_str());
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!("MCPdef denied ({rule}):")),
        "{body}"
    );
    assert_eq!(denied.record, Some(1));

    // The same tool, on a server whose allowlist names no tool.
    let elsewhere = check(
        &base,
        "POST",
        "/docs/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(elsewhere.status, 403, "{elsewhere:?}");

    let records = records(dir.path());
    assert_eq!(records.len(), 3);
    for record in &records {
        assert_eq!(record.hook.as_deref(), Some("ext_authz"));
        assert_eq!(record.method.as_deref(), Some("tools/call"));
        assert_eq!(record.agent, "agent:unknown");
        assert_eq!(record.peer, None, "the check's peer is the proxy");
    }
    assert_eq!(
        (
            records[0].server.as_str(),
            records[0].tool.as_deref(),
            records[0].decision.as_str()
        ),
        ("github", Some("list_issues"), "allow")
    );
    assert_eq!(
        (
            records[1].server.as_str(),
            records[1].tool.as_deref(),
            records[1].decision.as_str()
        ),
        ("github", Some("delete_repo"), "deny")
    );
    assert_eq!(
        (records[2].server.as_str(), records[2].decision.as_str()),
        ("docs", "deny")
    );
}

#[tokio::test]
async fn a_path_that_names_no_server_or_could_name_another_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let (base, _served) = serve(&cfg, None).await;

    // Under no filter_path: refused, and the call it would have been recorded.
    let nowhere = check(
        &base,
        "POST",
        "/gitlab/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(
        (nowhere.status, nowhere.rule.as_deref()),
        (403, Some("unknown-route"))
    );
    // By whole segments: `/githubx` is not under `/github`.
    let beside = check(
        &base,
        "POST",
        "/githubx/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(
        (beside.status, beside.rule.as_deref()),
        (403, Some("unknown-route"))
    );
    // Not even what would pass unjudged.
    let stream = check(&base, "GET", "/gitlab/mcp", None, &[]).await;
    assert_eq!(
        (stream.status, stream.rule.as_deref()),
        (403, Some("unknown-route"))
    );
    let unrouted = records(dir.path());
    assert_eq!(unrouted.len(), 2);
    assert!(unrouted
        .iter()
        .all(|r| r.server == "(unrouted)" && r.rule.as_deref() == Some("unknown-route")));

    // What a proxy could route to another server than the one it names, sent
    // as written: an HTTP client would resolve the dot segments itself.
    for path in [
        "/github/../docs/mcp",
        "/github%2f..%2fdocs",
        "/github//mcp",
        "/docs/%2e%2e/github",
    ] {
        let (status, rule) = raw_check(&base, path, &call("list_issues", json!({}))).await;
        assert_eq!(
            (status, rule.as_deref()),
            (403, Some("path-refused")),
            "{path}"
        );
    }
    assert_eq!(
        records(dir.path()).len(),
        2,
        "a refused path is not recorded"
    );
}

/// A check of `POST path` with `body`, the path sent as written: its status
/// and its rule.
async fn raw_check(base: &str, path: &str, body: &str) -> (u16, Option<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response.split(' ').nth(1).unwrap().parse().unwrap();
    let rule = response
        .lines()
        .find_map(|l| l.strip_prefix("x-mcpdef-rule: "))
        .map(str::to_string);
    (status, rule)
}

#[tokio::test]
async fn the_proxys_path_prefix_comes_off_first() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "[gateway.filter]\npath_prefix = \"/authz\"\n");
    let (base, _served) = serve(&cfg, None).await;
    let routed = check(
        &base,
        "POST",
        "/authz/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(routed.status, 200, "{routed:?}");
    let unprefixed = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(
        (unprefixed.status, unprefixed.rule.as_deref()),
        (403, Some("unknown-route"))
    );
}

#[tokio::test]
async fn a_call_meets_the_rules_the_transforms_and_the_rate_limit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let (base, _served) = serve(&cfg, None).await;

    // A deny rule over the arguments.
    let prod = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({ "repo": "prod" }))),
        &[],
    )
    .await;
    assert_eq!((prod.status, prod.rule.as_deref()), (403, Some("no-prod")));

    // A transform that would change the arguments: the filter cannot change
    // what the proxy sends, so the call is refused by the transform's name.
    let clamped = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("search_code", json!({ "per_page": 500 }))),
        &[],
    )
    .await;
    assert_eq!(
        (clamped.status, clamped.rule.as_deref()),
        (403, Some("page-size"))
    );
    let reason = clamped.body.unwrap()["error"]["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(reason.contains("put the gateway in the path"), "{reason}");
    // One it leaves as it is passes.
    let kept = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("search_code", json!({ "per_page": 50 }))),
        &[],
    )
    .await;
    assert_eq!(kept.status, 200, "{kept:?}");

    // The rate limit: two calls of a tool, then no more, while another tool
    // still has its own.
    for _ in 0..2 {
        let ok = check(
            &base,
            "POST",
            "/github/mcp",
            Some(&call("get_me", json!({}))),
            &[],
        )
        .await;
        assert_eq!(ok.status, 200, "{ok:?}");
    }
    let limited = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("get_me", json!({}))),
        &[],
    )
    .await;
    assert_eq!(
        (limited.status, limited.rule.as_deref()),
        (403, Some("rate-limited"))
    );

    let transforms: Vec<Vec<String>> = records(dir.path())
        .iter()
        .map(|r| r.transforms.clone().unwrap_or_default())
        .collect();
    assert_eq!(transforms[1], vec!["page-size".to_string()]);
    assert_eq!(transforms[2], vec!["page-size".to_string()]);
}

#[tokio::test]
async fn a_read_and_a_prompt_meet_their_allowlists() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let (base, _served) = serve(&cfg, None).await;
    let read = |uri: &str| request(2, "resources/read", json!({ "uri": uri }));

    let allowed = check(
        &base,
        "POST",
        "/docs/mcp",
        Some(&read("file:///srv/docs/a.md")),
        &[],
    )
    .await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    let outside = check(
        &base,
        "POST",
        "/docs/mcp",
        Some(&read("file:///etc/passwd")),
        &[],
    )
    .await;
    assert_eq!(outside.status, 403, "{outside:?}");
    // The server would read the URI as sent: one the gateway would judge in
    // another form is refused, since it cannot send the form it judged.
    let dotted = check(
        &base,
        "POST",
        "/docs/mcp",
        Some(&read("file:///srv/docs/../secrets/key")),
        &[],
    )
    .await;
    assert_eq!(
        (dotted.status, dotted.rule.as_deref()),
        (403, Some("uri-refused")),
        "{dotted:?}"
    );
    // A subscription delivers what a read would.
    let subscribe = request(
        3,
        "resources/subscribe",
        json!({ "uri": "file:///etc/passwd" }),
    );
    let subscribed = check(&base, "POST", "/docs/mcp", Some(&subscribe), &[]).await;
    assert_eq!(subscribed.status, 403, "{subscribed:?}");

    let prompt = |name: &str| request(4, "prompts/get", json!({ "name": name, "arguments": {} }));
    let summarize = check(&base, "POST", "/docs/mcp", Some(&prompt("summarize")), &[]).await;
    assert_eq!(summarize.status, 200, "{summarize:?}");
    let other = check(&base, "POST", "/docs/mcp", Some(&prompt("exfiltrate")), &[]).await;
    assert_eq!(other.status, 403, "{other:?}");

    let records = records(dir.path());
    let read_record = &records[0];
    assert_eq!(read_record.method.as_deref(), Some("resources/read"));
    assert_eq!(read_record.uri.as_deref(), Some("file:///srv/docs/a.md"));
    assert_eq!(records[3].method.as_deref(), Some("resources/subscribe"));
    assert_eq!(records[4].tool.as_deref(), Some("summarize"));
}

#[tokio::test]
async fn what_is_not_judged_passes_unrecorded() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "");
    let (base, _served) = serve(&cfg, None).await;
    let initialize = request(
        1,
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "c", "version": "1" } }),
    );
    let notification =
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
    let list = request(2, "tools/list", json!({}));
    for (method, body) in [
        ("POST", Some(initialize.as_str())),
        ("POST", Some(notification.as_str())),
        ("POST", Some(list.as_str())),
        ("GET", None),
        ("DELETE", None),
    ] {
        let answer = check(&base, method, "/github/mcp", body, &[]).await;
        assert_eq!(answer.status, 200, "{method} {body:?}: {answer:?}");
        assert_eq!(answer.record, None);
    }
    assert!(records(dir.path()).is_empty());

    // A POST with nothing to judge in it is refused: the proxy was not set to
    // send the body, or the body is not one message.
    let empty = check(&base, "POST", "/github/mcp", Some(""), &[]).await;
    assert_eq!(
        (empty.status, empty.rule.as_deref()),
        (403, Some("invalid-request"))
    );
    let batch = format!("[{}]", call("list_issues", json!({})));
    let batched = check(&base, "POST", "/github/mcp", Some(&batch), &[]).await;
    assert_eq!(
        (batched.status, batched.rule.as_deref()),
        (403, Some("invalid-request"))
    );
    let nameless = request(5, "tools/call", json!({ "arguments": {} }));
    let unnamed = check(&base, "POST", "/github/mcp", Some(&nameless), &[]).await;
    assert_eq!(
        (unnamed.status, unnamed.rule.as_deref()),
        (403, Some("invalid-request"))
    );

    // And a browser's cross-site origin, as the listener refuses it.
    let origin = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[("origin", "https://evil.example")],
    )
    .await;
    assert_eq!(
        (origin.status, origin.rule.as_deref()),
        (403, Some("origin-refused"))
    );
    assert!(records(dir.path()).is_empty());
}

/// `mcpdef keys create`: the key, and the `[[key]]` table it prints.
fn create(name: &str, role: &str) -> (String, String) {
    let out = Command::new(BIN)
        .args(["keys", "create", "--name", name, "--role", role])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let printed = String::from_utf8(out.stdout).unwrap();
    let mut lines = printed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let key = lines.next().unwrap().to_string();
    let table: Vec<&str> = lines.collect();
    (key, table.join("\n"))
}

#[tokio::test]
async fn a_credential_is_checked_and_its_roles_judged() {
    let dir = tempfile::tempdir().unwrap();
    let (reader, reader_key) = create("ci", "reader");
    let roles = format!(
        "[gateway.auth]\nenabled = true\nmethods = [\"key\"]\n\n\
         [[role]]\nname = \"reader\"\ngrants = [\"github:list_*\"]\n\n{reader_key}\n"
    );
    let cfg = config(dir.path(), &roles);
    let (base, _served) = serve(&cfg, Some(AuthState::keys())).await;
    let bearer = format!("Bearer {reader}");

    // No credential: the listener's 401, its challenge kept for the client.
    let anonymous = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[],
    )
    .await;
    assert_eq!(anonymous.status, 401, "{anonymous:?}");
    assert!(anonymous.challenge.unwrap().starts_with("Bearer"));
    // A key it did not issue.
    let forged = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[("authorization", "Bearer mcpdef_key_forged")],
    )
    .await;
    assert_eq!(forged.status, 401, "{forged:?}");
    assert!(
        records(dir.path()).is_empty(),
        "a refused credential is not a decision"
    );

    // A role that grants the tool.
    let granted = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("list_issues", json!({}))),
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(granted.status, 200, "{granted:?}");
    // One the allowlist takes and the role does not grant.
    let ungranted = check(
        &base,
        "POST",
        "/github/mcp",
        Some(&call("get_me", json!({}))),
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(ungranted.status, 403, "{ungranted:?}");

    let records = records(dir.path());
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.agent == "key:ci"));
    assert_eq!(records[0].decision, "allow");
    assert_eq!(records[1].decision, "deny");
    // No key shows in a record.
    let ledger = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(!ledger.contains(&reader));
}

/// A bearer token for `RESOURCE`, signed by the test key, with `roles`.
fn token(roles: &[&str]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "sub": "agent-7", "iss": ISSUER, "aud": RESOURCE,
        "iat": now, "exp": now + 3600, "roles": roles,
    });
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

#[tokio::test]
async fn a_tokens_challenge_sends_the_client_to_metadata_the_filter_serves() {
    let dir = tempfile::tempdir().unwrap();
    let jwks = dir.path().join("jwks.json");
    std::fs::write(&jwks, TEST_JWKS).unwrap();
    let auth = format!(
        "[gateway.filter]\npath_prefix = \"/authz\"\n\n\
         [gateway.auth]\nenabled = true\nissuer = {ISSUER:?}\nresource = {RESOURCE:?}\n\
         jwks = {jwks:?}\n\n\
         [[role]]\nname = \"reader\"\ngrants = [\"github:list_*\"]\n"
    );
    let cfg = config(dir.path(), &auth);
    let verifier = Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE).unwrap();
    let (base, _served) = serve(&cfg, Some(AuthState::new(verifier))).await;
    let body = call("list_issues", json!({}));

    // No token: the challenge names where the resource's metadata is, at the
    // resource's origin, the proxy's.
    let anonymous = check(&base, "POST", "/authz/github/mcp", Some(&body), &[]).await;
    assert_eq!(anonymous.status, 401, "{anonymous:?}");
    assert_eq!(
        anonymous.challenge.as_deref(),
        Some(
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", \
             error=\"invalid_token\""
        )
    );

    // That metadata, to anyone: as a check, and routed here by the proxy.
    let document = json!({
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    });
    for path in [
        "/authz/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource",
    ] {
        let metadata = check(&base, "GET", path, None, &[]).await;
        assert_eq!(metadata.status, 200, "{path}: {metadata:?}");
        assert_eq!(metadata.body, Some(document.clone()), "{path}");
    }
    // Only a GET of it: anything else under it is a request like another.
    let posted = check(
        &base,
        "POST",
        "/authz/.well-known/oauth-protected-resource",
        Some("{}"),
        &[],
    )
    .await;
    assert_eq!(posted.status, 401, "{posted:?}");
    let below = check(
        &base,
        "GET",
        "/authz/.well-known/oauth-protected-resource/x",
        None,
        &[],
    )
    .await;
    assert_eq!(below.status, 401, "{below:?}");

    // The token the client gets there: its roles judged.
    let bearer = format!("Bearer {}", token(&["reader"]));
    let granted = check(
        &base,
        "POST",
        "/authz/github/mcp",
        Some(&body),
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(granted.status, 200, "{granted:?}");
    assert_eq!(granted.record, Some(0));
    let records = records(dir.path());
    assert_eq!(records.len(), 1, "a refused credential is not a decision");
    assert_eq!(records[0].agent, "sub:agent-7");
}
