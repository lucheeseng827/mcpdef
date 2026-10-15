// SPDX-License-Identifier: Apache-2.0
//! `[identity]`'s model of a caller, on the HTTP listener: the subject and
//! roles it reads from a bearer token decide what RBAC lets the caller call,
//! and name the caller in the ledger, as each identity provider writes them:
//!   * Keycloak: the subject as `preferred_username`, roles under
//!     `realm_access.roles`;
//!   * Entra: a string `scp`, and app roles;
//!   * Okta: a group, mapped to a role;
//!   * Google: the hosted domain, mapped to a role.
//!
//! And `mcpdef auth test` says the same of a token.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::listener::{serve_http_on, AuthState, HttpConfig};
use mcpdef::Gateway;
use mcpdef_audit::{read_all, Ledger};
use mcpdef_auth::{IdentityModel, RoleMapping, Verifier};
use mcpdef_core::wire::WireMode;
use mcpdef_policy::{Policy, Rbac, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const ISSUER: &str = "https://auth.example.com";
const RESOURCE: &str = "https://mcpdef.acme.internal/mcp";

/// A valid token with `claims` besides the ones every valid token has.
fn token(claims: Value) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut all = json!({ "sub": "opaque-7", "iss": ISSUER, "aud": RESOURCE, "exp": now + 3600 });
    for (name, value) in claims.as_object().unwrap() {
        all[name] = value.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &all, &key).unwrap()
}

/// A listener whose tokens are read by `model`, fronting the mock's `echo`,
/// which only the `reader` role may call.
async fn start(model: IdentityModel, dir: &Path) -> String {
    let mut policy = Policy::new();
    policy.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    let mut rbac = Rbac::new();
    rbac.insert_role("reader", vec![("mock".into(), "echo".into())]);
    let ledger = Ledger::open(dir.join("audit.log")).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:test").with_rbac(Some(rbac));
    let mock = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    gw.add_upstream("mock", Box::new(StdioChild::spawn(&[mock]).unwrap()))
        .await
        .unwrap();
    let verifier = Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE)
        .unwrap()
        .with_identity(model);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::default(),
    };
    tokio::spawn(serve_http_on(
        listener,
        gw,
        cfg,
        Some(AuthState::new(verifier)),
    ));
    format!("http://{addr}/mcp")
}

/// Whether a call to `echo` with `token` was taken.
async fn calls(url: &str, token: &str) -> bool {
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(url)
        .bearer_auth(token)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let answer: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    answer["result"]["isError"] == false
}

/// The agent and decision of each `tools/call` the ledger recorded.
fn calls_recorded(dir: &Path) -> Vec<(String, String)> {
    read_all(dir.join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_deref() == Some("tools/call"))
        .map(|r| (r.agent, r.decision))
        .collect()
}

fn mapping(claim: &str, value: &str, roles: &[&str]) -> RoleMapping {
    RoleMapping {
        claim: claim.into(),
        value: value.into(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_providers_token_names_its_caller_as_configured() {
    // Keycloak.
    let dir = tempfile::tempdir().unwrap();
    let keycloak = IdentityModel {
        subject_claim: "preferred_username".into(),
        roles_claims: vec!["realm_access.roles".into()],
        ..IdentityModel::default()
    };
    let url = start(keycloak, dir.path()).await;
    let reader =
        token(json!({ "preferred_username": "ann", "realm_access": { "roles": ["reader"] } }));
    let outsider = token(
        json!({ "preferred_username": "bo", "realm_access": { "roles": ["other"] }, "roles": ["reader"] }),
    );
    assert!(calls(&url, &reader).await);
    assert!(
        !calls(&url, &outsider).await,
        "a `roles` claim the model does not read grants nothing"
    );
    assert_eq!(
        calls_recorded(dir.path()),
        [
            ("sub:ann".into(), "allow".into()),
            ("sub:bo".into(), "deny".into())
        ]
    );

    // Entra: `scp` a string of scopes, roles as app roles.
    let dir = tempfile::tempdir().unwrap();
    let url = start(
        IdentityModel {
            subject_claim: "oid".into(),
            ..IdentityModel::default()
        },
        dir.path(),
    )
    .await;
    let app =
        token(json!({ "oid": "0000-aaaa", "scp": "User.Read Mail.Read", "roles": ["reader"] }));
    let scoped = token(json!({ "oid": "0000-bbbb", "scp": "reader openid" }));
    assert!(calls(&url, &app).await);
    assert!(
        calls(&url, &scoped).await,
        "a scope still counts as a role name"
    );
    assert_eq!(calls_recorded(dir.path())[0].0, "sub:0000-aaaa");

    // Okta: a group mapped to the role.
    let dir = tempfile::tempdir().unwrap();
    let okta = IdentityModel {
        roles_claims: vec![],
        role_map: vec![mapping("groups", "mcp-readers", &["reader"])],
        ..IdentityModel::default()
    };
    let url = start(okta, dir.path()).await;
    assert!(
        calls(
            &url,
            &token(json!({ "groups": ["Everyone", "mcp-readers"] }))
        )
        .await
    );
    assert!(!calls(&url, &token(json!({ "groups": ["Everyone"] }))).await);

    // Google: the hosted domain mapped to the role.
    let dir = tempfile::tempdir().unwrap();
    let google = IdentityModel {
        subject_claim: "email".into(),
        role_map: vec![mapping("hd", "example.com", &["reader"])],
        ..IdentityModel::default()
    };
    let url = start(google, dir.path()).await;
    assert!(
        calls(
            &url,
            &token(json!({ "email": "ann@example.com", "hd": "example.com" }))
        )
        .await
    );
    assert!(!calls(&url, &token(json!({ "email": "bo@gmail.com" }))).await);
    // A token without the subject's claim is refused at the door.
    let nameless = token(json!({ "hd": "example.com" }));
    mcpdef_transport::install_crypto_provider();
    let refused = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&url)
        .bearer_auth(nameless)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
}

#[test]
fn auth_test_says_whom_a_token_names_and_what_it_grants() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    std::fs::write(
        &config,
        format!(
            "[gateway]\nlisten = \"127.0.0.1:7878\"\n\n[gateway.auth]\nenabled = true\nissuer = {ISSUER:?}\n\
             resource = {RESOURCE:?}\njwks = {TEST_JWKS:?}\n\n\
             [identity]\nsubject_claim = \"email\"\nroles_claims = [\"realm_access.roles\"]\n\n\
             [[identity.role_map]]\nclaim = \"hd\"\nvalue = \"example.com\"\nroles = [\"writer\"]\n\n\
             [[role]]\nname = \"reader\"\ngrants = [\"github:list_*\", \"get_*\"]\n\n\
             [[role]]\nname = \"writer\"\ngrants = [\"files:write_*\"]\n\n\
             [[server]]\nid = \"github\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n\n\
             [[server]]\nid = \"files\"\ntransport = \"stdio\"\ncommand = [\"y\"]\n"
        ),
    )
    .unwrap();
    let run = |token: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_mcpdef"))
            .args(["auth", "test", "--config"])
            .arg(&config)
            .args(["--token", token])
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let named = token(json!({
        "email": "ann@example.com",
        "hd": "example.com",
        "realm_access": { "roles": ["reader"] },
        "scp": "mcp.read",
    }));
    let (ok, out, err) = run(&named);
    assert!(ok, "{out}{err}");
    for line in [
        "verified · issuer https://auth.example.com",
        "subject : ann@example.com",
        "roles   : reader, writer",
        "scopes  : mcp.read",
        "  github : list_* (reader), get_* (reader)",
        "  files : get_* (reader), write_* (writer)",
    ] {
        assert!(out.lines().any(|l| l == line), "{line:?} not in\n{out}");
    }
    let (ok, out, err) = run("not.a.token");
    assert!(!ok, "{out}");
    assert!(err.contains("not verified: malformed token"), "{err}");
}
