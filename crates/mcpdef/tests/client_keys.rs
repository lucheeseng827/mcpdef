// SPDX-License-Identifier: Apache-2.0
//! Client keys the gateway issues, on the MCP listener:
//!   * `mcpdef keys create` makes one, and the `[[key]]` that keeps its
//!     SHA-256 and roles;
//!   * a caller presenting it is `key:<name>`, and RBAC judges its roles;
//!   * a key the gateway did not issue, another kind of token where keys
//!     alone are taken, and no token are each refused `401`;
//!   * a reload takes a key away, and it opens nothing from then on;
//!   * no key shows in a record.

use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_http_on, AuthState, HttpConfig};
use mcpdef::reload::{channel, Outcome, Reloader, Snapshot};
use mcpdef::Config;
use mcpdef_audit::read_all;
use mcpdef_core::wire::WireMode;
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
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

fn config_text(dir: &Path, keys: &[&str]) -> String {
    format!(
        "[gateway]\nlisten = \"127.0.0.1:7878\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.auth]\nenabled = true\nmethods = [\"key\"]\n\n\
         [[role]]\nname = \"reader\"\ngrants = [\"mock:echo\"]\n\n\
         [[role]]\nname = \"other\"\ngrants = [\"mock:nothing\"]\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = [\"echo\"]\n\n\
         {}\n",
        keys.join("\n\n"),
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    )
}

/// What a `tools/call` of `echo` with `key` got: its HTTP status, and, when
/// it was answered, whether the call was taken.
async fn call(url: &str, key: Option<&str>) -> (u16, Option<bool>, Option<String>) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut request = client
        .post(url)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#);
    if let Some(key) = key {
        request = request.bearer_auth(key);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let text = response.text().await.unwrap();
    let taken = serde_json::from_str::<Value>(&text)
        .ok()
        .map(|answer| answer["result"]["isError"] == false);
    (status, taken, challenge)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_key_names_its_caller_until_a_reload_takes_it_away() {
    mcpdef_transport::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let (reader, reader_table) = create("ci-bot", "reader");
    let (other, other_table) = create("nightly", "other");
    assert!(reader.starts_with("mcpdef_key_"), "{reader}");
    assert!(
        reader_table.starts_with("[[key]]\nname = \"ci-bot\"\nsha256 = \""),
        "{reader_table}"
    );
    assert!(
        reader_table.ends_with("roles = [\"reader\"]"),
        "{reader_table}"
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(
        &path,
        config_text(dir.path(), &[&reader_table, &other_table]),
    )
    .unwrap();
    let (cfg, text) = Config::load_text(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    assert_eq!(cfg.warnings(), Vec::<String>::new());

    let gw = build_gateway(&cfg).await.unwrap();
    let (reloads, requests) = channel();
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    let reloader = Reloader::new(&path, None, gw.clone(), cfg, snapshot).with_requests(requests);
    let _reloading = Aborted(tokio::spawn(reloader.run(Duration::from_secs(3600))));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let http = HttpConfig {
        listen: listener.local_addr().unwrap().to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::default(),
    };
    let _serving = Aborted(tokio::spawn(async move {
        serve_http_on(listener, gw, http, Some(AuthState::keys()))
            .await
            .unwrap();
    }));

    // The reader's key: taken, as key:ci-bot. The other's: named, and its
    // role grants nothing here.
    assert_eq!(call(&url, Some(&reader)).await.1, Some(true));
    assert_eq!(call(&url, Some(&other)).await.1, Some(false));

    // A key not issued, a token of another kind, and none.
    let forged = format!("mcpdef_key_{}", "A".repeat(43));
    for refused in [
        Some(forged.as_str()),
        Some("eyJhbGciOiJSUzI1NiJ9.e30.c2ln"),
        None,
    ] {
        let (status, _, challenge) = call(&url, refused).await;
        assert_eq!(status, 401, "{refused:?}");
        assert_eq!(challenge.as_deref(), Some("Bearer"), "{refused:?}");
    }

    // A reload without the reader's key: it opens nothing from then on.
    std::fs::write(&path, config_text(dir.path(), &[&other_table])).unwrap();
    let outcome = reloads.reload("test".into(), None).await.unwrap();
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    assert_eq!(call(&url, Some(&reader)).await.0, 401);
    assert_eq!(call(&url, Some(&other)).await.1, Some(false));

    let calls: Vec<(String, String)> = read_all(dir.path().join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_deref() == Some("tools/call"))
        .map(|r| (r.agent, r.decision))
        .collect();
    assert_eq!(
        calls,
        [
            ("key:ci-bot".to_string(), "allow".to_string()),
            ("key:nightly".to_string(), "deny".to_string()),
            ("key:nightly".to_string(), "deny".to_string()),
        ]
    );
    let ledger = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    for key in [&reader, &other] {
        assert!(!ledger.contains(key.as_str()), "a key in the ledger");
    }
}

#[test]
fn keys_create_refuses_a_name_a_record_could_not_carry() {
    for name in ["", "two words", "a:b", "ü"] {
        let out = Command::new(BIN)
            .args(["keys", "create", "--name", name, "--role", "reader"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{name:?}");
    }
    let out = Command::new(BIN)
        .args(["keys", "create", "--name", "ci-bot"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a key with no role");
}

#[test]
fn auth_test_says_whom_a_key_names_and_what_it_grants() {
    let dir = tempfile::tempdir().unwrap();
    let (reader, reader_table) = create("ci-bot", "reader");
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config_text(dir.path(), &[&reader_table])).unwrap();
    let test = |token: &str| {
        let out = Command::new(BIN)
            .args(["auth", "test", "--config"])
            .arg(&path)
            .args(["--token", token])
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (ok, said) = test(&reader);
    assert!(ok, "{said}");
    for line in [
        "verified · a client key this gateway issued",
        "caller  : key:ci-bot",
        "roles   : reader",
        "  mock : echo (reader)",
    ] {
        assert!(said.lines().any(|l| l == line), "{line:?} not in\n{said}");
    }
    assert!(!said.contains(&reader), "the key is not printed back");
    let (ok, said) = test(&format!("mcpdef_key_{}", "B".repeat(43)));
    assert!(!ok, "{said}");
    assert!(
        said.contains("no [[key]] of this config is that key"),
        "{said}"
    );
}
