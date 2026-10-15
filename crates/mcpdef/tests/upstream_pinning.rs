// SPDX-License-Identifier: Apache-2.0
//! SPKI pins as a config gives them (`[server.tls] pin_sha256`), and
//! `mcpdef tls pin`, which prints one for a server.

use mcpdef::connect::build_gateway;
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{HttpsUpstream, Leaf, Pki};
use mcpdef_transport::Pin;
use serde_json::json;
use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");

/// A `[gateway]` table with its ledger in `dir`, then `rest`.
fn config(dir: &Path, rest: &str) -> String {
    let audit = dir.join("audit.log");
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n{rest}")
}

/// A `[[server]]` entry for a Streamable-HTTP upstream at `url`, then `rest`.
fn server(id: &str, url: &str, rest: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"streamable-http\"\nurl = {url:?}\n{rest}\n\n")
}

async fn start(text: &str) -> Gateway {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    build_gateway(&config).await.unwrap()
}

async fn echo(gw: &Gateway) -> String {
    let call = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": "echo", "arguments": {} })),
    );
    let reply = gw.handle(call).await.unwrap().expect("a reply");
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn health(gw: &Gateway, id: &str) -> (HealthState, String) {
    let status = gw
        .upstream_status()
        .into_iter()
        .find(|u| u.id == id)
        .expect("the upstream");
    let error = status.last_error.map(|e| e.message).unwrap_or_default();
    (status.health, error)
}

fn records(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Record>(l).ok())
        .collect()
}

/// `mcpdef` run with `args`, off the runtime, so that the upstreams the test
/// serves keep answering meanwhile.
async fn mcpdef(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || Command::new(BIN).args(&args).output().unwrap())
        .await
        .unwrap()
}

fn pinned(pin: impl std::fmt::Display) -> String {
    format!("[server.tls]\npin_sha256 = [\"{pin}\"]")
}

#[tokio::test]
async fn a_pinned_self_signed_upstream_is_served_and_a_wrong_pin_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;
    let pin = Pin::of(leaf.cert_der()).unwrap();

    let gw = start(&config(
        dir.path(),
        &server("appliance", &upstream.url(), &pinned(pin)),
    ))
    .await;
    assert_eq!(echo(&gw).await, "echo:{}");
    // A pin is verification: nothing is recorded as connected unverified.
    assert!(records(dir.path())
        .iter()
        .all(|r| r.rule.as_deref() != Some("tls-verify-disabled")));

    let other = tempfile::tempdir().unwrap();
    let stranger = Pin::of(Leaf::self_signed(&["127.0.0.1"]).cert_der()).unwrap();
    let gw = start(&config(
        other.path(),
        &server("appliance", &upstream.url(), &pinned(stranger)),
    ))
    .await;
    let (state, error) = health(&gw, "appliance");
    assert_eq!(state, HealthState::Down);
    assert!(
        error.contains(&format!(
            "no pin_sha256 matches the server's key, whose pin is \"{pin}\""
        )),
        "{error}"
    );
}

/// What `mcpdef tls pin` prints is TOML: pasted into the server's
/// `[server.tls]` as it is, the config validates, and the upstream is served.
#[tokio::test]
async fn the_output_of_mcpdef_tls_pin_pastes_into_a_config_that_works() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;

    let out = mcpdef(vec!["tls".into(), "pin".into(), upstream.url()]).await;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pin = Pin::of(leaf.cert_der()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.last().copied(),
        Some(format!("pin_sha256 = [\"{pin}\"]").as_str())
    );
    assert!(lines[..lines.len() - 1].iter().all(|l| l.starts_with("# ")));
    assert!(stdout.contains("presented a certificate for"), "{stdout}");
    assert!(stdout.contains("sha256 fingerprint"), "{stdout}");

    let table = format!("[server.tls]\n{stdout}");
    let gw = start(&config(
        dir.path(),
        &server("appliance", &upstream.url(), &table),
    ))
    .await;
    assert_eq!(echo(&gw).await, "echo:{}");
}

#[tokio::test]
async fn mcpdef_tls_pin_goes_through_the_egress_guard() {
    let out = mcpdef(vec![
        "tls".into(),
        "pin".into(),
        "https://169.254.169.254/".into(),
    ])
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("egress blocked") && stderr.contains("always blocked"),
        "{stderr}"
    );
    assert!(out.stdout.is_empty());

    // With --config, the config's own egress policy: here, no private
    // address, loopback included.
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let path = dir.path().join("mcpdef.toml");
    let text = config(
        dir.path(),
        "[gateway.egress]\nallow_private = false\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n",
    );
    std::fs::write(&path, text).unwrap();
    let out = mcpdef(vec![
        "tls".into(),
        "pin".into(),
        upstream.url(),
        "--config".into(),
        path.display().to_string(),
    ])
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("allow_private = false"), "{stderr}");
    // Without it, the defaults allow loopback.
    let out = mcpdef(vec!["tls".into(), "pin".into(), upstream.url()]).await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
