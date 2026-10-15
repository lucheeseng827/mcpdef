// SPDX-License-Identifier: Apache-2.0
//! TLS profiles as a config gives them: `[gateway.upstream_tls]` for every
//! HTTPS upstream, a server's `[server.tls]` over it, and what a reload does
//! when a file they name changes.

use mcpdef::connect::build_gateway;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{HttpsUpstream, Pki};
use serde_json::json;
use std::path::Path;

/// A `[gateway]` table with its ledger in `dir`, then `rest`.
fn config(dir: &Path, rest: &str) -> String {
    let audit = dir.join("audit.log");
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n{rest}")
}

/// A `[[server]]` entry for a Streamable-HTTP upstream at `url`, then `rest`.
fn server(id: &str, url: &str, rest: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"streamable-http\"\nurl = {url:?}\n{rest}\n\n")
}

/// A gateway started as `mcpdef run` starts one, from a config that passes
/// `validate()`.
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

/// Upstream `id`'s health, and why it last failed.
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

#[tokio::test]
async fn a_private_ca_upstream_is_served_with_its_ca_and_refused_without() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("corp CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let ca = pki.write_root(dir.path(), "corp-root");

    let with = server(
        "corp",
        &upstream.url(),
        &format!("[server.tls]\nca = [{ca:?}]"),
    );
    let gw = start(&config(dir.path(), &with)).await;
    assert_eq!(echo(&gw).await, "echo:{}");
    assert_eq!(health(&gw, "corp").0, HealthState::Up);

    // Without it, the upstream never opens: it is down, and says why.
    let bare = tempfile::tempdir().unwrap();
    let gw = start(&config(bare.path(), &server("corp", &upstream.url(), ""))).await;
    let (state, error) = health(&gw, "corp");
    assert_eq!(state, HealthState::Down);
    assert!(error.contains("UnknownIssuer"), "{error}");
}

/// `[gateway.upstream_tls]` is every HTTPS upstream's profile; a server's
/// table replaces the fields it sets, and keeps the rest.
#[tokio::test]
async fn a_server_table_goes_over_the_gateway_one_field_by_field() {
    let dir = tempfile::tempdir().unwrap();
    let corp = Pki::new("corp CA");
    let team = Pki::new("team CA");
    let clients = Pki::new("client CA");
    let corp_ca = corp.write_root(dir.path(), "corp");
    let team_ca = team.write_root(dir.path(), "team");
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "gateway");

    // On the corp CA, asking for a client certificate: the gateway's CA and
    // certificate, both inherited.
    let mtls = HttpsUpstream::start_mtls(&corp.server(&["127.0.0.1"]), &clients, &[]).await;
    // On the team CA: its own table names that CA.
    let team_upstream = HttpsUpstream::start(&team.server(&["127.0.0.1"])).await;
    // On the corp CA, but its table names the team CA alone: `ca` is
    // replaced, not added to.
    let replaced = HttpsUpstream::start(&corp.server(&["127.0.0.1"])).await;

    let gateway = format!(
        "[gateway.upstream_tls]\nca = [{corp_ca:?}]\nclient_cert = {cert:?}\nclient_key = {{ file = {key:?} }}\n\n"
    );
    let team_table = format!("[server.tls]\nca = [{team_ca:?}]");
    let servers = [
        server("mtls", &mtls.url(), ""),
        server("team", &team_upstream.url(), &team_table),
        server("replaced", &replaced.url(), &team_table),
    ]
    .concat();
    let gw = start(&config(dir.path(), &format!("{gateway}{servers}"))).await;

    assert_eq!(health(&gw, "mtls").0, HealthState::Up);
    let presented = mtls.client_certificates();
    assert!(!presented.is_empty());
    assert!(
        presented.iter().all(|c| c == leaf.cert_der()),
        "the gateway's own"
    );
    assert_eq!(health(&gw, "team").0, HealthState::Up);
    let (state, error) = health(&gw, "replaced");
    assert_eq!(state, HealthState::Down);
    assert!(error.contains("UnknownIssuer"), "{error}");
    assert!(replaced.methods().is_empty());
}

#[tokio::test]
async fn an_upstream_whose_certificate_a_crl_revokes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("corp CA");
    let revoked = pki.server(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&revoked).await;
    let ca = pki.write_root(dir.path(), "corp-root");
    let crl = pki.crl(&[&revoked]).write(dir.path(), "corp");

    let table = format!("[server.tls]\nca = [{ca:?}]\ncrl = [{crl:?}]");
    let gw = start(&config(
        dir.path(),
        &server("corp", &upstream.url(), &table),
    ))
    .await;
    let (state, error) = health(&gw, "corp");
    assert_eq!(state, HealthState::Down);
    assert!(error.contains("Revoked"), "{error}");
    assert!(upstream.methods().is_empty());
}

#[tokio::test]
async fn connect_to_reaches_a_name_dns_does_not_know_and_never_the_metadata_address() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("corp CA");
    let upstream = HttpsUpstream::start(&pki.server(&["mcp.corp.test"])).await;
    let ca = pki.write_root(dir.path(), "corp-root");
    let url = upstream.url_for("mcp.corp.test");

    let table = format!("[server.tls]\nca = [{ca:?}]\nconnect_to = \"127.0.0.1\"");
    let gw = start(&config(dir.path(), &server("corp", &url, &table))).await;
    assert_eq!(echo(&gw).await, "echo:{}");

    // The metadata address: `validate` refuses the config, and a gateway
    // started without validating it refuses to dial.
    let table = format!("[server.tls]\nca = [{ca:?}]\nconnect_to = \"169.254.169.254\"");
    let text = config(dir.path(), &server("corp", &url, &table));
    let config = Config::parse(&text).unwrap();
    let errors = config.validate();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with("server 'corp': [server.tls] connect_to 169.254.169.254:")
            && errors[0].contains("always blocked"),
        "{errors:?}"
    );
    let gw = build_gateway(&config).await.unwrap();
    let (state, error) = health(&gw, "corp");
    assert_eq!(state, HealthState::Down);
    assert!(
        error.contains("egress blocked") && error.contains("169.254.169.254"),
        "{error}"
    );
}

/// `insecure_skip_verify` connects to whatever answers. It is warned about,
/// and every connection opened with it is on the record, a reconnection too.
#[tokio::test]
async fn insecure_skip_verify_is_warned_about_and_every_connection_audited() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("nobody's CA");
    let upstream = HttpsUpstream::start(&pki.server(&["elsewhere.test"])).await;
    let path = dir.path().join("mcpdef.toml");
    let write = |max_inflight: u32| {
        let rest =
            format!("max_inflight = {max_inflight}\n[server.tls]\ninsecure_skip_verify = true");
        std::fs::write(
            &path,
            config(dir.path(), &server("lax", &upstream.url(), &rest)),
        )
        .unwrap();
    };
    write(4);
    let (config, text) = Config::load_text(&path).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    let warnings = config.warnings();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].starts_with("server 'lax': [server.tls] insecure_skip_verify = true"),
        "{warnings:?}"
    );
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    assert_eq!(echo(&gw).await, "echo:{}");

    // A reload that changes how it is reached opens a new connection.
    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);
    write(8);
    let Outcome::Applied(report) = reloader.reload(Trigger::Signal).await else {
        panic!("the reload applies")
    };
    assert_eq!(report.reconnected, ["lax"]);

    let unverified: Vec<Record> = records(dir.path())
        .into_iter()
        .filter(|r| r.kind.as_deref() == Some("upstream"))
        .collect();
    assert_eq!(unverified.len(), 2, "{unverified:?}");
    for r in &unverified {
        assert_eq!(r.server, "lax");
        assert_eq!(r.method.as_deref(), Some("connect"));
        assert_eq!(r.decision, "allow");
        assert_eq!(r.rule.as_deref(), Some("tls-verify-disabled"));
    }
    assert!(mcpdef_audit::verify(dir.path().join("audit.log"))
        .unwrap()
        .ok());
}

/// A certificate renewed in place, as cert-manager renews one: a reload sees
/// the file change and reconnects the upstream, which then gets the new one.
/// Nothing else changed, and nothing else reconnects.
#[tokio::test]
async fn a_client_certificate_renewed_in_place_reconnects_its_upstream_on_reload() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("corp CA");
    let clients = Pki::new("client CA");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &clients, &[]).await;
    let other = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let ca = pki.write_root(dir.path(), "corp-root");
    let first = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = first.write(dir.path(), "gateway");

    let path = dir.path().join("mcpdef.toml");
    let mtls = format!(
        "[server.tls]\nca = [{ca:?}]\nclient_cert = {cert:?}\nclient_key = {{ file = {key:?} }}"
    );
    let plain = format!("[server.tls]\nca = [{ca:?}]");
    let servers = [
        server("mtls", &upstream.url(), &mtls),
        server("other", &other.url(), &plain),
    ]
    .concat();
    std::fs::write(&path, config(dir.path(), &servers)).unwrap();
    let (config, text) = Config::load_text(&path).unwrap();
    assert!(config
        .referenced_files()
        .contains(&cert.to_str().unwrap().to_string()));
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);

    // Nothing changed: nothing reconnects.
    let Outcome::Applied(report) = reloader.reload(Trigger::Signal).await else {
        panic!("the reload applies")
    };
    assert!(report.reconnected.is_empty(), "{report:?}");

    let before = upstream.client_certificates();
    assert!(!before.is_empty());
    assert!(before.iter().all(|c| c == first.cert_der()));

    let renewed = clients.client("spiffe://example.org/mcpdef");
    renewed.write(dir.path(), "gateway");
    let Outcome::Applied(report) = reloader.reload(Trigger::Signal).await else {
        panic!("the reload applies")
    };
    assert_eq!(report.reconnected, ["mtls"]);
    let after = upstream.client_certificates();
    let since = &after[before.len()..];
    assert!(
        !since.is_empty(),
        "a new connection, with the new certificate"
    );
    assert!(since.iter().all(|c| c == renewed.cert_der()));
    assert_eq!(health(&gw, "mtls").0, HealthState::Up);
}
