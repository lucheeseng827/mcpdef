// SPDX-License-Identifier: Apache-2.0
//! A secret a config names by where it is: a client key read from MCPdef's
//! own environment, presented to the upstream that asks for it, and kept from
//! the stdio upstreams MCPdef starts; and one a command writes, which takes
//! its time off the async runtime.

use mcpdef::connect::build_gateway;
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{HttpsUpstream, Pki};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

async fn call(gw: &Gateway, tool: &str, arguments: serde_json::Value) -> String {
    let call = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": arguments })),
    );
    let reply = gw.handle(call).await.unwrap().expect("a reply");
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The one test here that sets variables of the process's own environment.
#[tokio::test]
async fn a_client_key_from_the_environment_is_presented_and_kept_from_stdio_upstreams() {
    let dir = tempfile::tempdir().unwrap();
    let servers = Pki::new("server CA");
    let clients = Pki::new("client CA");
    let upstream = HttpsUpstream::start_mtls(&servers.server(&["127.0.0.1"]), &clients, &[]).await;
    let ca = servers.write_root(dir.path(), "ca");
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, _) = leaf.write(dir.path(), "gateway");
    std::env::set_var("MCPDEF_TEST_GATEWAY_KEY", leaf.key_pem());
    std::env::set_var("MCPDEF_TEST_UNRELATED", "inherited");

    let audit = dir.path().join("audit.log");
    let url = upstream.url();
    let mock = env!("CARGO_BIN_EXE_mock_mcp_server");
    let text = format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n\
         [[server]]\nid = \"mtls\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         tools = [\"echo\"]\n\
         [server.tls]\nca = [{ca:?}]\nclient_cert = {cert:?}\n\
         client_key = {{ env = \"MCPDEF_TEST_GATEWAY_KEY\" }}\n\n\
         [[server]]\nid = \"local\"\ntransport = \"stdio\"\n\
         command = [{mock:?}, \"--with-env\", \"--tool-prefix\", \"local_\"]\n\
         [server.env]\nINJECTED = \"set\"\n"
    );
    let config = Config::parse(&text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    assert_eq!(config.secret_vars(), ["MCPDEF_TEST_GATEWAY_KEY"]);
    let gw = build_gateway(&config).await.unwrap();

    // The key went to the upstream that asked for it.
    assert_eq!(call(&gw, "echo", json!({})).await, "echo:{}");
    let presented = upstream.client_certificates();
    assert!(!presented.is_empty());
    assert!(presented.iter().all(|c| c == leaf.cert_der()));
    let status = gw.upstream_status();
    assert!(
        status.iter().all(|u| u.health == HealthState::Up),
        "{status:?}"
    );

    // And not to the stdio upstream, which inherits the rest.
    let seen = |name: &str| call(&gw, "local_env", json!({ "name": name }));
    assert_eq!(seen("MCPDEF_TEST_GATEWAY_KEY").await, "(unset)");
    assert_eq!(seen("MCPDEF_TEST_UNRELATED").await, "inherited");
    assert_eq!(seen("INJECTED").await, "set");
}

/// A client key a command writes is read off the async workers: while the
/// command takes its time, the gateway's other tasks go on, though its runtime
/// has one thread.
#[tokio::test(flavor = "current_thread")]
async fn a_client_key_a_command_writes_leaves_the_runtime_free() {
    let dir = tempfile::tempdir().unwrap();
    let servers = Pki::new("server CA");
    let clients = Pki::new("client CA");
    let upstream = HttpsUpstream::start_mtls(&servers.server(&["127.0.0.1"]), &clients, &[]).await;
    let ca = servers.write_root(dir.path(), "ca");
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "gateway");
    let audit = dir.path().join("audit.log");
    let url = upstream.url();
    let script = format!("sleep 0.5; cat '{}'", key.display());
    let text = format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n\
         [[server]]\nid = \"mtls\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         [server.tls]\nca = [{ca:?}]\nclient_cert = {cert:?}\n\
         client_key = {{ exec = [\"sh\", \"-c\", {script:?}] }}\n"
    );
    let config = Config::parse(&text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());

    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let gw = build_gateway(&config).await.unwrap();
    ticker.abort();
    let ticks = ticks.load(Ordering::Relaxed);
    assert!(ticks >= 20, "{ticks} ticks while the gateway started");
    assert_eq!(call(&gw, "echo", json!({})).await, "echo:{}");
    assert!(upstream
        .client_certificates()
        .iter()
        .all(|c| c == leaf.cert_der()));
}
