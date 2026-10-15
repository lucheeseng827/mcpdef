// SPDX-License-Identifier: Apache-2.0
//! `Reloader::run` listens for `SIGHUP` from the moment it is called, not from
//! when its loop first runs. `mcpdef run` calls it before printing its ready
//! line, so a `SIGHUP` sent as soon as the gateway says it is ready reloads it,
//! where it would otherwise end the process.
//!
//! A test binary of its own, because it sends `SIGHUP` to its own process.
#![cfg(unix)]

use mcpdef::connect::build_gateway;
use mcpdef::reload::{Reloader, Snapshot};
use mcpdef::Config;
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

fn serving(dir: &std::path::Path, ids: &[&str]) -> String {
    let audit = dir.join("audit.log");
    let servers: String = ids
        .iter()
        .map(|id| {
            format!(
                "[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \
                 \"--tool-prefix\", \"{id}_\"]\ntools = [\"{id}_echo\"]\n\n"
            )
        })
        .collect();
    format!("[gateway]\naudit = {audit:?}\n\n{servers}")
}

#[tokio::test]
async fn a_sighup_that_comes_before_the_loop_first_runs_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, serving(dir.path(), &["a"])).unwrap();
    let (config, text) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let reloads =
        Reloader::new(&path, None, gw.clone(), config, snapshot).run(Duration::from_secs(3600));

    std::fs::write(&path, serving(dir.path(), &["a", "b"])).unwrap();
    let pid = std::process::id().to_string();
    let hup = std::process::Command::new("kill")
        .args(["-HUP", &pid])
        .status()
        .unwrap();
    assert!(hup.success());
    // Delivered, and still here.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let running = tokio::spawn(reloads);
    let ids = || -> Vec<String> { gw.upstream_status().into_iter().map(|u| u.id).collect() };
    let until = Instant::now() + Duration::from_secs(10);
    while ids() != ["a", "b"] {
        assert!(Instant::now() < until, "not reloaded: {:?}", ids());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    running.abort();
}
