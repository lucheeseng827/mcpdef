// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the inspection subcommands wired in Phase 1.5:
//! `mcpdef servers list`, `mcpdef audit verify`, and `mcpdef audit tail`. They drive
//! the real binary (`CARGO_BIN_EXE_mcpdef`) against a ledger built through the
//! `mcpdef-audit` API, so they exercise the same code path an operator does.

use mcpdef_audit::{Entry, Ledger};
use mcpdef_core::Decision;
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");

fn entry(server: &str, tool: &str, decision: Decision) -> Entry {
    Entry {
        agent: "agent:test".into(),
        server: server.into(),
        method: Some("tools/call".into()),
        tool: Some(tool.into()),
        decision,
        latency_ms: 2,
    }
}

/// Write a 3-record ledger and return its path inside `dir`.
fn seed_ledger(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("audit.log");
    let mut led = Ledger::open(&path).unwrap();
    led.append(entry("github", "list_issues", Decision::Allow))
        .unwrap();
    led.append(entry(
        "github",
        "delete_repo",
        Decision::Deny {
            rule: "deny-glob".into(),
            reason: "blocked".into(),
        },
    ))
    .unwrap();
    led.append(entry("files", "read_file", Decision::Allow))
        .unwrap();
    path
}

#[test]
fn audit_verify_reports_ok_on_an_intact_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed_ledger(dir.path());

    let out = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify should exit 0 on an intact chain"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("chain OK"), "got: {stdout}");
    assert!(stdout.contains("3 record(s)"), "got: {stdout}");
}

#[test]
fn audit_verify_fails_on_a_tampered_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed_ledger(dir.path());

    // Rewrite record 1's tool so its stored hash no longer matches.
    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    lines[1] = lines[1].replace("delete_repo", "exfiltrate_secrets");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let out = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify must exit non-zero on tampering"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("BROKEN"), "got: {stderr}");
}

#[test]
fn audit_verify_against_seal_catches_tail_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed_ledger(dir.path());
    let sealed_head = {
        let led = Ledger::open(&path).unwrap();
        led.head().to_string()
    };

    // Drop the last record: the remaining chain is internally valid…
    let content = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = content.lines().take(2).collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();

    // …so a plain verify passes…
    let plain = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(plain.status.success());

    // …but verify against the sealed (head, count) catches the truncation.
    let sealed = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&path)
        .args(["--head", &sealed_head, "--count", "3"])
        .output()
        .unwrap();
    assert!(
        !sealed.status.success(),
        "seal check must fail on truncation"
    );
}

#[test]
fn audit_tail_renders_each_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed_ledger(dir.path());

    // OCSF: the last record (a deny is record 1; last is the allow on files).
    let ocsf = Command::new(BIN)
        .args(["audit", "tail", "-n", "1", "--format", "ocsf", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(ocsf.status.success());
    let line = String::from_utf8_lossy(&ocsf.stdout);
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(v["class_uid"], 6003);

    // CEF for all 3 records: 3 lines, each a CEF header.
    let cef = Command::new(BIN)
        .args(["audit", "tail", "-n", "10", "--format", "cef", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    let cef_out = String::from_utf8_lossy(&cef.stdout);
    let lines: Vec<&str> = cef_out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|l| l.starts_with("CEF:0|mcpdef|mcpdef|")));
    assert!(cef_out.contains("act=deny"));

    // An unknown format is a clean error, not a panic.
    let bad = Command::new(BIN)
        .args(["audit", "tail", "--format", "csv", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

#[test]
fn audit_verify_missing_ledger_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(dir.path().join("nope.log"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not exist"), "got: {stderr}");
}

#[test]
fn servers_list_shows_governed_servers() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        r#"
        [gateway]
        audit = "./audit.log"

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        tools = ["list_issues"]
        deny = ["delete_*"]

        [[server]]
        id = "files"
        transport = "stdio"
        command = ["mcp-fs"]
        "#,
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["servers", "list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("github"));
    assert!(stdout.contains("list_issues"));
    assert!(stdout.contains("delete_*"));
    assert!(stdout.contains("(all)")); // files has no allowlist
    assert!(stdout.contains("2 server(s) governed"));
}

#[test]
fn servers_list_resolves_profiles_and_active() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        r#"
        [gateway]
        profile = "readonly"

        [profile.readonly]
        tools = ["get_*", "list_*"]
        deny  = ["*_secret"]

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        profile = "readonly"
        deny = ["delete_*"]
        "#,
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["servers", "list", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The listing shows the *resolved* allowlist (from the profile) and the
    // unioned deny set, plus the active-profile note.
    assert!(stdout.contains("readonly"));
    assert!(stdout.contains("get_*"));
    assert!(stdout.contains("delete_*")); // server deny appended
    assert!(stdout.contains("*_secret")); // profile deny inherited
    assert!(stdout.contains("active gateway profile: readonly"));
}

#[test]
fn pin_then_diff_tools_detects_drift() {
    let dir = tempfile::tempdir().unwrap();
    let pins = dir.path().join("pins.toml");
    let cfg = dir.path().join("mcpdef.toml");
    let mock = env!("CARGO_BIN_EXE_mock_mcp_server");
    std::fs::write(
        &cfg,
        format!(
            r#"
            [gateway]
            audit = "{audit}"
            pins  = "{pins}"

            [[server]]
            id = "mock"
            transport = "stdio"
            command = ["{mock}"]
            "#,
            audit = dir.path().join("audit.log").display(),
            pins = pins.display(),
            mock = mock,
        ),
    )
    .unwrap();

    // `mcpdef pin` records the mock's tools and writes the store.
    let pin = Command::new(BIN)
        .args(["pin", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        pin.status.success(),
        "{}",
        String::from_utf8_lossy(&pin.stderr)
    );
    assert!(pins.exists(), "pin store should be written");

    // `diff-tools` now matches the live server → exit 0.
    let ok = Command::new(BIN)
        .args(["diff-tools", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(ok.status.success());
    assert!(String::from_utf8_lossy(&ok.stdout).contains("ok"));

    // Corrupt the pinned hash for one tool → diff-tools must flag a rug-pull.
    let mut store = mcpdef_pin::PinStore::load(&pins).unwrap();
    store.record("mock", "echo", "0000_wrong");
    store.save(&pins).unwrap();

    let drifted = Command::new(BIN)
        .args(["diff-tools", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        !drifted.status.success(),
        "diff-tools must fail on a changed pin"
    );
    assert!(String::from_utf8_lossy(&drifted.stdout).contains("CHANGED"));
}

/// Write a config fronting the stdio mock server, allowlisting only `echo`.
fn mock_cfg(dir: &Path) -> std::path::PathBuf {
    let cfg = dir.join("mcpdef.toml");
    let mock = env!("CARGO_BIN_EXE_mock_mcp_server");
    std::fs::write(
        &cfg,
        format!(
            r#"
            [gateway]
            audit = "{audit}"

            [[server]]
            id = "mock"
            transport = "stdio"
            command = ["{mock}"]
            tools = ["echo"]
            "#,
            audit = dir.join("audit.log").display(),
            mock = mock,
        ),
    )
    .unwrap();
    cfg
}

#[test]
fn call_invokes_a_tool_through_the_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = mock_cfg(dir.path());

    let out = Command::new(BIN)
        .args(["call", "echo", "--args", r#"{"msg":"hi"}"#, "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "call should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The mock echoes "<tool>: <arguments>".
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("echo:"), "got: {stdout}");
    assert!(stdout.contains("hi"), "got: {stdout}");
}

#[test]
fn call_json_emits_the_raw_result() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = mock_cfg(dir.path());

    let out = Command::new(BIN)
        .args(["call", "echo", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["isError"], false);
    assert!(v["content"][0]["text"].as_str().unwrap().contains("echo:"));
}

#[test]
fn call_denied_tool_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = mock_cfg(dir.path());

    // `delete_repo` exists on the mock but is not in the allowlist → denied.
    let out = Command::new(BIN)
        .args(["call", "delete_repo", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a denied tool call must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "got: {stderr}");
}

#[test]
fn call_rejects_non_object_args() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = mock_cfg(dir.path());

    let out = Command::new(BIN)
        .args(["call", "echo", "--args", "[1,2,3]", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("JSON object"), "got: {stderr}");
}

#[test]
fn validate_rejects_unknown_profile() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        r#"
        [gateway]
        [[server]]
        id = "x"
        transport = "stdio"
        command = ["true"]
        profile = "ghost"
        "#,
    )
    .unwrap();

    let out = Command::new(BIN)
        .args(["validate", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown profile 'ghost'"), "got: {stderr}");
}
