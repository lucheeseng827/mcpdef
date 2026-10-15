// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the inspection subcommands wired in Phase 1.5:
//! `mcpdef servers list`, `mcpdef audit verify`, and `mcpdef audit tail`. They drive
//! the real binary (`CARGO_BIN_EXE_mcpdef`) against a ledger built through the
//! `mcpdef-audit` API, so they exercise the same code path an operator does.

use mcpdef_audit::{Attrs, Entry, Ledger};
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
        attrs: Attrs::default(),
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

/// A 0.2.1 ledger whose seq 6 denied a tool name carrying U+001F: the chain is
/// intact, and the record whose field boundaries its hash cannot pin is named.
#[test]
fn audit_verify_warns_about_a_record_holding_the_separator() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mcpdef-audit/tests/fixtures/ledger-0.2.1.jsonl");
    let out = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(out.status.success(), "the chain itself is intact");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("chain OK · 8 record(s)"), "got: {stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 record(s) hold U+001F inside a field (seq [6])"),
        "got: {stderr}"
    );
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

/// `servers list` says where each variable a server is given comes from, and
/// never what it holds: not a value written in the config, and not a command's
/// arguments.
#[test]
fn servers_list_shows_where_env_comes_from_never_a_value() {
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

        [server.env]
        GITHUB_TOKEN = "s3cret-literal"
        FROM_ENV = { env = "GH_TOKEN" }
        FROM_FILE = { file = "/run/secrets/gh" }
        FROM_EXEC = { exec = ["op", "read", "op://infra/gh/s3cret-field"] }
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
    assert!(
        stdout.contains(
            "env FROM_ENV=$GH_TOKEN FROM_EXEC=(exec op) FROM_FILE=/run/secrets/gh \
             GITHUB_TOKEN=(literal)"
        ),
        "{stdout}"
    );
    let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("s3cret"), "{all}");
}

/// `servers list` says how a server proves itself, and where its secret comes
/// from, never the secret or the user name that goes with it.
#[test]
fn servers_list_shows_auth_by_kind_and_source_never_the_secret() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        r#"
        [gateway]
        audit = "./audit.log"

        [[server]]
        id = "remote"
        transport = "streamable-http"
        url = "https://mcp.example.com/mcp"

        [server.auth]
        kind = "basic"
        username = "s3cret-user"
        password = "s3cret-password"

        [[server]]
        id = "keyed"
        transport = "streamable-http"
        url = "https://api.example.com/mcp"

        [server.auth]
        kind = "header"
        name = "X-Api-Key"
        value = { env = "API_KEY" }
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
    assert!(stdout.contains("auth basic password=(literal)"), "{stdout}");
    assert!(
        stdout.contains("auth header X-Api-Key value=$API_KEY"),
        "{stdout}"
    );
    let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("s3cret"), "{all}");
}

#[test]
fn servers_list_shows_where_oauth2_tokens_and_their_secret_come_from() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        r#"
        [gateway]
        audit = "./audit.log"

        [[server]]
        id = "remote"
        transport = "streamable-http"
        url = "https://mcp.example.com/mcp"

        [server.auth]
        kind = "oauth2"
        token_url = "https://idp.example.com/oauth2/token"
        client_id = "s3cret-id"
        client_secret = "s3cret-literal"
        scopes = ["mcp:tools"]
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
    assert!(
        stdout.contains("auth oauth2 https://idp.example.com/oauth2/token client_secret=(literal)"),
        "{stdout}"
    );
    let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!all.contains("s3cret"), "{all}");
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

#[test]
fn validate_warns_about_insecure_skip_verify_and_refuses_a_bad_tls_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    let validate = |table: &str| {
        let text = format!(
            "[gateway]\n[[server]]\nid = \"lax\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcp.test/mcp\"\n[server.tls]\n{table}\n"
        );
        std::fs::write(&cfg, text).unwrap();
        Command::new(BIN)
            .args(["validate", "--config"])
            .arg(&cfg)
            .output()
            .unwrap()
    };

    let out = validate("insecure_skip_verify = true");
    assert!(out.status.success(), "a warning, not an error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("⚠ server 'lax': [server.tls] insecure_skip_verify = true"),
        "got: {stderr}"
    );

    let p12 = dir.path().join("client.p12");
    std::fs::write(&p12, [0x30, 0x82, 0x04, 0x00, 0x02, 0x01, 0x03]).unwrap();
    let key = dir.path().join("client.key");
    let out = validate(&format!(
        "client_cert = {p12:?}\nclient_key = {{ file = {key:?} }}"
    ));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("✗ server 'lax': [server.tls] client_cert")
            && stderr.contains("is PKCS#12"),
        "got: {stderr}"
    );
}

/// `mcpdef validate` on `cfg`, with `--strict` when `strict`.
fn validate(cfg: &Path, strict: bool) -> std::process::Output {
    let mut command = Command::new(BIN);
    command.args(["validate", "--config"]).arg(cfg);
    if strict {
        command.arg("--strict");
    }
    command.output().unwrap()
}

/// The example config, where the docs send a new user to start, is valid,
/// and holds nothing strict mode refuses: no secret written in it.
#[test]
fn the_example_config_passes_strictly() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../mcpdef.example.toml");
    let out = validate(&example, true);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains("config valid, strictly"), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// Each finding, one at a time: `validate` warns about it and passes the
/// config, and `--strict`, or `[gateway] strict = true`, refuses it. No secret
/// is repeated either way.
#[cfg(unix)]
#[test]
fn strict_refuses_each_finding_that_validate_only_warns_about() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let readable = dir.path().join("token");
    std::fs::write(&readable, "t").unwrap();
    std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o644)).unwrap();
    let leaf = mcpdef_testkit::Pki::new("mcpdef test CA").client("spiffe://mcpdef.test/gw");
    let cert = dir.path().join("client.crt");
    std::fs::write(&cert, leaf.cert_pem()).unwrap();
    let token = format!("ghp_{}", "a1B2".repeat(9));
    let stdio = "transport = \"stdio\"\ncommand = [\"srv\"]";
    let https = "transport = \"streamable-http\"\nurl = \"https://mcp.example.com/mcp\"";
    let oauth2 = "kind = \"oauth2\"\nclient_id = \"mcpdef\"";
    let cases = [
        // A secret written in the config.
        (
            format!("{stdio}\n[server.env]\nGITHUB_TOKEN = \"hunter2\""),
            "server 's': [server.env] GITHUB_TOKEN is a secret written in the config".to_string(),
        ),
        (
            format!("{stdio}\n[server.env]\nNOTE = \"{token}\""),
            "server 's': [server.env] NOTE is a secret written in the config".to_string(),
        ),
        (
            format!(
                "{https}\n[server.tls]\nclient_cert = {cert:?}\nclient_key = \"\"\"\n{}\"\"\"",
                leaf.key_pem()
            ),
            "server 's': [server.tls] client_key is a secret written in the config".to_string(),
        ),
        (
            format!("{https}\n[server.auth]\nkind = \"bearer\"\ntoken = \"hunter2\""),
            "server 's': [server.auth] token is a secret written in the config".to_string(),
        ),
        (
            format!(
                "{https}\n[server.auth]\n{oauth2}\ntoken_url = \"https://idp.example.com/token\"\n\
                 client_secret = \"hunter2\""
            ),
            "server 's': [server.auth] client_secret is a secret written in the config".to_string(),
        ),
        (
            "transport = \"streamable-http\"\n\
             url = \"https://mcpdef:hunter2@mcp.example.com/mcp\""
                .to_string(),
            "server 's': url holds a password".to_string(),
        ),
        (
            "transport = \"streamable-http\"\n\
             url = \"https://mcp.example.com/mcp?api_key=hunter2\""
                .to_string(),
            "server 's': url holds a secret, its query parameter `api_key`".to_string(),
        ),
        (
            format!("transport = \"stdio\"\ncommand = [\"srv\", \"--token\", \"{token}\"]"),
            "server 's': command[2] holds a secret, a github-token by its shape".to_string(),
        ),
        // A certificate not checked.
        (
            format!("{https}\n[server.tls]\ninsecure_skip_verify = true"),
            "server 's': [server.tls] insecure_skip_verify = true: its certificate is not \
             checked"
                .to_string(),
        ),
        // A secret file others can read.
        (
            format!("{stdio}\n[server.env]\nTOKEN = {{ file = {readable:?} }}"),
            format!(
                "server 's': [server.env] TOKEN: {} can be read by its group and every user \
                 (mode 644)",
                readable.display()
            ),
        ),
        // Credentials sent in the clear.
        (
            "transport = \"streamable-http\"\nurl = \"http://mcp.example.com/mcp\"\n\
             [server.auth]\nkind = \"bearer\"\ntoken = { env = \"T\" }"
                .to_string(),
            "server 's': [server.auth] sends its credentials over plain HTTP to mcp.example.com"
                .to_string(),
        ),
        (
            format!(
                "{https}\n[server.auth]\n{oauth2}\ntoken_url = \"http://idp.example.com/token\"\n\
                 client_secret = {{ env = \"S\" }}"
            ),
            "server 's': [server.auth] sends its client secret over plain HTTP to \
             idp.example.com"
                .to_string(),
        ),
    ];
    let cfg = dir.path().join("mcpdef.toml");
    for (server, found) in &cases {
        for strict_key in [false, true] {
            let gateway = if strict_key { "strict = true\n" } else { "" };
            std::fs::write(
                &cfg,
                format!("[gateway]\n{gateway}\n[[server]]\nid = \"s\"\n{server}\n"),
            )
            .unwrap();
            for flag in [false, true] {
                let out = validate(&cfg, flag);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if strict_key || flag {
                    assert!(!out.status.success(), "{found}: {stderr}");
                    assert!(stderr.contains(&format!("✗ strict: {found}")), "{stderr}");
                    assert_eq!(stderr.matches('✗').count(), 1, "{stderr}");
                    assert!(!stderr.contains('⚠'), "{stderr}");
                } else {
                    assert!(out.status.success(), "{found}: {stderr}");
                    assert!(stderr.contains(&format!("⚠ {found}")), "{stderr}");
                    assert_eq!(stderr.matches('⚠').count(), 1, "{stderr}");
                }
                assert!(
                    !stderr.contains("hunter2") && !stderr.contains(&token),
                    "{stderr}"
                );
            }
        }
    }
}

/// The shape a strict config takes: an OAuth2 client-credentials HTTPS
/// upstream on a private CA, with mTLS, and two stdio servers with API keys,
/// every secret read from where it is kept. `validate --strict` passes it.
#[cfg(unix)]
#[test]
fn strict_passes_a_config_that_keeps_its_secrets_elsewhere() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let pki = mcpdef_testkit::Pki::new("mcpdef test CA");
    let ca = pki.write_root(dir.path(), "ca");
    let (cert, key) = pki
        .client("spiffe://mcpdef.test/gw")
        .write(dir.path(), "client");
    let slack = dir.path().join("slack-token");
    std::fs::write(&slack, "a token kept in a file").unwrap();
    std::fs::set_permissions(&slack, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    std::fs::write(
        &cfg,
        format!(
            "[gateway]\nstrict = true\n\n[gateway.upstream_tls]\nca = [{ca:?}]\n\n\
             [[server]]\nid = \"github\"\ntransport = \"stdio\"\n\
             command = [\"github-mcp-server\", \"stdio\"]\n\
             [server.env]\nGITHUB_PERSONAL_ACCESS_TOKEN = {{ env = \"MCPDEF_GITHUB_TOKEN\" }}\n\
             LOG_LEVEL = \"info\"\n\n\
             [[server]]\nid = \"slack\"\ntransport = \"stdio\"\ncommand = [\"slack-mcp-server\"]\n\
             [server.env]\nSLACK_BOT_TOKEN = {{ file = {slack:?} }}\n\n\
             [[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcp.internal.test/mcp\"\n\
             [server.tls]\nclient_cert = {cert:?}\nclient_key = {{ file = {key:?} }}\n\
             [server.auth]\nkind = \"oauth2\"\ntoken_url = \"https://idp.internal.test/token\"\n\
             client_id = \"mcpdef\"\nclient_secret = {{ exec = [\"op\", \"read\", \"op://x/y\"] }}\n\
             scopes = [\"mcp:tools\"]\n"
        ),
    )
    .unwrap();
    for flag in [false, true] {
        let out = validate(&cfg, flag);
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(out.status.success(), "{stderr}");
        assert!(
            stdout.contains("3 upstream(s), config valid, strictly"),
            "{stdout}"
        );
        assert!(stderr.is_empty(), "{stderr}");
    }
}

/// `mcpdef call` through the gateway `cfg` describes, to `echo`.
fn call_echo(cfg: &Path) -> std::process::Output {
    Command::new(BIN)
        .args(["call", "echo", "--config"])
        .arg(cfg)
        .output()
        .unwrap()
}

/// Under `[gateway] strict`, the gateway starts whole or not at all: not with
/// a config that has a warning, and not with an upstream that does not open.
/// Without it, it starts with the one and without the other.
#[test]
fn under_strict_the_gateway_starts_whole_or_not_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("mcpdef.toml");
    let mock = env!("CARGO_BIN_EXE_mock_mcp_server");
    let write = |strict: bool, server: &str| {
        std::fs::write(
            &cfg,
            format!(
                "[gateway]\naudit = {:?}\nstrict = {strict}\n\n[[server]]\nid = \"s\"\n\
                 tools = [\"echo\"]\n{server}\n",
                dir.path().join("audit.log")
            ),
        )
        .unwrap();
    };
    let literal = format!(
        "transport = \"stdio\"\ncommand = [{mock:?}]\n[server.env]\nGITHUB_TOKEN = \"hunter2\""
    );
    write(false, &literal);
    let out = call_echo(&cfg);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "mcpdef: warning — server 's': [server.env] GITHUB_TOKEN is a secret written in \
             the config"
        ),
        "{stderr}"
    );
    write(true, &literal);
    let out = call_echo(&cfg);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("✗ strict: server 's': [server.env] GITHUB_TOKEN is a secret")
            && stderr.contains("invalid config"),
        "{stderr}"
    );

    let missing = "transport = \"stdio\"\ncommand = [\"/nonexistent/mcp-server\"]";
    write(false, missing);
    let out = call_echo(&cfg);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("upstream 's' is down"), "{stderr}");
    write(true, missing);
    let out = call_echo(&cfg);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("initializing upstream 's'") && !stderr.contains("is down"),
        "{stderr}"
    );
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A gateway that runs strictly says so when it is ready.
#[test]
fn a_strict_gateway_says_so_when_it_is_ready() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let cfg = mock_cfg(dir.path());
    let text = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        text.replacen("[gateway]", "[gateway]\nstrict = true", 1),
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&cfg)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let _running = Running(child);
    let ready = std::io::BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .find(|line| line.contains(" ready "))
        .expect("a ready line");
    assert!(ready.contains(" · strict · "), "{ready}");
}

// ---------------------------------------------------------------------------
// `mcpdef version`
// ---------------------------------------------------------------------------

use mcpdef_core::wire::{SpecSetting, UpstreamSpec, WireMode, KNOWN_SPEC_VERSIONS};

fn version_output() -> String {
    let out = Command::new(BIN).arg("version").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// `mcpdef version` reports every revision the build speaks, with the default
/// listener's marked as the default.
///
/// The spec line was hand-written once and went stale — it went on calling
/// 2026-07-28 "planned" after that revision shipped — and nothing caught it,
/// because no test read this output. This one is written against the constants,
/// not against a copy of the line: adding a revision cannot make it fail, and
/// forgetting to report one cannot make it pass.
#[test]
fn version_reports_every_revision_the_build_speaks() {
    let text = version_output();
    let spec = text
        .lines()
        .find(|l| l.trim_start().starts_with("spec target"))
        .unwrap_or_else(|| panic!("no spec line in:\n{text}"));

    for v in KNOWN_SPEC_VERSIONS {
        assert!(spec.contains(v), "{v} is spoken but not reported: {spec}");
    }
    for v in WireMode::default().served() {
        assert!(
            spec.contains(&format!("{v} default")),
            "{v} is the default listener's revision but not marked so: {spec}"
        );
    }
    for v in WireMode::Modern.served() {
        assert!(
            spec.contains(&format!("stateless {v}")) || WireMode::default().served().contains(v),
            "{v} is stateless but not called so: {spec}"
        );
    }
}

/// The first line is what `mcpdef-bench` records as the measured binary's
/// identity, so it keeps its shape: the name, then the exact package version.
#[test]
fn version_first_line_names_the_exact_package_version() {
    let text = version_output();
    let first = text.lines().next().unwrap_or_default();
    assert!(
        first.starts_with(&format!("mcpdef {}  ·  ", env!("CARGO_PKG_VERSION"))),
        "{first}"
    );
}

/// The phase labels predate the 0.4.0 work and are retired.
/// `mcpdef --help`'s header carried the same one.
#[test]
fn version_and_help_carry_no_phase_label() {
    assert!(
        !version_output().to_lowercase().contains("phase"),
        "`mcpdef version` still names a phase"
    );
    let help = Command::new(BIN).arg("--help").output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(
        !help
            .lines()
            .next()
            .unwrap_or_default()
            .to_lowercase()
            .contains("phase"),
        "`mcpdef --help` still names a phase in its header:\n{help}"
    );
}

/// `mcpdef version` prints one default, which is only true while a listener and
/// an upstream default to the same revision.
///
/// If one moves — the listener to `dual`, say, with upstreams still pinned to
/// 2025-11-25 — this fails, so the line gets rewritten to say which default is
/// which instead of quietly claiming one for both.
#[test]
fn the_listener_and_upstream_defaults_agree() {
    let upstream = SpecSetting::default().pinned().map(UpstreamSpec::version);
    assert_eq!(
        WireMode::default().served(),
        upstream.as_slice(),
        "`mcpdef version` reports one default; say which is which there before splitting them"
    );
}
