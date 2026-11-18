// SPDX-License-Identifier: Apache-2.0
//! `mcpdef hook`: MCPdef as Claude Code's and Codex's `PreToolUse` hook,
//! through the real binary, with no proxy in the path.
//!
//! - A call the config allows gets no answer, so the client goes on as it
//!   would; one it refuses is denied, with why, and exit status 2, which
//!   blocks it whatever else the client reads. Both are recorded, as the
//!   gateway records them, and signed as receipts.
//! - What is no MCP tool call is not MCPdef's: no answer, no record.
//! - A server the config does not name, a config that does not read, an
//!   event that does not read and a command line that does not are refused:
//!   the hook fails closed.
//! - Hooks in processes of their own, many at once and beside a running
//!   gateway, keep one chain in the one ledger.
//! - `mcpdef hook install --write` adds the hook to the settings, keeping
//!   every other hook there, with a timeout of seconds rather than the
//!   clients' ten minutes.
//! - Codex asks and is answered as Claude Code is; its hook goes in the
//!   project's `.codex/hooks.json` and runs as `--client codex`.
//! - A hook installed with `--bundle-trust` judges by the config only while
//!   the signed bundle beside it holds it (tests/bundle.rs holds the rest).

use serde_json::{json, Value};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A config in `dir/cfg` fronting the mock as `github`, which allows `echo`
/// and refuses it for a `prod` repository.
fn config(dir: &Path) -> std::path::PathBuf {
    let cfg = dir.join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let path = cfg.join("mcpdef.toml");
    std::fs::write(
        &path,
        format!(
            "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = \"./mcpdef-audit/audit.log\"\n\n\
             [[server]]\nid = \"github\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
             tools = [\"echo\"]\n\n\
             [[policy]]\nname = \"no-prod\"\neffect = \"deny\"\nservers = [\"github\"]\n\
             tools = [\"echo\"]\nargs = [{{ path = \"repo\", equals = \"prod\" }}]\n"
        ),
    )
    .unwrap();
    path
}

fn event(tool: &str, input: Value) -> String {
    json!({
        "session_id": "4e1b7d5c",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/somewhere/else",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

/// A Codex `PreToolUse` event: Claude Code's fields, plus the turn, the call's
/// id and the model.
fn codex_event(tool: &str, input: Value) -> String {
    json!({
        "session_id": "019a6c1e",
        "transcript_path": null,
        "cwd": "/somewhere/else",
        "model": "gpt-6-astra",
        "permission_mode": "default",
        "turn_id": "turn-7",
        "tool_use_id": "call_7d1",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

/// The hook run in `dir`, a project directory other than the config's, with
/// `stdin` as the event.
fn hook(dir: &Path, cfg: &Path, stdin: &str) -> Output {
    hook_as(None, dir, cfg, stdin)
}

/// The same, as `--client <client>` when given one.
fn hook_as(client: Option<&str>, dir: &Path, cfg: &Path, stdin: &str) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.arg("hook");
    if let Some(client) = client {
        cmd.args(["--client", client]);
    }
    let mut child = cmd
        .arg("--config")
        .arg(cfg)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Why a hook refused the call, `None` for no answer.
fn denied(out: &Output) -> Option<String> {
    let text = String::from_utf8_lossy(&out.stdout);
    if out.status.code() == Some(0) {
        assert!(text.trim().is_empty(), "an answer, and status 0: {out:?}");
        return None;
    }
    // Status 2, which blocks the call whatever else the client reads, why on
    // standard error, and the answer on standard output.
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    let hso = &answer["hookSpecificOutput"];
    assert_eq!(hso["hookEventName"], "PreToolUse");
    assert_eq!(hso["permissionDecision"], "deny", "{answer}");
    let reason = hso["permissionDecisionReason"].as_str().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(reason),
        "{out:?}"
    );
    Some(reason.to_string())
}

fn records(cfg: &Path) -> Vec<Value> {
    let ledger = cfg.parent().unwrap().join("mcpdef-audit/audit.log");
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn each_mcp_tool_call_is_judged_by_the_config_and_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let allowed = hook(
        &project,
        &cfg,
        &event("mcp__github__echo", json!({ "repo": "x" })),
    );
    assert_eq!(denied(&allowed), None, "an allowed call gets no answer");
    let reason = denied(&hook(
        &project,
        &cfg,
        &event("mcp__github__echo", json!({ "repo": "prod" })),
    ))
    .unwrap();
    assert!(reason.starts_with("MCPdef denied (no-prod): "), "{reason}");
    let reason = denied(&hook(
        &project,
        &cfg,
        &event("mcp__github__delete_repo", json!({})),
    ))
    .unwrap();
    assert!(reason.contains("not-on-allowlist"), "{reason}");
    let reason = denied(&hook(&project, &cfg, &event("mcp__slack__post", json!({})))).unwrap();
    assert!(
        reason.contains("no [[server]] in the config is named 'slack'"),
        "{reason}"
    );
    // Not MCPdef's: no answer, and nothing recorded.
    for tool in ["Bash", "Edit"] {
        let out = hook(&project, &cfg, &event(tool, json!({ "command": "ls" })));
        assert_eq!(denied(&out), None, "{tool}");
    }

    // Recorded in the config's ledger, not in the project's directory.
    assert!(!project.join("mcpdef-audit").exists());
    let records = records(&cfg);
    let seen: Vec<(&str, &str, Option<&str>)> = records
        .iter()
        .map(|r| {
            (
                r["tool"].as_str().unwrap(),
                r["decision"].as_str().unwrap(),
                r["rule"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("echo", "allow", None),
            ("echo", "deny", Some("no-prod")),
            ("delete_repo", "deny", Some("not-on-allowlist")),
            ("post", "deny", Some("unknown-server")),
        ]
    );
    for r in &records {
        assert_eq!(r["hook"], "claude-code");
        assert_eq!(r["agent"], "agent:claude-code");
        assert_eq!(r["method"], "tools/call");
    }
    let ledger = cfg.parent().unwrap().join("mcpdef-audit/audit.log");
    let verified = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&ledger)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");

    // The same receipts as the gateway's decisions get.
    let key = dir.path().join("k.jwk");
    assert!(Command::new(BIN)
        .args(["receipts", "key", "--out"])
        .arg(&key)
        .status()
        .unwrap()
        .success());
    let exported = Command::new(BIN)
        .args(["receipts", "export", "--key"])
        .arg(&key)
        .arg("--path")
        .arg(&ledger)
        .output()
        .unwrap();
    assert!(exported.status.success(), "{exported:?}");
    assert_eq!(String::from_utf8_lossy(&exported.stdout).lines().count(), 4);
}

/// Codex asks in the shape Claude Code does and reads the same refusal, so
/// the same config judges its calls, and the ledger names it.
#[test]
fn codex_calls_are_judged_by_the_config_and_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let codex = |tool: &str, input: Value| {
        hook_as(Some("codex"), &project, &cfg, &codex_event(tool, input))
    };

    assert_eq!(
        denied(&codex("mcp__github__echo", json!({ "repo": "x" }))),
        None
    );
    let reason = denied(&codex("mcp__github__echo", json!({ "repo": "prod" }))).unwrap();
    assert!(reason.starts_with("MCPdef denied (no-prod): "), "{reason}");
    let reason = denied(&codex("mcp__github__delete_repo", json!({}))).unwrap();
    assert!(reason.contains("not-on-allowlist"), "{reason}");
    let reason = denied(&codex("mcp__slack__post", json!({}))).unwrap();
    assert!(reason.contains("named 'slack'"), "{reason}");
    // Codex's own tools are not MCPdef's: no answer, no record.
    for tool in ["Bash", "apply_patch"] {
        assert_eq!(
            denied(&codex(tool, json!({ "command": "ls" }))),
            None,
            "{tool}"
        );
    }

    let records = records(&cfg);
    let seen: Vec<(&str, &str)> = records
        .iter()
        .map(|r| (r["tool"].as_str().unwrap(), r["decision"].as_str().unwrap()))
        .collect();
    assert_eq!(
        seen,
        [
            ("echo", "allow"),
            ("echo", "deny"),
            ("delete_repo", "deny"),
            ("post", "deny"),
        ]
    );
    for r in &records {
        assert_eq!(r["hook"], "codex");
        assert_eq!(r["agent"], "agent:codex");
    }
}

#[test]
fn what_cannot_be_judged_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    // An event that does not read: refused, whatever it was.
    let out = hook(dir.path(), &cfg, "not an event");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("MCPdef refused the call"));
    // A hook naming a client MCPdef does not know: the same.
    let mut child = Command::new(BIN)
        .args(["hook", "--client", "nope", "--config"])
        .arg(&cfg)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // It may have gone before reading it.
    let stdin = event("mcp__github__echo", json!({}));
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown --client"));
    // A config that does not read: an MCP call is refused, with why.
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, "[gateway\n").unwrap();
    let reason = denied(&hook(
        dir.path(),
        &broken,
        &event("mcp__github__echo", json!({})),
    ))
    .unwrap();
    assert!(reason.contains("its config"), "{reason}");
    // And what is not an MCP call is still not MCPdef's.
    assert_eq!(
        denied(&hook(dir.path(), &broken, &event("Bash", json!({})))),
        None
    );
}

/// Hooks run in processes of their own, many at once, and maybe beside a
/// gateway writing to the same ledger: they take turns on it.
#[test]
fn hooks_at_once_and_a_gateway_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    // A gateway on the same ledger, with the config's directory its own.
    let mut gateway = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&cfg)
        .current_dir(cfg.parent().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut to_gateway = gateway.stdin.take().unwrap();
    let hooks: Vec<_> = (0..12)
        .map(|n| {
            let (dir, cfg) = (dir.path().to_path_buf(), cfg.clone());
            std::thread::spawn(move || {
                let repo = if n % 3 == 0 { "prod" } else { "x" };
                hook(
                    &dir,
                    &cfg,
                    &event("mcp__github__echo", json!({ "repo": repo })),
                )
            })
        })
        .collect();
    for id in 0..12 {
        let call = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": "echo", "arguments": { "repo": "x" } }
        });
        writeln!(to_gateway, "{call}").unwrap();
    }
    for (n, h) in hooks.into_iter().enumerate() {
        let out = h.join().unwrap();
        assert_eq!(denied(&out).is_some(), n % 3 == 0, "{out:?}");
    }
    drop(to_gateway);
    let answered = gateway.wait_with_output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&answered.stdout).lines().count(),
        12,
        "the gateway answered each call"
    );

    let records = records(&cfg);
    let hooked = records
        .iter()
        .filter(|r| r["hook"] == "claude-code")
        .count();
    let gated = records
        .iter()
        .filter(|r| r.get("hook").is_none() && r["method"] == "tools/call")
        .count();
    assert_eq!((hooked, gated), (12, 12));
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r["seq"], i, "no seq taken twice or skipped");
    }
    let ledger = cfg.parent().unwrap().join("mcpdef-audit/audit.log");
    let verified = Command::new(BIN)
        .args(["audit", "verify", "--path"])
        .arg(&ledger)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");
}

#[test]
fn install_adds_the_hook_and_keeps_every_other() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let project = dir.path().join("project");
    let settings = project.join(".claude/settings.local.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let before = json!({
        "permissions": { "allow": ["Bash(ls:*)"] },
        "hooks": { "PreToolUse": [
            { "hooks": [{ "type": "command", "command": "/usr/local/bin/slop-hook" }] },
            { "matcher": "mcp__.*", "hooks": [
                { "type": "command", "command": "/old/bin/mcpdef hook --config /old/mcpdef.toml" }
            ] }
        ] }
    });
    std::fs::write(&settings, before.to_string()).unwrap();
    let install = |write: bool| {
        let mut cmd = Command::new(BIN);
        cmd.args(["hook", "install", "--config"])
            .arg(&cfg)
            .current_dir(&project);
        if write {
            cmd.arg("--write");
        }
        cmd.output().unwrap()
    };

    // Printed, the file left as it is.
    let printed = install(false);
    assert!(printed.status.success(), "{printed:?}");
    let group: Value = serde_json::from_slice(&printed.stdout).unwrap();
    assert_eq!(group["matcher"], "mcp__.*");
    // A hook that fails refuses the call, rather than letting it through.
    assert_eq!(group["hooks"][0]["onFailure"], "block");
    // And the client gives up on one that hangs after seconds, not its
    // default ten minutes.
    assert_eq!(group["hooks"][0]["timeout"], 10);
    let command = group["hooks"][0]["command"].as_str().unwrap().to_string();
    assert!(command.ends_with(&format!(
        " hook --config {}",
        std::fs::canonicalize(&cfg).unwrap().display()
    )));
    assert_eq!(
        serde_json::from_str::<Value>(&std::fs::read_to_string(&settings).unwrap()).unwrap(),
        before
    );

    let wrote = install(true);
    assert!(wrote.status.success(), "{wrote:?}");
    let after: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(after["permissions"], before["permissions"]);
    let commands: Vec<&str> = after["hooks"]["PreToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["hooks"].as_array().unwrap())
        .map(|h| h["command"].as_str().unwrap())
        .collect();
    assert_eq!(commands, ["/usr/local/bin/slop-hook", command.as_str()]);
    assert!(project.join(".claude/settings.local.json.bak").exists());
    let again = install(true);
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("already asks MCPdef"),
        "{again:?}"
    );
}

/// For Codex, `install` writes the project's `.codex/hooks.json`, with the
/// hook running as Codex's and the timeout asked for, and says the hook runs
/// only once it is trusted in `/hooks`.
#[test]
fn install_for_codex_writes_its_hooks_file() {
    let dir = tempfile::tempdir().unwrap();
    // A directory both shells must be given in quotes, or run something else.
    let cfg = config(&dir.path().join("my tools & (x86)"));
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let install = |extra: &[&str]| {
        Command::new(BIN)
            .args(["hook", "install", "--client", "codex", "--config"])
            .arg(&cfg)
            .args(extra)
            .current_dir(&project)
            .output()
            .unwrap()
    };

    // Not a timeout a client could use.
    for bad in ["0", "601"] {
        let out = install(&["--timeout", bad]);
        assert!(!out.status.success(), "--timeout {bad}: {out:?}");
    }

    let wrote = install(&["--timeout", "5", "--write"]);
    assert!(wrote.status.success(), "{wrote:?}");
    let stderr = String::from_utf8_lossy(&wrote.stderr);
    assert!(stderr.contains("/hooks"), "{stderr}");
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(project.join(".codex/hooks.json")).unwrap())
            .unwrap();
    let groups = hooks["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{hooks}");
    assert_eq!(groups[0]["matcher"], "mcp__.*");
    let handler = &groups[0]["hooks"][0];
    assert_eq!(handler["type"], "command");
    assert_eq!(handler["timeout"], 5);
    assert!(handler.get("onFailure").is_none(), "{handler}");
    // A line for each shell Codex runs a hook through.
    for key in ["command", "commandWindows"] {
        let line = handler[key].as_str().unwrap();
        assert!(
            line.contains(" hook --client codex --config "),
            "{key}: {line}"
        );
        assert!(line.contains("my tools & (x86)"), "{key}: {line}");
    }

    // The hook as Codex runs it judges a Codex call, a path with a space,
    // `&` and parentheses in it and all: allowed, nothing said; refused, why.
    let allowed = run_as_codex(
        handler,
        &project,
        &codex_event("mcp__github__echo", json!({ "repo": "x" })),
    );
    assert_eq!(denied(&allowed), None, "{allowed:?}");
    let refused = run_as_codex(
        handler,
        &project,
        &codex_event("mcp__github__delete_repo", json!({})),
    );
    assert!(denied(&refused).unwrap().contains("not-on-allowlist"));
    let records = records(&cfg);
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(records.iter().all(|r| r["hook"] == "codex"));

    // Installed again: one MCPdef hook, not two.
    let again = install(&["--timeout", "5", "--write"]);
    assert!(again.status.success(), "{again:?}");
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(project.join(".codex/hooks.json")).unwrap())
            .unwrap();
    assert_eq!(hooks["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
}

/// For Codex, `install --bundle-trust` names the keys on the line for each
/// shell, and the hook as Codex runs it judges by the config only while the
/// signed bundle beside it holds it: widened by hand, every MCP call is
/// refused, and nothing recorded.
#[test]
fn install_for_codex_with_bundle_trust_holds_the_hook_to_its_bundle() {
    use mcpdef::bundle;
    use mcpdef_audit::receipt::SigningKey;
    let dir = tempfile::tempdir().unwrap();
    // Directories both shells must be given in quotes, or run something else.
    let cfg = config(&dir.path().join("my tools & (x86)"));
    let keys = dir.path().join("keys & (x86)").join("bundle-keys.json");
    std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
    let key =
        SigningKey::from_jwk(&SigningKey::generate_named(bundle::KID_PREFIX).unwrap()).unwrap();
    std::fs::write(&keys, key.jwks().to_string()).unwrap();
    // Carried in: the config, and beside it the bundle that holds it.
    let text = std::fs::read_to_string(&cfg).unwrap();
    let signed = bundle::sign(&text, 1, &bundle::now(), &key).unwrap();
    std::fs::write(bundle::beside(&cfg), signed).unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();

    let wrote = Command::new(BIN)
        .args(["hook", "install", "--client", "codex", "--config"])
        .arg(&cfg)
        .arg("--bundle-trust")
        .arg(&keys)
        .arg("--write")
        .current_dir(&project)
        .output()
        .unwrap();
    assert!(wrote.status.success(), "{wrote:?}");
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(project.join(".codex/hooks.json")).unwrap())
            .unwrap();
    let handler = &hooks["hooks"]["PreToolUse"][0]["hooks"][0];
    for key in ["command", "commandWindows"] {
        let line = handler[key].as_str().unwrap();
        assert!(line.contains(" --bundle-trust "), "{key}: {line}");
        assert!(line.contains("keys & (x86)"), "{key}: {line}");
    }

    let allowed = run_as_codex(
        handler,
        &project,
        &codex_event("mcp__github__echo", json!({ "repo": "x" })),
    );
    assert_eq!(denied(&allowed), None, "{allowed:?}");
    std::fs::write(&cfg, text.replace("tools = [\"echo\"]", "tools = [\"*\"]")).unwrap();
    let refused = run_as_codex(
        handler,
        &project,
        &codex_event("mcp__github__delete_repo", json!({})),
    );
    let reason = denied(&refused).unwrap();
    assert!(
        reason.starts_with("MCPdef denied (bundle-unverified): "),
        "{reason}"
    );
    let records = records(&cfg);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
}

/// Run the hook `handler` names, in `dir`, with `stdin` as its event, as
/// Codex runs a hook's command: `$SHELL -lc <command>` on Unix, and on
/// Windows `%COMSPEC% /C "<commandWindows>"`, the line handed to cmd.exe as
/// it is, in the one pair of quotes Codex adds (codex-rs/hooks/src/engine/
/// command_runner.rs, `build_command`).
fn run_as_codex(handler: &Value, dir: &Path, stdin: &str) -> Output {
    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt as _;
        let line = handler["commandWindows"].as_str().unwrap();
        let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
        let mut cmd = Command::new(comspec);
        cmd.arg("/C").raw_arg(format!("\"{line}\""));
        cmd
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", handler["command"].as_str().unwrap()]);
        cmd
    };
    let mut child = cmd
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
