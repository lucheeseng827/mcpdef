// SPDX-License-Identifier: Apache-2.0
//! `mcpdef import`, and `mcpdef up` with no config: the real binary, run with a
//! scratch home and working directory that hold the clients' config files.

use mcpdef::config::Config;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// `mcpdef` in `cwd`, with `home` as its home and no other config directory.
fn mcpdef(home: &Path, cwd: &Path) -> Command {
    let mut c = Command::new(BIN);
    c.current_dir(cwd)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME");
    c
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The mock as Claude Code runs it, from the project's `.mcp.json`, which
/// the user told Claude Code to run there, as `~/.claude.json` records it.
fn claude_code_runs_the_mock(home: &Path, cwd: &Path, env: &str) {
    write(
        &cwd.join(".mcp.json"),
        &format!(r#"{{"mcpServers":{{"mock":{{"command":{MOCK:?},"env":{env}}}}}}}"#),
    );
    let cwd = std::fs::canonicalize(cwd).unwrap();
    write(
        &home.join(".claude.json"),
        &format!(
            r#"{{"projects":{{{:?}:{{"enabledMcpjsonServers":["mock"]}}}}}}"#,
            cwd.display().to_string()
        ),
    );
}

#[test]
fn import_prints_a_config_that_fronts_what_the_clients_run() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    claude_code_runs_the_mock(home.path(), cwd.path(), r#"{"MOCK_TOKEN":"${MOCK_TOKEN}"}"#);
    // Cursor reaches MCPdef already: that is not fronted again.
    write(
        &home.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"gw":{"url":"http://127.0.0.1:7878/mcp"}}}"#,
    );
    let out = mcpdef(home.path(), cwd.path())
        .arg("import")
        .output()
        .unwrap();
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(out.status.success(), "{stderr}");
    let cfg = Config::parse(&stdout).unwrap_or_else(|e| panic!("{e}\n{stdout}"));
    assert_eq!(cfg.validate(), Vec::<String>::new(), "{stdout}");
    assert_eq!(cfg.servers.len(), 1);
    assert_eq!(cfg.servers[0].id, "mock");
    assert!(
        stdout.contains("MOCK_TOKEN = { env = \"MOCK_TOKEN\" }"),
        "{stdout}"
    );
    assert!(stderr.contains("mock: "), "{stderr}");
    assert!(
        stderr.contains("not fronted: gw, from Cursor (~/.cursor/mcp.json)"),
        "{stderr}"
    );
}

#[test]
fn import_with_nothing_to_front_says_so() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let out = mcpdef(home.path(), cwd.path())
        .arg("import")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("no MCP server to front"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn import_out_keeps_a_file_that_is_there_and_a_written_value_to_its_owner() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // A value the client writes in, not a variable: it goes in the file as is.
    claude_code_runs_the_mock(home.path(), cwd.path(), r#"{"API_KEY":"not-a-real-key"}"#);
    let target = cwd.path().join("mcpdef.toml");
    write(&target, "# mine\n");
    let import = |force: bool| {
        let mut c = mcpdef(home.path(), cwd.path());
        c.args(["import", "--out", "mcpdef.toml"]);
        if force {
            c.arg("--force");
        }
        c.output().unwrap()
    };
    let refused = import(false);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("--force"),
        "{}",
        text(&refused.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "# mine\n");

    let replaced = import(true);
    assert!(replaced.status.success(), "{}", text(&replaced.stderr));
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        written.contains("API_KEY = \"not-a-real-key\""),
        "{written}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a replaced file is kept to its owner too"
        );
    }
}

/// `mcpdef up` that has stopped, or is stopped after `limit`.
fn up_within(home: &Path, cwd: &Path, limit: Duration) -> Output {
    let mut child = mcpdef(home, cwd)
        .arg("up")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// With no `mcpdef.toml`, `up` writes one from what the clients run and starts
/// it. The default port is held here, so the gateway stops at binding it, after
/// writing its config: the test needs no port of its own. If something else
/// holds it, it stops all the same.
#[test]
fn up_with_no_config_writes_one_from_what_the_clients_run() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    claude_code_runs_the_mock(home.path(), cwd.path(), "{}");
    let _held = std::net::TcpListener::bind("127.0.0.1:7878");
    let out = up_within(home.path(), cwd.path(), Duration::from_secs(30));
    let stderr = text(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("there is no mcpdef.toml here"), "{stderr}");
    assert!(
        stderr.contains("binding the MCP listener on 127.0.0.1:7878"),
        "{stderr}"
    );
    let written = std::fs::read_to_string(cwd.path().join("mcpdef.toml")).unwrap();
    let cfg = Config::parse(&written).unwrap();
    assert_eq!(cfg.servers[0].id, "mock");

    // The next `up` runs the file it wrote, and reads no client's again.
    let again = up_within(home.path(), cwd.path(), Duration::from_secs(30));
    assert!(
        !text(&again.stderr).contains("there is no mcpdef.toml here"),
        "{}",
        text(&again.stderr)
    );
}

#[test]
fn up_with_no_config_and_nothing_to_front_says_what_to_do() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let out = up_within(home.path(), cwd.path(), Duration::from_secs(30));
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("no mcpdef.toml here, and no MCP server in any client's config"),
        "{stderr}"
    );
    assert!(!cwd.path().join("mcpdef.toml").exists());
}

/// A repository's `.mcp.json` names a server no client was told to run: `up`
/// does not start it, and `import` fronts it only when asked.
#[test]
fn a_server_no_client_was_told_to_run_is_not_started_unasked() {
    let (home, cwd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    write(
        &cwd.path().join(".mcp.json"),
        &format!(r#"{{"mcpServers":{{"mock":{{"command":{MOCK:?}}}}}}}"#),
    );
    let out = up_within(home.path(), cwd.path(), Duration::from_secs(30));
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("Claude Code was not told to run it here"),
        "{stderr}"
    );
    assert!(!cwd.path().join("mcpdef.toml").exists(), "{stderr}");

    let asked = mcpdef(home.path(), cwd.path())
        .args(["import", "--project-servers"])
        .output()
        .unwrap();
    let stdout = text(&asked.stdout);
    assert!(asked.status.success(), "{}", text(&asked.stderr));
    let cfg = Config::parse(&stdout).unwrap_or_else(|e| panic!("{e}\n{stdout}"));
    assert_eq!(cfg.servers.len(), 1);
    assert!(stdout.contains("read what it runs"), "{stdout}");
}
