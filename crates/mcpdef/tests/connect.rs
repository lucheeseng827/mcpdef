// SPDX-License-Identifier: Apache-2.0
//! `mcpdef connect <client>`, through the real binary.
//!
//! - A golden file per client: the entry it prints for a gateway on the local
//!   CA, in that client's own format, with how that client trusts the CA.
//!   `MCPDEF_BLESS=1` rewrites them; read the diff before committing it.
//! - `--write` merges into the client's file and keeps a `.bak` of what was
//!   there; run again, it writes nothing and leaves the backup alone.
//! - A file it cannot parse, such as VS Code's with comments, is refused and
//!   left byte for byte as it was.
//! - Codex's TOML keeps its comments and its other settings.
//! - A token is named by its variable, never its value; a client certificate
//!   makes any client's entry a `mcpdef bridge` one.
//!
//! Every run sets `HOME` and the working directory to temporary ones, so no
//! test can touch the real config files of the machine it runs on.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A gateway on the local CA, on a fixed port, for `connect` to describe.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        for dir in ["home", "work"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        let config = format!(
            "[gateway]\nlisten = \"127.0.0.1:8443\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
             [gateway.tls]\nmode = \"self-signed\"\n\n\
             [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = [\"echo\"]\n",
            audit = root.path().join("audit.log"),
            state = root.path().join("state"),
        );
        std::fs::write(root.path().join("mcpdef.toml"), config).unwrap();
        Fixture { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }

    /// `mcpdef connect <args>` against this gateway.
    fn connect(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .arg("connect")
            .args(args)
            .arg("--config")
            .arg(self.root.path().join("mcpdef.toml"))
            .env("HOME", self.home())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("APPDATA")
            .current_dir(self.work())
            .output()
            .unwrap()
    }

    fn connect_ok(&self, args: &[&str]) -> String {
        let out = self.connect(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// Output with this run's paths put back as placeholders, so a golden
    /// file reads the same on every machine.
    fn normalize(&self, text: &str) -> String {
        let root = std::fs::canonicalize(self.root.path()).unwrap();
        text.replace(BIN, "$MCPDEF")
            .replace(&root.display().to_string(), "$DIR")
            .replace(&self.root.path().display().to_string(), "$DIR")
    }
}

/// Compare with the golden file, or write it when blessing.
///
/// `.golden`, not `.txt`: the repository ignores `*.txt`, so a golden file by
/// that name would exist only on the machine that blessed it, and CI would
/// find none.
fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/connect")
        .join(format!("{name}.golden"));
    if std::env::var_os("MCPDEF_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("no golden file {}: run with MCPDEF_BLESS=1", path.display()));
    assert_eq!(
        actual,
        expected,
        "`mcpdef connect {name}` no longer prints {}",
        path.display()
    );
}

// The golden files hold the Linux trust-store commands and Linux paths.
#[cfg(target_os = "linux")]
mod goldens {
    use super::*;

    fn check(client: &str) {
        let f = Fixture::new();
        golden(client, &f.normalize(&f.connect_ok(&[client])));
    }

    #[test]
    fn claude_code() {
        check("claude-code");
    }

    #[test]
    fn claude_desktop() {
        check("claude-desktop");
    }

    #[test]
    fn cursor() {
        check("cursor");
    }

    #[test]
    fn vscode() {
        check("vscode");
    }

    #[test]
    fn codex() {
        check("codex");
    }

    #[test]
    fn generic() {
        check("generic");
    }
}

/// `--write` merges, keeps a `.bak` of what was there, and a second run
/// changes nothing — neither the file nor the backup.
#[test]
fn write_merges_keeps_the_backup_and_is_idempotent() {
    let f = Fixture::new();
    let file = f.home().join(".cursor/mcp.json");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let original =
        r#"{"mcpServers": {"other": {"url": "https://other.example/mcp"}}, "theme": "dark"}"#;
    std::fs::write(&file, original).unwrap();

    let out = f.connect_ok(&["cursor", "--write"]);
    assert!(out.contains("what it held before is in"), "{out}");
    let backup = f.home().join(".cursor/mcp.json.bak");
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);

    let merged: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        merged["mcpServers"]["mcpdef"]["url"],
        "https://127.0.0.1:8443/mcp"
    );
    assert_eq!(
        merged["mcpServers"]["other"]["url"],
        "https://other.example/mcp"
    );
    assert_eq!(merged["theme"], "dark", "what else the file held is kept");

    let first = std::fs::read(&file).unwrap();
    let again = f.connect_ok(&["cursor", "--write"]);
    assert!(again.contains("nothing written"), "{again}");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        first,
        "the second run changed the file"
    );
    assert_eq!(
        std::fs::read_to_string(&backup).unwrap(),
        original,
        "the second run replaced the backup of the original"
    );
}

/// A file that does not exist yet is created, with its directory, and there
/// is nothing to back up.
#[test]
fn write_creates_a_missing_file_without_a_backup() {
    let f = Fixture::new();
    let out = f.connect_ok(&["claude-code", "--write"]);
    assert!(out.contains("wrote"), "{out}");
    let file = f.work().join(".mcp.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(doc["mcpServers"]["mcpdef"]["type"], "http");
    assert!(!f.work().join(".mcp.json.bak").exists());
}

/// VS Code's file may hold comments, which plain JSON does not. Rather than
/// drop them by rewriting, `--write` refuses and leaves the file exactly as
/// it was.
#[test]
fn a_file_with_comments_is_refused_and_left_as_it_was() {
    let f = Fixture::new();
    let file = f.work().join(".vscode/mcp.json");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let original = "{\n  // my servers\n  \"servers\": {}\n}\n";
    std::fs::write(&file, original).unwrap();

    let out = f.connect(&["vscode", "--write"]);
    assert!(!out.status.success(), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("by hand"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    assert!(!f.work().join(".vscode/mcp.json.bak").exists());
}

/// Codex's TOML keeps its comments and its other settings: it is edited in
/// place, not rewritten from a table.
#[test]
fn codex_toml_keeps_its_comments_and_settings() {
    let f = Fixture::new();
    let file = f.home().join(".codex/config.toml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "# my settings\nmodel = \"gpt-5\"\n").unwrap();

    f.connect_ok(&["codex", "--write"]);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("# my settings"), "{text}");
    assert!(text.contains("model = \"gpt-5\""), "{text}");
    let doc: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(
        doc["mcp_servers"]["mcpdef"]["url"].as_str(),
        Some("https://127.0.0.1:8443/mcp"),
        "{text}"
    );

    let again = f.connect_ok(&["codex", "--write"]);
    assert!(again.contains("nothing written"), "{again}");
}

/// A token is referred to by its variable; its value never reaches the
/// output, even when it is set in the environment `connect` runs in.
#[test]
fn a_token_is_named_by_its_variable_never_its_value() {
    let f = Fixture::new();
    let out = Command::new(BIN)
        .args(["connect", "claude-code", "--token-env", "MCPDEF_TOKEN"])
        .arg("--config")
        .arg(f.root.path().join("mcpdef.toml"))
        .env("HOME", f.home())
        .env("MCPDEF_TOKEN", "s3cr3t-value")
        .current_dir(f.work())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Bearer ${MCPDEF_TOKEN}"), "{text}");
    assert!(!text.contains("s3cr3t-value"), "{text}");
    // The command line would have the shell expand the token into the
    // client's file, so it is not offered with one.
    assert!(!text.contains("claude mcp add"), "{text}");
}

/// A client certificate makes any client's entry a bridge, which presents it.
#[test]
fn a_certificate_makes_the_entry_a_bridge() {
    let f = Fixture::new();
    let text = f.connect_ok(&["cursor", "--cert", "/c/agent.crt", "--key", "/c/agent.key"]);
    let json_start = text.find('{').unwrap();
    let json_end = text.rfind('}').unwrap();
    let doc: Value = serde_json::from_str(&text[json_start..=json_end]).unwrap();
    let entry = &doc["mcpServers"]["mcpdef"];
    assert_eq!(entry["type"], "stdio", "{text}");
    let args: Vec<&str> = entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(args[0], "bridge", "{text}");
    for flag in ["--cert", "/c/agent.crt", "--key", "/c/agent.key", "--ca"] {
        assert!(args.contains(&flag), "{flag} missing: {text}");
    }
}

/// A generic client has no file of its own: `--write` asks for one.
#[test]
fn generic_has_no_file_to_write_to() {
    let f = Fixture::new();
    let out = f.connect(&["generic", "--write"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8(out.stderr).unwrap().contains("--file"));
}

/// An unknown client is refused with the names that exist.
#[test]
fn an_unknown_client_is_named_with_the_choices() {
    let f = Fixture::new();
    let out = f.connect(&["zed"]);
    assert!(!out.status.success());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("claude-code") && err.contains("vscode"),
        "{err}"
    );
}
