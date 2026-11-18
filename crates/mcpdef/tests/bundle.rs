// SPDX-License-Identifier: Apache-2.0
//! `mcpdef bundle`: a config signed at a revision, and a node that takes it
//! only from a key it trusts, never below the last revision it applied, and
//! records each bundle it takes or refuses. They drive the real binary
//! (`CARGO_BIN_EXE_mcpdef`) in a directory of its own, as an operator would.

use mcpdef::bundle::{self, FLOOR_FILE, KID_PREFIX};
use mcpdef_audit::receipt::SigningKey;
use mcpdef_audit::Record;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");

/// A config that validates, its server listing `tools`.
fn policy(tools: &str) -> String {
    format!(
        "[gateway]\naudit = \"./audit/audit.log\"\nstate_dir = \"./state\"\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [\"mock\"]\ntools = {tools}\n"
    )
}

/// A directory with a signing key, its public half as `keys.json`, and the
/// node's config to be, `mcpdef.toml`.
struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    fn new() -> Node {
        let node = Node {
            dir: tempfile::tempdir().unwrap(),
        };
        let key = node.mcpdef(&["bundle", "key", "--out", "signer.jwk"]);
        assert!(key.status.success(), "{}", said(&key));
        let jwks = node.mcpdef(&["bundle", "jwks", "--key", "signer.jwk"]);
        assert!(jwks.status.success(), "{}", said(&jwks));
        std::fs::write(node.path("keys.json"), &jwks.stdout).unwrap();
        node
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn mcpdef(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .unwrap()
    }

    /// `config` signed at `revision` as `<name>`, through the CLI.
    fn sign(&self, config: &str, revision: u64, name: &str) {
        std::fs::write(self.path("policy.toml"), config).unwrap();
        let signed = self.mcpdef(&[
            "bundle",
            "sign",
            "--config",
            "policy.toml",
            "--key",
            "signer.jwk",
            "--revision",
            &revision.to_string(),
            "--out",
            name,
        ]);
        assert!(signed.status.success(), "{}", said(&signed));
    }

    fn apply(&self, name: &str) -> Output {
        self.mcpdef(&["bundle", "apply", name, "--trust", "keys.json"])
    }

    fn config(&self) -> Option<String> {
        std::fs::read_to_string(self.path("mcpdef.toml")).ok()
    }

    fn records(&self) -> Vec<Record> {
        mcpdef_audit::read_all(self.path("audit/audit.log")).unwrap()
    }
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_bundle_is_applied_once_and_never_rolled_back() {
    let node = Node::new();
    let (one, two) = (policy("[\"echo\"]"), policy("[\"echo\", \"list\"]"));
    node.sign(&one, 1, "r1.bundle");
    node.sign(&two, 2, "r2.bundle");

    let first = node.apply("r1.bundle");
    assert!(first.status.success(), "{}", said(&first));
    assert!(said(&first).contains("applied revision 1 (the first this node applied)"));
    assert_eq!(node.config().as_deref(), Some(one.as_str()));
    let again = node.apply("r1.bundle");
    assert!(again.status.success(), "{}", said(&again));
    assert!(said(&again).contains("is as it was"), "{}", said(&again));

    let second = node.apply("r2.bundle");
    assert!(second.status.success(), "{}", said(&second));
    assert!(said(&second).contains("applied revision 2 (over revision 1)"));
    assert_eq!(node.config().as_deref(), Some(two.as_str()));

    // The older bundle, replayed: refused, and the config stays.
    let replayed = node.apply("r1.bundle");
    assert!(!replayed.status.success());
    assert!(
        said(&replayed).contains("revision 1 is older than revision 2"),
        "{}",
        said(&replayed)
    );
    assert_eq!(node.config().as_deref(), Some(two.as_str()));

    // A rollback: the earlier config, signed again above the floor.
    node.sign(&one, 3, "r3.bundle");
    let back = node.apply("r3.bundle");
    assert!(back.status.success(), "{}", said(&back));
    assert_eq!(node.config().as_deref(), Some(one.as_str()));

    let records = node.records();
    let seen: Vec<(Option<&str>, &str, Option<u64>)> = records
        .iter()
        .map(|r| {
            (
                r.rule.as_deref(),
                r.decision.as_str(),
                r.bundle.as_ref().and_then(|b| b.revision),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (None, "allow", Some(1)),
            (None, "allow", Some(2)),
            (Some("bundle-older"), "deny", Some(1)),
            (None, "allow", Some(3)),
        ]
    );
    for r in &records {
        assert_eq!(r.kind.as_deref(), Some("reload"));
        assert_eq!(r.method.as_deref(), Some("bundle"));
        let kid = r.bundle.as_ref().and_then(|b| b.kid.as_deref()).unwrap();
        assert!(kid.starts_with(KID_PREFIX), "{kid}");
    }
    // Each applied record names the config it put in place, and from the
    // second on, the one before it.
    assert!(records[0].config_from.is_none());
    assert_eq!(records[1].config_from, records[0].config_to);
    let verified = node.mcpdef(&["audit", "verify", "--config", "mcpdef.toml"]);
    assert!(verified.status.success(), "{}", said(&verified));
}

#[test]
fn a_bundle_no_trusted_key_signed_as_it_is_is_refused_and_recorded() {
    let node = Node::new();
    node.sign(&policy("[\"echo\"]"), 1, "r1.bundle");
    assert!(node.apply("r1.bundle").status.success());

    // Raised to revision 2 by hand: the signature no longer covers it.
    let text = std::fs::read_to_string(node.path("r1.bundle")).unwrap();
    let forged = text
        .replace("\"revision\": 1", "\"revision\": 2")
        .replace("[\\\"echo\\\"]", "[\\\"echo\\\", \\\"delete_repo\\\"]");
    assert_ne!(forged, text);
    std::fs::write(node.path("forged.bundle"), &forged).unwrap();
    let refused = node.apply("forged.bundle");
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("its signature does not verify"),
        "{}",
        said(&refused)
    );

    // Signed, but by a key the node was not given.
    let stranger = SigningKey::from_jwk(&SigningKey::generate_named(KID_PREFIX).unwrap()).unwrap();
    let signed = bundle::sign(&policy("[\"echo\"]"), 5, &bundle::now(), &stranger).unwrap();
    std::fs::write(node.path("stranger.bundle"), signed).unwrap();
    let refused = node.apply("stranger.bundle");
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("no key it trusts is named"),
        "{}",
        said(&refused)
    );

    assert_eq!(
        node.config().as_deref(),
        Some(policy("[\"echo\"]").as_str())
    );
    let records = node.records();
    assert_eq!(records.len(), 3, "{records:?}");
    for refused in &records[1..] {
        assert_eq!(refused.rule.as_deref(), Some("bundle-unverified"));
        let named = refused.bundle.as_ref().unwrap();
        // What a bundle that did not verify says of itself is not recorded.
        assert_eq!((named.revision, named.kid.as_deref()), (None, None));
        assert!(named.sha256.starts_with("sha256:"), "{named:?}");
    }
}

#[test]
fn a_config_that_does_not_validate_is_neither_signed_nor_applied() {
    let node = Node::new();
    std::fs::write(node.path("empty.toml"), "[gateway]\n").unwrap();
    let signed = node.mcpdef(&[
        "bundle",
        "sign",
        "--config",
        "empty.toml",
        "--key",
        "signer.jwk",
        "--revision",
        "1",
    ]);
    assert!(!signed.status.success());
    assert!(
        said(&signed).contains("a node would refuse it"),
        "{}",
        said(&signed)
    );
    assert!(!node.path("mcpdef.bundle").exists());

    // Signed all the same, through the library: the node checks it too.
    let key =
        SigningKey::from_jwk(&std::fs::read_to_string(node.path("signer.jwk")).unwrap()).unwrap();
    let text = bundle::sign("[gateway]\n", 1, &bundle::now(), &key).unwrap();
    std::fs::write(node.path("empty.bundle"), text).unwrap();
    let refused = node.apply("empty.bundle");
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("no [[server]] entries"),
        "{}",
        said(&refused)
    );
    assert_eq!(node.config(), None);
}

#[test]
fn a_new_config_takes_a_new_revision() {
    let node = Node::new();
    node.sign(&policy("[\"echo\"]"), 4, "a.bundle");
    node.sign(&policy("[\"list\"]"), 4, "b.bundle");
    assert!(node.apply("a.bundle").status.success());
    let refused = node.apply("b.bundle");
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("a new config takes a new revision"),
        "{}",
        said(&refused)
    );
    let floor: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(node.path("state").join(FLOOR_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(floor["revision"], 4);
    assert_eq!(
        floor["config"],
        bundle::sha256(policy("[\"echo\"]").as_bytes())
    );
}

#[test]
fn verify_says_what_a_bundle_holds_and_writes_its_config_out() {
    let node = Node::new();
    node.sign(&policy("[\"echo\"]"), 9, "r9.bundle");
    let checked = node.mcpdef(&[
        "bundle",
        "verify",
        "r9.bundle",
        "--trust",
        "keys.json",
        "--config-out",
        "review.toml",
    ]);
    assert!(checked.status.success(), "{}", said(&checked));
    let line = String::from_utf8_lossy(&checked.stdout);
    assert!(
        line.starts_with("bundle OK · revision 9 · signed by mcpdef:bundle:"),
        "{line}"
    );
    assert_eq!(
        std::fs::read_to_string(node.path("review.toml")).unwrap(),
        policy("[\"echo\"]")
    );
    // Verifying writes nothing a node runs.
    assert_eq!(node.config(), None);
    assert!(!Path::new(&node.path("state")).exists());
}

#[test]
fn the_bundle_applied_last_puts_back_a_config_changed_since() {
    let node = Node::new();
    let config = policy("[\"echo\"]");
    node.sign(&config, 2, "r2.bundle");
    assert!(node.apply("r2.bundle").status.success());
    // Changed in place by hand, not through a bundle.
    std::fs::write(
        node.path("mcpdef.toml"),
        policy("[\"echo\", \"delete_repo\"]"),
    )
    .unwrap();
    let again = node.apply("r2.bundle");
    assert!(again.status.success(), "{}", said(&again));
    assert!(
        said(&again)
            .contains("applied revision 2 (again: what was in place was not this bundle's)"),
        "{}",
        said(&again)
    );
    assert_eq!(node.config().as_deref(), Some(config.as_str()));
    let records = node.records();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[1].decision, "allow");
}

#[test]
fn a_config_that_names_a_file_the_host_lacks_is_refused() {
    let node = Node::new();
    let config = format!(
        "{}\n[server.env]\nTOKEN = {{ file = \"secrets/token\" }}\n",
        policy("[\"echo\"]")
    );
    node.sign(&config, 1, "r1.bundle");
    let refused = node.apply("r1.bundle");
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("it names secrets/token, which this host does not have"),
        "{}",
        said(&refused)
    );
    assert_eq!(node.config(), None);

    std::fs::create_dir_all(node.path("secrets")).unwrap();
    std::fs::write(node.path("secrets/token"), "t0ken\n").unwrap();
    let applied = node.apply("r1.bundle");
    assert!(applied.status.success(), "{}", said(&applied));
    assert_eq!(node.config().as_deref(), Some(config.as_str()));
}

/// A config the gateway can run, listening on `listen`: its server is the
/// mock.
fn served(listen: &str) -> String {
    format!(
        "[gateway]\nlisten = {listen:?}\naudit = \"./audit/audit.log\"\nstate_dir = \"./state\"\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{:?}]\ntools = [\"echo\"]\n",
        env!("CARGO_BIN_EXE_mock_mcp_server")
    )
}

/// `mcpdef up --bundle-trust keys.json` in the node's directory: its ready
/// line once it says it, then stopped; or, if it stops first, what it said.
#[cfg(unix)]
fn up_locked(node: &Node) -> Result<String, String> {
    locked(node, "up")
}

/// `mcpdef <command> --bundle-trust keys.json`, as [`up_locked`] runs `up`.
#[cfg(unix)]
fn locked(node: &Node, command: &str) -> Result<String, String> {
    use std::io::BufRead;
    use std::process::Stdio;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;
    let mut up = Command::new(BIN)
        .args([
            command,
            "--config",
            "mcpdef.toml",
            "--bundle-trust",
            "keys.json",
        ])
        .current_dir(node.path(""))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = up.stderr.take().unwrap();
    let (send, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let said = loop {
        match lines.recv_timeout(Duration::from_secs(20)) {
            Ok(line) if line.contains(" ready ") => break Ok(line),
            Ok(line) => seen.push(line),
            // Its stderr closed: it stopped.
            Err(RecvTimeoutError::Disconnected) => break Err(seen.join("\n")),
            Err(RecvTimeoutError::Timeout) => {
                let _ = up.kill();
                panic!("no ready line: {seen:#?}");
            }
        }
    };
    let _ = up.kill();
    let _ = up.wait();
    said
}

/// `mcpdef up --bundle-trust`: a config no bundle holds does not start, and
/// one a bundle applied does, saying the revision it runs.
#[cfg(unix)]
#[test]
fn up_with_bundle_trust_runs_only_a_config_a_bundle_holds() {
    use std::process::Stdio;
    let node = Node::new();
    let config = served("127.0.0.1:0");
    std::fs::write(node.path("mcpdef.toml"), &config).unwrap();

    // Written in place, not applied: it does not start. The keys come from
    // the environment as well as from the flag.
    let plain = Command::new(BIN)
        .args(["up", "--config", "mcpdef.toml"])
        .env("MCPDEF_BUNDLE_TRUST", "keys.json")
        .current_dir(node.path(""))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!plain.status.success());
    assert!(
        said(&plain).contains("there is no mcpdef.toml.bundle"),
        "{}",
        said(&plain)
    );
    assert!(
        said(&plain).contains("are in the config's directory"),
        "{}",
        said(&plain)
    );

    node.sign(&config, 1, "r1.bundle");
    let applied = node.apply("r1.bundle");
    assert!(applied.status.success(), "{}", said(&applied));
    let ready = up_locked(&node).unwrap();
    assert!(ready.contains(" · bundle r1 · "), "{ready}");
    assert_eq!(
        std::fs::read_to_string(node.path("mcpdef.toml.bundle")).unwrap(),
        std::fs::read_to_string(node.path("r1.bundle")).unwrap(),
        "the bundle applied is kept beside the config"
    );
}

#[test]
fn a_bundle_applied_again_puts_back_the_bundle_beside_the_config() {
    let node = Node::new();
    let config = policy("[\"echo\"]");
    node.sign(&config, 1, "r1.bundle");
    assert!(node.apply("r1.bundle").status.success());
    std::fs::remove_file(node.path("mcpdef.toml.bundle")).unwrap();
    let again = node.apply("r1.bundle");
    assert!(again.status.success(), "{}", said(&again));
    assert!(
        said(&again)
            .contains("applied revision 1 (again: what was in place was not this bundle's)"),
        "{}",
        said(&again)
    );
    assert_eq!(
        std::fs::read(node.path("mcpdef.toml.bundle")).unwrap(),
        std::fs::read(node.path("r1.bundle")).unwrap()
    );
    let unchanged = node.apply("r1.bundle");
    assert!(
        said(&unchanged).contains("is as it was"),
        "{}",
        said(&unchanged)
    );
}

/// A bundle carried in with its config, not applied, raises the floor only
/// once the gateway runs it: a start that fails leaves the floor as it was.
#[cfg(unix)]
#[test]
fn a_bundle_carried_in_raises_the_floor_only_once_it_runs() {
    let node = Node::new();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = served(&taken.local_addr().unwrap().to_string());
    node.sign(&config, 1, "r1.bundle");
    std::fs::copy(node.path("r1.bundle"), node.path("mcpdef.toml.bundle")).unwrap();
    std::fs::write(node.path("mcpdef.toml"), &config).unwrap();
    let floor = node.path("state").join(FLOOR_FILE);

    // Its listener's address is taken: it does not start.
    let failed = up_locked(&node).unwrap_err();
    assert!(failed.contains("binding the MCP listener"), "{failed}");
    assert!(!floor.exists(), "{failed}");

    drop(taken);
    let ready = up_locked(&node).unwrap();
    assert!(ready.contains(" · bundle r1 · "), "{ready}");
    let raised: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&floor).unwrap()).unwrap();
    assert_eq!(raised["revision"], 1);
}

/// `mcpdef filter --bundle-trust`: held to its bundle as `up` is, as it
/// starts, the one time it reads its config.
#[cfg(unix)]
#[test]
fn filter_with_bundle_trust_runs_only_a_config_a_bundle_holds() {
    let node = Node::new();
    let config = "[gateway]\naudit = \"./audit/audit.log\"\nstate_dir = \"./state\"\n\n\
                  [gateway.filter]\nlisten = \"127.0.0.1:0\"\n\n\
                  [[server]]\nid = \"github\"\ntransport = \"streamable-http\"\n\
                  url = \"http://127.0.0.1:9/mcp\"\nfilter_path = \"/github\"\ntools = [\"list_*\"]\n";
    std::fs::write(node.path("mcpdef.toml"), config).unwrap();
    let plain = locked(&node, "filter").unwrap_err();
    assert!(plain.contains("there is no mcpdef.toml.bundle"), "{plain}");

    // Carried in, not applied: the filter raises the floor as it starts.
    node.sign(config, 1, "r1.bundle");
    std::fs::copy(node.path("r1.bundle"), node.path("mcpdef.toml.bundle")).unwrap();
    let ready = locked(&node, "filter").unwrap();
    assert!(
        ready.contains(" filter ready ") && ready.contains(" · bundle r1 · "),
        "{ready}"
    );
    let floor = std::fs::read_to_string(node.path("state").join(FLOOR_FILE)).unwrap();
    let floor: serde_json::Value = serde_json::from_str(&floor).unwrap();
    assert_eq!(floor["revision"], 1);

    // Widened by hand since: it does not start.
    std::fs::write(node.path("mcpdef.toml"), config.replace("list_*", "*")).unwrap();
    let edited = locked(&node, "filter").unwrap_err();
    assert!(
        edited.contains("mcpdef.toml is not the config that mcpdef.toml.bundle, revision 1, holds"),
        "{edited}"
    );
}

/// A Claude Code `PreToolUse` event for `tool`.
fn hook_event(tool: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {},
    })
    .to_string()
}

impl Node {
    /// `mcpdef hook` as Claude Code runs it, from a project directory of its
    /// own, with `event` on standard input: `Ok` for no answer, so the client
    /// goes on with the call; or the refusal, with exit status 2, which blocks
    /// it.
    fn hook(&self, lock: &[&str], event: &str) -> Result<(), String> {
        self.hook_with(lock, &[], event)
    }

    /// [`Node::hook`], in an environment with `env` too.
    fn hook_with(&self, lock: &[&str], env: &[(&str, &str)], event: &str) -> Result<(), String> {
        use std::io::Write as _;
        use std::process::Stdio;
        let project = self.path("project");
        std::fs::create_dir_all(&project).unwrap();
        let mut hook = Command::new(BIN)
            .args(["hook", "--config", "../mcpdef.toml"])
            .args(lock)
            .env_remove("MCPDEF_BUNDLE_TRUST")
            .envs(env.iter().copied())
            .current_dir(&project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        hook.stdin
            .take()
            .unwrap()
            .write_all(event.as_bytes())
            .unwrap();
        let out = hook.wait_with_output().unwrap();
        match out.status.code() {
            Some(0) => {
                assert!(out.stdout.is_empty(), "{}", said(&out));
                Ok(())
            }
            Some(2) => {
                let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                let answer = &answer["hookSpecificOutput"];
                assert_eq!(answer["permissionDecision"], "deny", "{answer}");
                Err(answer["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .to_string())
            }
            _ => panic!("{}", said(&out)),
        }
    }
}

/// `mcpdef hook --bundle-trust`: each call's hook reads the config afresh,
/// so each call is held as a gateway's start is. A config no bundle holds
/// refuses every MCP call, and records nothing in the ledger it names; one a
/// bundle carried in holds is judged, and raises the floor; one changed by
/// hand since, or an older bundle put back, refuses each call again.
#[test]
fn hook_with_bundle_trust_judges_only_by_a_config_a_bundle_holds() {
    let node = Node::new();
    // Named from where the hook runs, as the config is.
    let lock = ["--bundle-trust", "../keys.json"];
    let (echo, delete) = (
        hook_event("mcp__mock__echo"),
        hook_event("mcp__mock__delete_repo"),
    );
    let one = policy("[\"echo\"]");
    std::fs::write(node.path("mcpdef.toml"), &one).unwrap();
    let refused = node.hook(&lock, &echo).unwrap_err();
    assert!(
        refused.starts_with("MCPdef denied (bundle-unverified): ")
            && refused.contains("there is no ")
            && refused.contains("mcpdef.toml.bundle"),
        "{refused}"
    );
    // What is no MCP tool call is not MCPdef's, held or not.
    assert_eq!(node.hook(&lock, &hook_event("Bash")), Ok(()));
    assert!(!node.path("audit").exists());

    // Carried in with its config, not applied: judged, and the floor raised.
    node.sign(&one, 1, "r1.bundle");
    std::fs::copy(node.path("r1.bundle"), node.path("mcpdef.toml.bundle")).unwrap();
    assert_eq!(node.hook(&lock, &echo), Ok(()));
    let refused = node.hook(&lock, &delete).unwrap_err();
    assert!(
        refused.starts_with("MCPdef denied (not-on-allowlist): "),
        "{refused}"
    );
    let floor: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(node.path("state").join(FLOOR_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(floor["revision"], 1);

    // Widened by hand, as an agent with a tool that writes files could: the
    // call it would let through is refused, unless the hook is not held.
    std::fs::write(node.path("mcpdef.toml"), policy("[\"*\"]")).unwrap();
    let refused = node.hook(&lock, &delete).unwrap_err();
    assert!(
        refused.starts_with("MCPdef denied (bundle-unverified): ")
            && refused.contains("mcpdef.toml is not the config that ")
            && refused.contains("mcpdef.toml.bundle, revision 1, holds"),
        "{refused}"
    );
    // The keys come from the environment as well as from the flag.
    let refused = node
        .hook_with(&[], &[("MCPDEF_BUNDLE_TRUST", "../keys.json")], &delete)
        .unwrap_err();
    assert!(
        refused.starts_with("MCPdef denied (bundle-unverified): "),
        "{refused}"
    );
    // Not held, the hook judges the config as it is.
    assert_eq!(node.hook(&[], &delete), Ok(()));

    // Revision 2 applied, then revision 1 put back with its config: older
    // than the floor.
    node.sign(&policy("[\"echo\", \"list\"]"), 2, "r2.bundle");
    let applied = node.apply("r2.bundle");
    assert!(applied.status.success(), "{}", said(&applied));
    assert_eq!(node.hook(&lock, &echo), Ok(()));
    std::fs::write(node.path("mcpdef.toml"), &one).unwrap();
    std::fs::copy(node.path("r1.bundle"), node.path("mcpdef.toml.bundle")).unwrap();
    let refused = node.hook(&lock, &echo).unwrap_err();
    assert!(
        refused.starts_with("MCPdef denied (bundle-older): ")
            && refused.contains("revision 1 is older than revision 2"),
        "{refused}"
    );

    // Recorded: the calls judged, and the bundle applied. A call refused by
    // the lock is not: the ledger is a config's, and there was none to judge
    // by.
    let records = node.records();
    let seen: Vec<(Option<&str>, Option<&str>, &str)> = records
        .iter()
        .map(|r| (r.hook.as_deref(), r.tool.as_deref(), r.decision.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            (Some("claude-code"), Some("echo"), "allow"),
            (Some("claude-code"), Some("delete_repo"), "deny"),
            (Some("claude-code"), Some("delete_repo"), "allow"),
            (None, None, "allow"),
            (Some("claude-code"), Some("echo"), "allow"),
        ]
    );
}

/// `mcpdef hook install --bundle-trust`: the keys go into the hook by their
/// absolute path, as the config does, and a hook that would refuse every MCP
/// call, the config no bundle holds or one older than the floor, is not
/// written.
#[test]
fn hook_install_with_bundle_trust_writes_only_a_hook_that_judges() {
    let node = Node::new();
    let one = policy("[\"echo\"]");
    std::fs::write(node.path("mcpdef.toml"), &one).unwrap();
    let project = node.path("project");
    std::fs::create_dir_all(&project).unwrap();
    let install = || {
        Command::new(BIN)
            .args([
                "hook",
                "install",
                "--config",
                "../mcpdef.toml",
                "--bundle-trust",
                "../keys.json",
                "--write",
            ])
            .current_dir(&project)
            .output()
            .unwrap()
    };
    let settings = project.join(".claude/settings.local.json");

    let refused = install();
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("the hook would refuse every MCP call")
            && said(&refused).contains("there is no "),
        "{}",
        said(&refused)
    );
    assert!(!settings.exists());

    node.sign(&one, 1, "r1.bundle");
    assert!(node.apply("r1.bundle").status.success());
    let wrote = install();
    assert!(wrote.status.success(), "{}", said(&wrote));
    assert!(
        said(&wrote).contains("the signed bundle beside it holds it, revision 1 now"),
        "{}",
        said(&wrote)
    );
    let hooks: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let keys = std::fs::canonicalize(node.path("keys.json")).unwrap();
    assert!(
        command.ends_with(&format!(" --bundle-trust {}", keys.display())),
        "{command}"
    );

    // Revision 2 applied, then revision 1 put back: older than the floor.
    node.sign(&policy("[\"echo\", \"list\"]"), 2, "r2.bundle");
    assert!(node.apply("r2.bundle").status.success());
    std::fs::write(node.path("mcpdef.toml"), &one).unwrap();
    std::fs::copy(node.path("r1.bundle"), node.path("mcpdef.toml.bundle")).unwrap();
    let before = std::fs::read_to_string(&settings).unwrap();
    let refused = install();
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("revision 1 is older than revision 2"),
        "{}",
        said(&refused)
    );
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), before);
}
