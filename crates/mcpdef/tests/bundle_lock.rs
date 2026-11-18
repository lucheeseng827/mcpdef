// SPDX-License-Identifier: Apache-2.0
//! `--bundle-trust`: a gateway that runs only the config the signed bundle
//! beside it holds. A config changed in place, a bundle no trusted key signed
//! and an older bundle put back are each refused at a reload, and audited
//! with the bundle that was beside the config, while the gateway keeps
//! serving what it had. A newer bundle is taken, applied or carried in, and
//! the node's floor goes up with it.

use mcpdef::bundle::{self, Bundle, Floor, KID_PREFIX};
use mcpdef::connect::build_gateway;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::Gateway;
use mcpdef_audit::receipt::{Keys, SigningKey};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A node: its config, the ledger and state beside it, and the key its
/// bundles are signed with.
struct Node {
    dir: tempfile::TempDir,
    key: SigningKey,
}

impl Node {
    fn new() -> Node {
        let jwk = SigningKey::generate_named(KID_PREFIX).unwrap();
        Node {
            dir: tempfile::tempdir().unwrap(),
            key: SigningKey::from_jwk(&jwk).unwrap(),
        }
    }

    fn keys(&self) -> Keys {
        Keys::from_jwks(&self.key.jwks().to_string()).unwrap()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn config_path(&self) -> PathBuf {
        self.path("mcpdef.toml")
    }

    fn state(&self) -> PathBuf {
        self.path("state")
    }

    /// A config whose one server is allowed `tools`, with `gateway` added
    /// to its `[gateway]` table.
    fn config(&self, gateway: &str, tools: &[&str]) -> String {
        format!(
            "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {:?}\nstate_dir = {:?}\n{gateway}\n\n\
             [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = {tools:?}\n",
            self.path("audit.log"),
            self.state(),
        )
    }

    /// `config` signed at `revision` with the node's key, as `r<revision>.bundle`.
    fn sign(&self, config: &str, revision: u64) -> PathBuf {
        let path = self.path(&format!("r{revision}.bundle"));
        let signed = bundle::sign(config, revision, &bundle::now(), &self.key).unwrap();
        std::fs::write(&path, signed).unwrap();
        path
    }

    /// What `mcpdef bundle apply` does.
    fn apply(&self, bundle: &Path) {
        bundle::apply(bundle, &self.keys(), &self.config_path()).unwrap();
    }

    /// The bundle at `bundle`, and its config, put in place by hand, as an
    /// image or a config map carries them in: no apply, no floor raised.
    fn carry_in(&self, bundle: &Path) {
        let text = std::fs::read_to_string(bundle).unwrap();
        let config: serde_json::Value = serde_json::from_str(&text).unwrap();
        std::fs::write(bundle::beside(&self.config_path()), &text).unwrap();
        std::fs::write(self.config_path(), config["config"].as_str().unwrap()).unwrap();
    }

    fn floor(&self) -> Option<u64> {
        Floor::read(&self.state()).unwrap().map(|f| f.revision)
    }

    /// The gateway's reload records in the ledger, not those of an apply.
    fn reloads(&self) -> Vec<Record> {
        std::fs::read_to_string(self.path("audit.log"))
            .unwrap_or_default()
            .lines()
            // A record the gateway is still writing is not one yet.
            .filter_map(|l| serde_json::from_str::<Record>(l).ok())
            .filter(|r| {
                r.kind.as_deref() == Some("reload") && r.method.as_deref() == Some("reload")
            })
            .collect()
    }

    /// A gateway started from the config as `mcpdef up --bundle-trust` starts
    /// one, and its reloader.
    async fn start(&self) -> (Gateway, Reloader, Bundle) {
        let path = self.config_path();
        let admitted = bundle::admit(&path, &self.keys()).unwrap();
        assert_eq!(admitted.config.validate(), Vec::<String>::new());
        let snapshot = Snapshot::take(admitted.text.as_bytes(), &admitted.config);
        let gw = build_gateway(&admitted.config).await.unwrap();
        // Raised once nothing can stop the start.
        let state = PathBuf::from(&admitted.config.gateway.state_dir);
        bundle::holding(&path, || bundle::raise(&state, &admitted.bundle)).unwrap();
        let reloader = Reloader::new(&path, None, gw.clone(), admitted.config, snapshot)
            .with_bundle_lock(self.keys(), admitted.bundle.clone());
        (gw, reloader, admitted.bundle)
    }
}

async fn echo(gw: &Gateway, tool: &str) -> String {
    let request = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": {} })),
    );
    let reply = gw.handle(request).await.unwrap().expect("a reply");
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn refused(outcome: &Outcome) -> (&'static str, &str) {
    match outcome {
        Outcome::Refused { rule, reasons } => (*rule, reasons[0].as_str()),
        Outcome::Applied(report) => panic!("applied: {report:?}"),
    }
}

/// Each reload record's decision, rule, and the revision its `bundle` names.
fn told(records: &[Record]) -> Vec<(String, Option<String>, Option<u64>)> {
    records
        .iter()
        .map(|r| {
            let bundle = r.bundle.as_ref();
            assert!(bundle.is_some(), "{r:?}");
            (
                r.decision.clone(),
                r.rule.clone(),
                bundle.and_then(|b| b.revision),
            )
        })
        .collect()
}

async fn eventually(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done()
}

#[tokio::test]
async fn only_a_config_a_bundle_holds_is_reloaded_and_never_an_older_one() {
    let node = Node::new();
    let one = node.config("", &["echo"]);
    let r1 = node.sign(&one, 1);
    node.apply(&r1);
    let (gw, mut reloader, running) = node.start().await;
    assert_eq!(running.revision, 1);
    let serving = reloader.digest().to_string();

    // Changed in place: what no key signed.
    let widened = node.config("", &["echo", "delete_repo"]);
    std::fs::write(node.config_path(), &widened).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    let (rule, why) = refused(&outcome);
    assert_eq!(rule, "bundle-unverified");
    assert!(
        why.contains("is not the config that") && why.contains(", revision 1, holds"),
        "{why}"
    );
    assert!(echo(&gw, "delete_repo")
        .await
        .contains("is not on the allowlist"));
    assert_eq!(reloader.digest(), serving);

    // Signed and applied: taken.
    let two = node.config("", &["echo", "delete_repo"]);
    node.apply(&node.sign(&two, 2));
    let outcome = reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    assert!(echo(&gw, "delete_repo").await.starts_with("delete_repo:"));
    let serving = reloader.digest().to_string();

    // The bundle before, put back with its config: older than the floor.
    node.carry_in(&r1);
    let outcome = reloader.reload(Trigger::Signal).await;
    let (rule, why) = refused(&outcome);
    assert_eq!(rule, "bundle-older");
    assert!(why.contains("revision 1 is older than revision 2"), "{why}");
    // Older than the one running too, with the floor gone.
    std::fs::remove_file(node.state().join(bundle::FLOOR_FILE)).unwrap();
    let (rule, _) = refused(&reloader.reload(Trigger::Signal).await);
    assert_eq!(rule, "bundle-older");

    // Signed by a key the node does not trust, with the config it holds.
    let stranger = SigningKey::from_jwk(&SigningKey::generate_named(KID_PREFIX).unwrap()).unwrap();
    let three = node.config("", &["delete_repo"]);
    let forged = bundle::sign(&three, 3, &bundle::now(), &stranger).unwrap();
    std::fs::write(bundle::beside(&node.config_path()), forged).unwrap();
    std::fs::write(node.config_path(), &three).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    let (rule, why) = refused(&outcome);
    assert_eq!(rule, "bundle-unverified");
    let beside = bundle::beside(&node.config_path());
    assert!(why.starts_with(&format!("{}: ", beside.display())), "{why}");
    assert!(echo(&gw, "echo").await.starts_with("echo:"));
    assert_eq!(reloader.digest(), serving);

    // Each audited with the bundle beside the config: its revision once its
    // signature verified.
    let s = |text: &str| Some(text.to_string());
    assert_eq!(
        told(&node.reloads()),
        [
            ("deny".into(), s("bundle-unverified"), Some(1)),
            ("allow".into(), None, Some(2)),
            ("deny".into(), s("bundle-older"), Some(1)),
            ("deny".into(), s("bundle-older"), Some(1)),
            ("deny".into(), s("bundle-unverified"), None),
        ]
    );
}

#[tokio::test]
async fn a_bundle_carried_in_raises_the_floor_once_it_runs() {
    let node = Node::new();
    node.carry_in(&node.sign(&node.config("", &["echo"]), 5));
    assert_eq!(node.floor(), None);
    let (_gw, mut reloader, _) = node.start().await;
    assert_eq!(node.floor(), Some(5), "raised as it starts");

    node.carry_in(&node.sign(&node.config("", &["echo", "list"]), 6));
    let outcome = reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    assert_eq!(node.floor(), Some(6));

    // Refused for what else it changes: it does not run, so the floor stays.
    let moved = node
        .config("", &["echo"])
        .replace("127.0.0.1:0", "127.0.0.1:1");
    node.carry_in(&node.sign(&moved, 7));
    let (rule, _) = refused(&reloader.reload(Trigger::Signal).await);
    assert_eq!(rule, "restart-required");
    assert_eq!(node.floor(), Some(6));

    // A gateway started again runs no bundle below it.
    node.carry_in(&node.path("r5.bundle"));
    let older = bundle::admit(&node.config_path(), &node.keys()).unwrap_err();
    assert!(
        format!("{older:#}").contains("revision 5 is older than revision 6"),
        "{older:#}"
    );
}

#[tokio::test]
async fn the_watch_sees_a_bundle_that_changed_beside_a_config_that_did_not() {
    let node = Node::new();
    let config = node.config("watch_config = true", &["echo"]);
    node.apply(&node.sign(&config, 1));
    let (_gw, reloader, _) = node.start().await;
    let watching = tokio::spawn(reloader.run(Duration::from_millis(50)));

    // The same config, signed again at a new revision.
    node.apply(&node.sign(&config, 2));
    assert!(eventually(Duration::from_secs(10), || node.reloads().len() == 1).await);
    // A bundle beside it that does not verify: refused once, not every check.
    std::fs::write(bundle::beside(&node.config_path()), "{}").unwrap();
    assert!(eventually(Duration::from_secs(10), || node.reloads().len() == 2).await);
    tokio::time::sleep(Duration::from_millis(400)).await;
    watching.abort();
    let records = node.reloads();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(
        (records[0].decision.as_str(), records[0].actor.as_deref()),
        ("allow", Some("watch"))
    );
    assert_eq!(records[0].bundle.as_ref().and_then(|b| b.revision), Some(2));
    assert_eq!(
        records[0].config_from, records[0].config_to,
        "the same config"
    );
    assert_eq!(records[1].rule.as_deref(), Some("bundle-unverified"));
}
