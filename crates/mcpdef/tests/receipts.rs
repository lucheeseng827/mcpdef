// SPDX-License-Identifier: Apache-2.0
//! `mcpdef receipts`: a key made, its public half published, a ledger signed
//! as receipts, and the receipts checked, all through the real binary.

use mcpdef_audit::{Attrs, Entry, Ledger};
use mcpdef_core::Decision;
use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");

fn mcpdef(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A ledger of two tool calls, one allowed and one refused, and a read that
/// is not a tool call.
fn ledger(path: &Path) {
    let mut led = Ledger::open(path).unwrap();
    let call = |tool: &str, decision: Decision| Entry {
        agent: "agent:test".into(),
        server: "github".into(),
        method: Some("tools/call".into()),
        tool: Some(tool.into()),
        decision,
        latency_ms: 1,
        attrs: Attrs::default(),
    };
    led.append(call("list_issues", Decision::Allow)).unwrap();
    let mut read = call("x", Decision::Allow);
    (read.method, read.tool) = (Some("resources/read".into()), None);
    led.append(read).unwrap();
    led.append(call(
        "delete_repo",
        Decision::Deny {
            rule: "tools.deny".into(),
            reason: "not on the list".into(),
        },
    ))
    .unwrap();
}

#[test]
fn a_ledger_signed_as_receipts_verifies_with_the_published_key() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let made = mcpdef(d, &["receipts", "key", "--out", "k.jwk"]);
    assert!(made.status.success(), "{}", text(&made.stderr));
    assert!(
        text(&made.stderr).contains("named sb:issuer:"),
        "{}",
        text(&made.stderr)
    );
    let key = std::fs::read_to_string(d.join("k.jwk")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(d.join("k.jwk"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a key is its owner's alone");
    }
    let again = mcpdef(d, &["receipts", "key", "--out", "k.jwk"]);
    assert!(!again.status.success());
    assert!(
        text(&again.stderr).contains("never replaced"),
        "{}",
        text(&again.stderr)
    );
    assert_eq!(std::fs::read_to_string(d.join("k.jwk")).unwrap(), key);

    let jwks = mcpdef(d, &["receipts", "jwks", "--key", "k.jwk"]);
    assert!(jwks.status.success(), "{}", text(&jwks.stderr));
    let public: serde_json::Value = serde_json::from_slice(&jwks.stdout).unwrap();
    assert_eq!(public["keys"][0]["kty"], "OKP");
    assert!(public["keys"][0].get("d").is_none(), "the public half only");
    std::fs::write(d.join("keys.json"), &jwks.stdout).unwrap();

    ledger(&d.join("audit.log"));
    let export = |force: bool| {
        let mut args = vec![
            "receipts",
            "export",
            "--key",
            "k.jwk",
            "--path",
            "audit.log",
            "--out",
            "receipts.jsonl",
        ];
        if force {
            args.push("--force");
        }
        mcpdef(d, &args)
    };
    let exported = export(false);
    let stderr = text(&exported.stderr);
    assert!(exported.status.success(), "{stderr}");
    assert!(
        stderr.contains("signed 2 receipt(s), for the tool calls among 3 record(s)"),
        "{stderr}"
    );
    let receipts = std::fs::read_to_string(d.join("receipts.jsonl")).unwrap();
    assert_eq!(receipts.lines().count(), 2);
    assert!(receipts.contains("\"tool_name\":\"delete_repo\""));

    let refused = export(false);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("--force"),
        "{}",
        text(&refused.stderr)
    );
    assert!(export(true).status.success());
    assert_eq!(
        std::fs::read_to_string(d.join("receipts.jsonl")).unwrap(),
        receipts,
        "the same ledger and key sign the same"
    );

    let verified = mcpdef(
        d,
        &[
            "receipts",
            "verify",
            "receipts.jsonl",
            "--jwks",
            "keys.json",
        ],
    );
    let stdout = text(&verified.stdout);
    assert!(verified.status.success(), "{}", text(&verified.stderr));
    assert!(
        stdout.contains("receipts OK · 2 receipt(s) · 1 chain(s) · last=sha256:"),
        "{stdout}"
    );
    let last = stdout.trim().rsplit("last=").next().unwrap().to_string();

    // A seal recorded elsewhere: what it says, and one receipt more than there is.
    let sealed = mcpdef(
        d,
        &[
            "receipts",
            "verify",
            "receipts.jsonl",
            "--jwks",
            "keys.json",
            "--last",
            &last,
            "--count",
            "2",
        ],
    );
    assert!(sealed.status.success(), "{}", text(&sealed.stderr));
    let short = mcpdef(
        d,
        &[
            "receipts",
            "verify",
            "receipts.jsonl",
            "--jwks",
            "keys.json",
            "--last",
            &last,
            "--count",
            "3",
        ],
    );
    assert!(!short.status.success());
    assert!(
        text(&short.stderr).contains("do NOT match the seal"),
        "{}",
        text(&short.stderr)
    );

    std::fs::write(
        d.join("changed.jsonl"),
        receipts.replacen("\"allow\"", "\"deny\"", 1),
    )
    .unwrap();
    let changed = mcpdef(
        d,
        &["receipts", "verify", "changed.jsonl", "--jwks", "keys.json"],
    );
    assert!(!changed.status.success());
    assert!(
        text(&changed.stderr).contains("BROKEN at line 1: its signature does not verify"),
        "{}",
        text(&changed.stderr)
    );
}

#[test]
fn a_ledger_whose_chain_is_broken_is_not_signed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert!(mcpdef(d, &["receipts", "key", "--out", "k.jwk"])
        .status
        .success());
    ledger(&d.join("audit.log"));
    let edited = std::fs::read_to_string(d.join("audit.log"))
        .unwrap()
        .replace("delete_repo", "delete_rep0");
    std::fs::write(d.join("audit.log"), edited).unwrap();
    let out = mcpdef(
        d,
        &[
            "receipts",
            "export",
            "--key",
            "k.jwk",
            "--path",
            "audit.log",
            "--out",
            "r.jsonl",
        ],
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("broken at seq 2"),
        "{}",
        text(&out.stderr)
    );
    assert!(!d.join("r.jsonl").exists(), "nothing was written");
    let partial = std::fs::read_dir(d)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".mcpdef-receipts-")
        });
    assert!(!partial, "and nothing was left half-written");

    // Nor to standard output: the receipts signed before the break reach no one.
    let to_stdout = mcpdef(
        d,
        &[
            "receipts",
            "export",
            "--key",
            "k.jwk",
            "--path",
            "audit.log",
        ],
    );
    assert!(!to_stdout.status.success());
    assert!(to_stdout.stdout.is_empty(), "{}", text(&to_stdout.stdout));
}

/// A seal the ledger does not end at: the receipts of every record before it
/// verify, and still none are written.
#[test]
fn a_ledger_that_does_not_match_its_seal_is_not_signed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert!(mcpdef(d, &["receipts", "key", "--out", "k.jwk"])
        .status
        .success());
    ledger(&d.join("audit.log"));
    let head = mcpdef_audit::verify(d.join("audit.log")).unwrap().head;
    let sealed = |count: &str| {
        mcpdef(
            d,
            &[
                "receipts",
                "export",
                "--key",
                "k.jwk",
                "--path",
                "audit.log",
                "--head",
                &head,
                "--count",
                count,
            ],
        )
    };
    let matching = sealed("3");
    assert!(matching.status.success(), "{}", text(&matching.stderr));
    assert_eq!(text(&matching.stdout).lines().count(), 2);
    let longer = sealed("4");
    assert!(!longer.status.success());
    assert!(longer.stdout.is_empty(), "{}", text(&longer.stdout));
    assert!(
        text(&longer.stderr).contains("the seal 4"),
        "{}",
        text(&longer.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_key_others_can_read_is_named() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert!(mcpdef(d, &["receipts", "key", "--out", "k.jwk"])
        .status
        .success());
    std::fs::set_permissions(d.join("k.jwk"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = mcpdef(d, &["receipts", "jwks", "--key", "k.jwk"]);
    assert!(out.status.success());
    assert!(
        text(&out.stderr).contains("chmod 600"),
        "{}",
        text(&out.stderr)
    );
}
