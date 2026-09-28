// SPDX-License-Identifier: Apache-2.0
//! Ledgers written by earlier releases keep verifying, byte for byte.
//!
//! - `fixtures/ledger-0.2.1.jsonl` was written through the HTTP listener of an
//!   `mcpdef 0.2.1` build, whose audit code is the 0.2.1 release's. It holds every
//!   record shape that gateway writes: an allowed and a denied call, an unknown
//!   tool, and a forwarded method with no tool. It also holds caller-chosen tool
//!   names carrying a quote, a backslash, non-ASCII, CR/LF and a raw U+001F (seq 6).
//! - `fixtures/readme-example.jsonl` is the two-record example in the README.

use mcpdef_audit::{verify, Entry, ExportFormat, Ledger, Record};
use mcpdef_core::Decision;
use std::path::{Path, PathBuf};

const HEAD_0_2_1: &str = "3123105e204e1fe4d458de731b426d850ab354936a93afee6d3795eea7c23582";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A scratch copy of a fixture, for tests that append to it or edit it.
fn copy_of(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::copy(fixture(name), &path).unwrap();
    (dir, path)
}

#[test]
fn a_0_2_1_ledger_still_verifies() {
    let report = verify(fixture("ledger-0.2.1.jsonl")).unwrap();
    assert!(report.ok(), "broken at {:?}", report.broken_at);
    assert_eq!(report.records, 8);
    assert_eq!(report.head, HEAD_0_2_1);
}

#[test]
fn its_records_serialize_back_byte_for_byte() {
    let text = std::fs::read_to_string(fixture("ledger-0.2.1.jsonl")).unwrap();
    for line in text.lines() {
        let rec: Record = serde_json::from_str(line).unwrap();
        assert_eq!(rec.export(ExportFormat::Json), line);
    }
}

#[test]
fn the_readme_example_verifies() {
    let report = verify(fixture("readme-example.jsonl")).unwrap();
    assert!(report.ok());
    assert_eq!(report.records, 2);
}

#[test]
fn a_gateway_resumes_the_chain_of_a_0_2_1_ledger() {
    let (_dir, path) = copy_of("ledger-0.2.1.jsonl");
    let mut led = Ledger::open(&path).unwrap();
    assert_eq!(led.head(), HEAD_0_2_1);
    assert_eq!(led.next_seq(), 8);
    let rec = led
        .append(Entry {
            agent: "agent:test".into(),
            server: "s0".into(),
            method: Some("tools/call".into()),
            tool: Some("echo".into()),
            decision: Decision::Allow,
            latency_ms: 1,
        })
        .unwrap();
    assert_eq!(rec.prev_hash, HEAD_0_2_1);
    let report = verify(&path).unwrap();
    assert!(report.ok());
    assert_eq!(report.records, 9);
}

/// Record 6 denied the crafted tool name `x<U+001F>allow`. The v1 hash joins the
/// fields with U+001F, so the same bytes also read as an *allowed* call to `x`
/// with the rule `deny<U+001F>unknown-tool`. That edit keeps the chain intact,
/// which is why `verify` reports the record instead of vouching for its fields.
#[test]
fn an_old_record_with_the_separator_is_reported() {
    let report = verify(fixture("ledger-0.2.1.jsonl")).unwrap();
    assert_eq!(report.ambiguous, vec![6]);

    let (_dir, path) = copy_of("ledger-0.2.1.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut rec: Record = serde_json::from_str(&lines[6]).unwrap();
    assert_eq!(rec.decision, "deny");
    rec.tool = Some("x".into());
    rec.decision = "allow".into();
    rec.rule = Some("deny\u{1f}unknown-tool".into());
    lines[6] = serde_json::to_string(&rec).unwrap();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let report = verify(&path).unwrap();
    assert!(report.ok(), "the v1 encoding cannot see this edit");
    assert_eq!(report.ambiguous, vec![6], "but the record stays flagged");
}

#[test]
fn a_new_record_never_holds_the_separator() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut led = Ledger::open(&path).unwrap();
    let rec = led
        .append(Entry {
            agent: "agent:a\u{1f}b".into(),
            server: "s\u{1f}0".into(),
            method: Some("tools/call\u{1f}".into()),
            tool: Some("x\u{1f}allow".into()),
            decision: Decision::Deny {
                rule: "r\u{1f}1".into(),
                reason: "x".into(),
            },
            latency_ms: 0,
        })
        .unwrap();
    assert_eq!(rec.tool.as_deref(), Some("x\u{241f}allow"));
    assert_eq!(rec.agent, "agent:a\u{241f}b");
    assert_eq!(rec.server, "s\u{241f}0");
    assert_eq!(rec.method.as_deref(), Some("tools/call\u{241f}"));
    assert_eq!(rec.rule.as_deref(), Some("r\u{241f}1"));

    let report = verify(&path).unwrap();
    assert!(report.ok());
    assert!(report.ambiguous.is_empty());
}
