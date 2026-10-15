// SPDX-License-Identifier: Apache-2.0
//! The members a record gained after v1 (`kind`, `uri`, `transforms`, `actor`,
//! `peer`): how they are written, what the hash covers, and what each export
//! carries.

use mcpdef_audit::{
    read_all, verify, Attrs, AuditError, Entry, ExportFormat, Kind, Ledger, Record, ToolChanges,
};
use mcpdef_core::Decision;
use serde_json::Value;
use std::path::{Path, PathBuf};

const LATER: [&str; 5] = ["kind", "uri", "transforms", "actor", "peer"];

fn full() -> Attrs {
    Attrs {
        kind: Kind::Admin,
        uri: Some("file:///etc/hosts".into()),
        transforms: vec!["clamp-limit".into(), "redact-secrets".into()],
        actor: Some("oidc:alice@example.com".into()),
        peer: Some("203.0.113.7:51234".into()),
        ..Attrs::default()
    }
}

fn entry(attrs: Attrs) -> Entry {
    Entry {
        agent: "sub:alice".into(),
        server: "files".into(),
        method: Some("resources/read".into()),
        tool: None,
        decision: Decision::Allow,
        latency_ms: 3,
        attrs,
    }
}

/// A ledger holding one record per `attrs`, in order.
fn ledger(attrs: Vec<Attrs>) -> (tempfile::TempDir, PathBuf, Vec<Record>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut led = Ledger::open(&path).unwrap();
    let records = attrs
        .into_iter()
        .map(|a| led.append(entry(a)).unwrap())
        .collect();
    (dir, path, records)
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

/// Rewrite line `n` through `edit`, which sees it as a JSON object.
fn edit_line(path: &Path, n: usize, edit: impl FnOnce(&mut serde_json::Map<String, Value>)) {
    let mut all = lines(path);
    let mut value: Value = serde_json::from_str(&all[n]).unwrap();
    edit(value.as_object_mut().unwrap());
    all[n] = value.to_string();
    std::fs::write(path, all.join("\n") + "\n").unwrap();
}

/// Insert `members` (raw JSON text, e.g. `"a":1,`) just after line `n`'s `{`.
fn splice_line(path: &Path, n: usize, members: &str) {
    let mut all = lines(path);
    all[n] = format!("{{{members}{}", &all[n][1..]);
    std::fs::write(path, all.join("\n") + "\n").unwrap();
}

#[test]
fn every_kind_and_member_is_written_and_verifies() {
    let attrs = vec![
        Attrs::default(),
        full(),
        Attrs {
            kind: Kind::Reload,
            ..Attrs::default()
        },
        Attrs {
            kind: Kind::Upstream,
            peer: Some("[2001:db8::1]:443".into()),
            ..Attrs::default()
        },
    ];
    let (_dir, path, written) = ledger(attrs);
    let report = verify(&path).unwrap();
    assert!(report.ok(), "broken at {:?}", report.broken_at);

    let back = read_all(&path).unwrap();
    assert_eq!(back, written);
    let kinds: Vec<Option<&str>> = back.iter().map(|r| r.kind.as_deref()).collect();
    assert_eq!(
        kinds,
        [None, Some("admin"), Some("reload"), Some("upstream")]
    );
    assert_eq!(
        back[1].transforms.as_deref(),
        Some(&["clamp-limit".to_string(), "redact-secrets".to_string()][..])
    );
    assert_eq!(back[1].actor.as_deref(), Some("oidc:alice@example.com"));

    // A plain call carries none of them: its line is v1-shaped.
    let first = &lines(&path)[0];
    for member in LATER {
        assert!(
            !first.contains(&format!("\"{member}\"")),
            "{member} in {first}"
        );
    }
}

#[test]
fn an_empty_transform_list_records_nothing() {
    let (_dir, path, written) = ledger(vec![Attrs {
        transforms: Vec::new(),
        ..Attrs::default()
    }]);
    assert_eq!(written[0].transforms, None);
    assert!(!lines(&path)[0].contains("transforms"));
}

#[test]
fn deleting_any_later_member_breaks_the_chain() {
    for member in LATER {
        let (_dir, path, _) = ledger(vec![Attrs::default(), full(), Attrs::default()]);
        edit_line(&path, 1, |r| {
            r.remove(member).expect("present");
        });
        let report = verify(&path).unwrap();
        assert_eq!(report.broken_at, Some(1), "deleting {member}");
    }
}

/// An edit to one line, seen as a JSON object.
type Edit = fn(&mut serde_json::Map<String, Value>);

#[test]
fn adding_or_changing_a_later_member_breaks_the_chain() {
    let edits: [(&str, usize, Edit); 4] = [
        ("add uri to a plain call", 0, |r| {
            r.insert("uri".into(), "file:///etc/shadow".into());
        }),
        ("change actor", 1, |r| {
            r.insert("actor".into(), "oidc:mallory@example.com".into());
        }),
        ("reorder transforms", 1, |r| {
            r.insert(
                "transforms".into(),
                serde_json::json!(["redact-secrets", "clamp-limit"]),
            );
        }),
        ("add a member no release knows", 1, |r| {
            r.insert("approved_by".into(), "mallory".into());
        }),
    ];
    for (what, n, edit) in edits {
        let (_dir, path, _) = ledger(vec![Attrs::default(), full()]);
        edit_line(&path, n, edit);
        assert_eq!(verify(&path).unwrap().broken_at, Some(n as u64), "{what}");
    }
}

#[test]
fn member_order_within_a_line_does_not_matter() {
    let (_dir, path, _) = ledger(vec![full()]);
    let original = lines(&path)[0].clone();
    let value: Value = serde_json::from_str(&original).unwrap();
    let reversed: Vec<String> = value
        .as_object()
        .unwrap()
        .iter()
        .rev()
        .map(|(name, member)| format!("{}:{member}", Value::from(name.as_str())))
        .collect();
    let reordered = format!("{{{}}}", reversed.join(","));
    assert_ne!(reordered, original);
    std::fs::write(&path, reordered + "\n").unwrap();
    assert!(verify(&path).unwrap().ok());
}

/// Values are JSON-encoded in the hash, so no value can pose as a member. A
/// plain `key=value` encoding would let this `uri` split into a `uri` and an
/// `actor` with the hash unchanged.
#[test]
fn a_value_cannot_pose_as_another_member() {
    let crafted = [
        "file:///x\",\"actor\":\"admin",
        "file:///x\u{1f}actor=admin",
        "file:///x\u{1f}actor=\"admin\"",
    ];
    for uri in crafted {
        let (_dir, path, _) = ledger(vec![Attrs {
            uri: Some(uri.into()),
            ..Attrs::default()
        }]);
        assert!(verify(&path).unwrap().ok());
        edit_line(&path, 0, |r| {
            r.insert("uri".into(), "file:///x".into());
            r.insert("actor".into(), "admin".into());
        });
        assert_eq!(verify(&path).unwrap().broken_at, Some(0), "{uri:?}");
    }
}

#[test]
fn a_null_member_counts_as_absent() {
    let (_dir, path, _) = ledger(vec![Attrs::default()]);
    splice_line(&path, 0, r#""uri":null,"approved_by":null,"#);
    let report = verify(&path).unwrap();
    assert!(report.ok(), "null is the same as absent");
}

#[test]
fn a_member_named_twice_is_corrupt() {
    let twice = [
        r#""uri":"file:///a","uri":"file:///b","#,
        r#""approved_by":"carol","approved_by":"mallory","#,
        r#""approval":{"by":"carol","by":"mallory"},"#,
        r#""approvals":[{"by":"carol","by":"mallory"}],"#,
    ];
    for members in twice {
        let (_dir, path, _) = ledger(vec![Attrs::default()]);
        splice_line(&path, 0, members);
        let err = verify(&path).expect_err(members);
        assert!(
            matches!(&err, AuditError::Corrupt { detail, .. } if detail.contains("duplicate field")),
            "{members}: {err}"
        );
        assert!(read_all(&path).is_err(), "{members}");
        assert!(Ledger::open(&path).is_err(), "{members}");
    }
}

#[test]
fn ocsf_carries_the_later_members() {
    let (_dir, _path, written) = ledger(vec![full(), Attrs::default()]);
    let v: Value = serde_json::from_str(&written[0].export(ExportFormat::Ocsf)).unwrap();
    assert_eq!(
        v["src_endpoint"],
        serde_json::json!({ "ip": "203.0.113.7", "port": 51234 })
    );
    assert_eq!(
        v["resources"],
        serde_json::json!([{ "uid": "file:///etc/hosts" }])
    );
    let unmapped = &v["unmapped"];
    assert_eq!(unmapped["kind"], "admin");
    assert_eq!(unmapped["uri"], "file:///etc/hosts");
    assert_eq!(unmapped["actor"], "oidc:alice@example.com");
    assert_eq!(unmapped["peer"], "203.0.113.7:51234");
    assert_eq!(
        unmapped["transforms"],
        serde_json::json!(["clamp-limit", "redact-secrets"])
    );

    // A plain call gains nothing.
    let plain: Value = serde_json::from_str(&written[1].export(ExportFormat::Ocsf)).unwrap();
    assert!(plain.get("src_endpoint").is_none() && plain.get("resources").is_none());
    for member in LATER {
        assert!(plain["unmapped"].get(member).is_none(), "{member}");
    }

    // A member this release does not know rides along in `unmapped`.
    let mut later = written[1].clone();
    later.extra = serde_json::from_value(serde_json::json!({ "config": "sha256:abc" })).unwrap();
    let v: Value = serde_json::from_str(&later.export(ExportFormat::Ocsf)).unwrap();
    assert_eq!(v["unmapped"]["config"], "sha256:abc");
}

#[test]
fn cef_carries_the_later_members() {
    let (_dir, _path, written) = ledger(vec![full()]);
    let c = written[0].export(ExportFormat::Cef);
    for part in [
        " cs3Label=kind cs3=admin",
        " cs4Label=actor cs4=oidc:alice@example.com",
        r#" cs5Label=transforms cs5=["clamp-limit","redact-secrets"]"#,
        " request=file:///etc/hosts",
        " src=203.0.113.7 spt=51234",
    ] {
        assert!(c.contains(part), "{part:?} missing from {c}");
    }

    let peers = [
        (
            "[2001:db8::1]:443",
            " c6a2Label=Source IPv6 Address c6a2=2001:db8::1 spt=443",
            true,
        ),
        ("203.0.113.7", " src=203.0.113.7", false),
        ("proxy.internal", " shost=proxy.internal", false),
    ];
    for (peer, part, has_port) in peers {
        let (_dir, _path, written) = ledger(vec![Attrs {
            peer: Some(peer.into()),
            ..Attrs::default()
        }]);
        let c = written[0].export(ExportFormat::Cef);
        assert!(c.contains(part), "{peer}: {part:?} missing from {c}");
        assert_eq!(c.contains(" spt="), has_port, "{peer}: {c}");
    }
}

#[test]
fn syslog_carries_the_later_members() {
    let (_dir, _path, written) = ledger(vec![full()]);
    let s = written[0].export(ExportFormat::Syslog);
    let part = r#" latencyMs="3" kind="admin" uri="file:///etc/hosts" actor="oidc:alice@example.com" peer="203.0.113.7:51234" transforms="[\"clamp-limit\",\"redact-secrets\"\]" hash=""#;
    assert!(s.contains(part), "{part:?} missing from {s}");
}

/// The CWE-117 guard covers the later members: CR/LF cannot split a CEF or
/// syslog line, and each format's own delimiters are escaped.
#[test]
fn the_later_members_cannot_split_a_siem_line() {
    let (_dir, _path, written) = ledger(vec![Attrs {
        kind: Kind::Call,
        uri: Some("file:///x\r\nCEF:0|forged|\"] [fake@0 a=\"b\"]".into()),
        transforms: vec!["t\n1".into()],
        actor: Some("alice\r\nbob=eve".into()),
        peer: Some("host\nname".into()),
        ..Attrs::default()
    }]);
    let rec = &written[0];
    for format in [ExportFormat::Cef, ExportFormat::Syslog] {
        let line = rec.export(format);
        assert!(!line.contains('\n') && !line.contains('\r'), "{line:?}");
    }
    let c = rec.export(ExportFormat::Cef);
    assert!(c.contains(r"cs4=alice  bob\=eve"), "{c}");
    let s = rec.export(ExportFormat::Syslog);
    assert!(
        s.contains(r#"uri="file:///x  CEF:0|forged|\"\] [fake@0 a=\"b\"\]""#),
        "{s}"
    );
    assert_eq!(s.matches("[mcpdef@0 ").count(), 1, "{s}");
}

fn reload() -> Attrs {
    Attrs {
        kind: Kind::Reload,
        actor: Some("sighup".into()),
        config_from: Some(format!("sha256:{}", "a".repeat(64))),
        config_to: Some(format!("sha256:{}", "b".repeat(64))),
        ..Attrs::default()
    }
}

#[test]
fn a_reload_records_the_config_digests() {
    let (_dir, path, written) = ledger(vec![reload(), Attrs::default()]);
    assert!(verify(&path).unwrap().ok());
    assert_eq!(read_all(&path).unwrap(), written);
    let line = &lines(&path)[0];
    assert!(line.contains(&format!("\"config_from\":\"sha256:{}\"", "a".repeat(64))));
    assert!(line.contains(&format!("\"config_to\":\"sha256:{}\"", "b".repeat(64))));
    assert!(
        !lines(&path)[1].contains("config_"),
        "a plain call has neither"
    );

    // Each digest is covered by the hash.
    for member in ["config_from", "config_to"] {
        let (_dir, path, _) = ledger(vec![reload()]);
        edit_line(&path, 0, |obj| {
            obj.remove(member);
        });
        assert!(!verify(&path).unwrap().ok(), "{member} removed");
    }
}

#[test]
fn every_export_carries_the_config_digests() {
    let (_dir, _path, written) = ledger(vec![reload()]);
    let rec = &written[0];
    let (from, to) = (
        format!("sha256:{}", "a".repeat(64)),
        format!("sha256:{}", "b".repeat(64)),
    );
    let ocsf: Value = serde_json::from_str(&rec.export(ExportFormat::Ocsf)).unwrap();
    assert_eq!(ocsf["unmapped"]["config_from"], from.as_str());
    assert_eq!(ocsf["unmapped"]["config_to"], to.as_str());
    let cef = rec.export(ExportFormat::Cef);
    assert!(
        cef.contains(&format!(" oldFileHash={from} fileHash={to}")),
        "{cef}"
    );
    let syslog = rec.export(ExportFormat::Syslog);
    assert!(
        syslog.contains(&format!(" config_from=\"{from}\" config_to=\"{to}\"")),
        "{syslog}"
    );
}

/// The attributes of an upstream record that says its tools changed.
fn tools_changed() -> Attrs {
    Attrs {
        kind: Kind::Upstream,
        tool_changes: Some(ToolChanges {
            added: 1,
            removed: 2,
            changed: 3,
            drifted: 1,
        }),
        ..Attrs::default()
    }
}

#[test]
fn a_tools_changed_record_carries_its_counts() {
    let (_dir, path, written) = ledger(vec![tools_changed(), Attrs::default()]);
    assert!(verify(&path).unwrap().ok());
    assert_eq!(read_all(&path).unwrap(), written);
    let line = &lines(&path)[0];
    assert!(
        line.contains(r#""tool_changes":{"added":1,"removed":2,"changed":3,"drifted":1}"#),
        "{line}"
    );
    assert!(
        !lines(&path)[1].contains("tool_changes"),
        "a plain call has none"
    );

    // The hash covers the member and each count in it.
    for count in ["added", "removed", "changed", "drifted"] {
        let (_dir, path, _) = ledger(vec![tools_changed()]);
        edit_line(&path, 0, |obj| {
            obj["tool_changes"][count] = Value::from(7);
        });
        assert_eq!(verify(&path).unwrap().broken_at, Some(0), "{count}");
    }
    let (_dir, path, _) = ledger(vec![tools_changed()]);
    edit_line(&path, 0, |obj| {
        obj.remove("tool_changes");
    });
    assert_eq!(verify(&path).unwrap().broken_at, Some(0));
}

/// A count named twice would let the verifier and a SIEM read different
/// numbers; a member it does not have would be dropped from the hash.
#[test]
fn a_count_named_twice_or_one_it_lacks_is_corrupt() {
    let bad = [
        (
            r#""tool_changes":{"added":1,"added":5,"removed":0,"changed":0,"drifted":0},"#,
            "duplicate field",
        ),
        (
            r#""tool_changes":{"added":1,"removed":0,"changed":0,"drifted":0,"renamed":2},"#,
            "unknown field",
        ),
        (
            r#""tool_changes":{"added":1,"removed":0,"changed":0},"#,
            "missing field",
        ),
    ];
    for (members, why) in bad {
        let (_dir, path, _) = ledger(vec![Attrs::default()]);
        splice_line(&path, 0, members);
        let err = verify(&path).expect_err(members);
        assert!(
            matches!(&err, AuditError::Corrupt { detail, .. } if detail.contains(why)),
            "{members}: {err}"
        );
        assert!(Ledger::open(&path).is_err(), "{members}");
    }
}

#[test]
fn every_export_carries_the_tool_changes() {
    let (_dir, _path, written) = ledger(vec![tools_changed(), Attrs::default()]);
    let rec = &written[0];
    let ocsf: Value = serde_json::from_str(&rec.export(ExportFormat::Ocsf)).unwrap();
    assert_eq!(
        ocsf["unmapped"]["tool_changes"],
        serde_json::json!({ "added": 1, "removed": 2, "changed": 3, "drifted": 1 })
    );
    let cef = rec.export(ExportFormat::Cef);
    assert!(
        cef.contains(
            r#" cs6Label=toolChanges cs6={"added":1,"changed":3,"drifted":1,"removed":2}"#
        ),
        "{cef}"
    );
    let syslog = rec.export(ExportFormat::Syslog);
    assert!(
        syslog.contains(
            r#" tool_changes="{\"added\":1,\"changed\":3,\"drifted\":1,\"removed\":2}" hash=""#
        ),
        "{syslog}"
    );

    // A plain call carries none of it.
    let plain = &written[1];
    let ocsf: Value = serde_json::from_str(&plain.export(ExportFormat::Ocsf)).unwrap();
    assert!(ocsf["unmapped"].get("tool_changes").is_none());
    assert!(!plain.export(ExportFormat::Cef).contains("cs6"));
    assert!(!plain.export(ExportFormat::Syslog).contains("tool_changes"));
}
