// SPDX-License-Identifier: Apache-2.0
//! `LedgerHandle`: many tasks appending to one ledger.

use mcpdef_audit::{read_all, verify, Attrs, Entry, Ledger, LedgerHandle, Record, GENESIS};
use mcpdef_core::Decision;
use std::collections::BTreeSet;
use std::path::Path;

fn entry(agent: &str, n: u64) -> Entry {
    Entry {
        agent: agent.to_string(),
        server: "s0".into(),
        method: Some("tools/call".into()),
        tool: Some(format!("tool_{n}")),
        decision: if n.is_multiple_of(7) {
            Decision::Deny {
                rule: "not-on-allowlist".into(),
                reason: "x".into(),
            }
        } else {
            Decision::Allow
        },
        latency_ms: n,
        attrs: Attrs::default(),
    }
}

/// The chain on disk verifies, `seq` runs `0..count` with no gap, and each
/// record a caller got back is exactly the line at its position.
fn assert_one_chain(path: &Path, returned: &[Record], count: u64) {
    let on_disk = read_all(path).unwrap();
    assert_eq!(on_disk.len() as u64, count);
    for (i, rec) in on_disk.iter().enumerate() {
        assert_eq!(rec.seq, i as u64);
    }
    for rec in returned {
        assert_eq!(&on_disk[rec.seq as usize], rec);
    }
    let report = verify(path).unwrap();
    assert!(report.ok(), "broken at {:?}", report.broken_at);
    assert_eq!(report.records, count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_hundred_concurrent_appends_make_one_valid_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let handle = LedgerHandle::new(Ledger::open(&path).unwrap());

    let tasks: Vec<_> = (0..200)
        .map(|n| {
            let handle = handle.clone();
            tokio::spawn(async move { handle.append(entry(&format!("agent:{n}"), n)).await })
        })
        .collect();
    let mut returned = Vec::new();
    for task in tasks {
        returned.push(task.await.unwrap().unwrap());
    }

    let seqs: BTreeSet<u64> = returned.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, (0..200).collect::<BTreeSet<_>>(), "one seq each");
    assert_one_chain(&path, &returned, 200);
    assert_eq!(handle.next_seq(), 200);
    assert_eq!(handle.head(), verify(&path).unwrap().head);
}

/// Sixteen callers each append 125 records in a row while the others do the
/// same. Every caller's records land in the order it made them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn each_caller_s_records_keep_its_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let handle = LedgerHandle::new(Ledger::open(&path).unwrap());

    let callers: Vec<_> = (0..16)
        .map(|c| {
            let handle = handle.clone();
            tokio::spawn(async move {
                let mut mine = Vec::new();
                for n in 0..125 {
                    mine.push(
                        handle
                            .append(entry(&format!("caller:{c}"), n))
                            .await
                            .unwrap(),
                    );
                }
                mine
            })
        })
        .collect();
    let mut returned = Vec::new();
    for caller in callers {
        let mine = caller.await.unwrap();
        assert!(mine.windows(2).all(|w| w[0].seq < w[1].seq), "out of order");
        returned.extend(mine);
    }
    assert_one_chain(&path, &returned, 2000);
}

/// Callers that give up mid-append (a client that disconnects, say) never leave
/// a gap in `seq` or a torn line: an append either wrote its whole record or
/// wrote nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn abandoned_appends_leave_no_gap_or_torn_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let handle = LedgerHandle::new(Ledger::open(&path).unwrap());

    let tasks: Vec<_> = (0..400)
        .map(|n| {
            let handle = handle.clone();
            tokio::spawn(async move { handle.append(entry(&format!("agent:{n}"), n)).await })
        })
        .collect();
    for (n, task) in tasks.iter().enumerate() {
        if n % 2 == 1 {
            task.abort();
        }
    }
    let mut returned = Vec::new();
    let mut abandoned = 0;
    for task in tasks {
        match task.await {
            Ok(written) => returned.push(written.unwrap()),
            Err(e) if e.is_cancelled() => abandoned += 1,
            Err(e) => panic!("{e}"),
        }
    }
    let on_disk = read_all(&path).unwrap();
    // Every completed append is on disk; an aborted one may or may not be.
    assert!(on_disk.len() >= returned.len());
    assert_one_chain(&path, &returned, on_disk.len() as u64);
    assert_eq!(handle.next_seq(), on_disk.len() as u64);
    assert!(abandoned <= 200);
}

/// A handle needs no runtime to exist. Once the last one is gone, the ledger
/// reopens where it left off.
#[test]
fn the_chain_resumes_after_the_last_handle_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let handle = LedgerHandle::new(Ledger::open(&path).unwrap());
    assert_eq!(handle.path(), path);
    assert_eq!((handle.head(), handle.next_seq()), (GENESIS.to_string(), 0));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut prev = GENESIS.to_string();
    for n in 0..3 {
        let rec = runtime
            .block_on(handle.append(entry("agent:a", n)))
            .unwrap();
        assert_eq!((rec.seq, rec.prev_hash.as_str()), (n, prev.as_str()));
        prev = rec.hash;
    }
    assert_eq!(handle.head(), prev);
    drop(handle);

    let reopened = LedgerHandle::new(Ledger::open(&path).unwrap());
    assert_eq!((reopened.head(), reopened.next_seq()), (prev.clone(), 3));
    let rec = runtime
        .block_on(reopened.append(entry("agent:a", 3)))
        .unwrap();
    assert_eq!((rec.seq, rec.prev_hash), (3, prev));
    assert!(verify(&path).unwrap().ok());
}
