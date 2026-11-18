// SPDX-License-Identifier: Apache-2.0
//! `LedgerHandle`: many tasks appending to one ledger.

use mcpdef_audit::{
    read_all, verify, Attrs, Durability, Entry, Ledger, LedgerHandle, Record, GENESIS,
};
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

/// Writers that each open the file themselves, as hooks in processes of their
/// own do, take turns on its lock: with a gateway's long-lived writer
/// appending beside them, the file is still one chain.
#[test]
fn writers_with_files_of_their_own_make_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut gateway = Ledger::open(&path).unwrap();
    let hooks: Vec<_> = (0..8)
        .map(|h| {
            let path = path.clone();
            std::thread::spawn(move || {
                (0..40)
                    .map(|n| {
                        let mut hook = Ledger::attach(&path, Durability::Os).unwrap();
                        hook.append(entry(&format!("hook:{h}"), n)).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut returned: Vec<Record> = (0..80)
        .map(|n| gateway.append(entry("gateway", n)).unwrap())
        .collect();
    for hook in hooks {
        returned.extend(hook.join().unwrap());
    }
    assert_one_chain(&path, &returned, 8 * 40 + 80);
    // The long-lived writer knows where the chain is, too.
    let last = gateway.append(entry("gateway", 80)).unwrap();
    assert_eq!(last.seq, 8 * 40 + 80);
    assert_one_chain(&path, &[last], 8 * 40 + 81);
}

/// A writer that attaches reads nothing until it writes, and then goes on
/// from the last record, however long the ledger is.
#[test]
fn an_attached_writer_goes_on_from_the_last_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut first = Ledger::open(&path).unwrap();
    let written: Vec<Record> = (0..5)
        .map(|n| first.append(entry("a", n)).unwrap())
        .collect();
    let mut hook = Ledger::attach(&path, Durability::Os).unwrap();
    assert_eq!(
        (hook.head(), hook.next_seq()),
        (GENESIS, 0),
        "nothing read yet"
    );
    let rec = hook.append(entry("hook", 5)).unwrap();
    assert_eq!(rec.seq, 5);
    assert_eq!(rec.prev_hash, written[4].hash);
    // An empty ledger, attached to, starts the chain.
    let empty = dir.path().join("empty.log");
    let first = Ledger::attach(&empty, Durability::Os)
        .unwrap()
        .append(entry("hook", 0))
        .unwrap();
    assert_eq!((first.seq, first.prev_hash.as_str()), (0, GENESIS));
}

/// A last line with no newline, from a writer that stopped part way, is never
/// joined to the next record: that one is a line of its own.
#[test]
fn a_record_never_joins_a_line_that_has_no_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut first = Ledger::open(&path).unwrap();
    first.append(entry("a", 0)).unwrap();
    let mut text = std::fs::read(&path).unwrap();
    text.pop();
    std::fs::write(&path, &text).unwrap();
    // Read whole, as a reopened gateway does, and attached, as a hook does.
    let mut reopened = Ledger::open(&path).unwrap();
    let rec = reopened.append(entry("a", 1)).unwrap();
    assert_eq!(rec.seq, 1);
    let hook = Ledger::attach(&path, Durability::Os)
        .unwrap()
        .append(entry("hook", 2))
        .unwrap();
    assert_eq!(hook.seq, 2);
    assert_one_chain(&path, &[rec, hook], 3);
}

/// A ledger cut short under a running writer stays cut: the writer goes on
/// from its own head, so a check finds the break.
#[test]
fn a_ledger_cut_short_under_a_writer_stays_broken() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut gateway = Ledger::open(&path).unwrap();
    for n in 0..3 {
        gateway.append(entry("a", n)).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let first_line = text.lines().next().unwrap().to_string() + "\n";
    std::fs::write(&path, first_line).unwrap();
    let rec = gateway.append(entry("a", 3)).unwrap();
    assert_eq!(rec.seq, 3, "the chain this writer holds");
    // Its `seq`: the record that does not follow the one before it.
    let report = verify(&path).unwrap();
    assert_eq!(report.broken_at, Some(3));
}

/// A ledger opened while another writer is halfway through a line waits for
/// the line, rather than taking it for a corrupt one: a gateway starting
/// beside hooks that are writing.
#[test]
fn a_ledger_opened_mid_line_waits_for_the_line() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut first = Ledger::open(&path).unwrap();
    for n in 0..3 {
        first.append(entry("a", n)).unwrap();
    }
    drop(first);
    // The third line, written again under a writer's lock, in two halves.
    let text = std::fs::read_to_string(&path).unwrap();
    let third = text.lines().nth(2).unwrap().to_string() + "\n";
    std::fs::write(&path, &text[..text.len() - third.len()]).unwrap();
    let file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    let mut lock = fd_lock::RwLock::new(file);
    let mut writing = lock.write().unwrap();
    let (half, rest) = third.split_at(third.len() / 2);
    writing.write_all(half.as_bytes()).unwrap();

    let opening = std::thread::spawn({
        let path = path.clone();
        move || Ledger::open(&path)
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!opening.is_finished(), "it waits for the writer");
    writing.write_all(rest.as_bytes()).unwrap();
    drop(writing);

    let opened = opening.join().unwrap().unwrap();
    assert_eq!(opened.next_seq(), 3);
    assert_eq!(opened.head(), read_all(&path).unwrap()[2].hash);
}
