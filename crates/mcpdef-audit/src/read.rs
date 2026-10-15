// SPDX-License-Identifier: Apache-2.0
//! Reading a ledger a part at a time: a page of records, newest first, from
//! where the last page stopped; one record by its `seq`; and the records after
//! a point, as they are appended. Each reads the file from where it needs to,
//! so a page costs its own records, not the ledger's length, and nothing about
//! the file is kept in memory between reads.
//!
//! These read the file as [`Ledger::append`](crate::Ledger::append) writes it:
//! one record per line, in `seq` order. A line still being written, with no
//! newline yet, is not read. [`find`] and [`Follow::after`] search by `seq`,
//! which needs it to increase down the file, as it does in any ledger that
//! verifies. The time filters assume the records are in time order, which they
//! are unless the clock was set back: `since` can miss a record written after
//! the clock stepped back.

use crate::{AuditError, Record};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

/// How much of the file a read takes at a time.
const CHUNK: u64 = 64 * 1024;

/// Which records a read wants: every member that is set must match, and one
/// left `None` matches anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// `allow` or `deny`.
    pub decision: Option<String>,
    pub server: Option<String>,
    pub tool: Option<String>,
    pub agent: Option<String>,
    pub rule: Option<String>,
    /// What the record is about: `call` matches a governed call, whose record
    /// leaves `kind` out.
    pub kind: Option<String>,
    /// Written at or after this time, in milliseconds since the epoch.
    pub since: Option<u64>,
    /// Written before this time.
    pub until: Option<u64>,
}

impl Filter {
    /// Whether `r` is one this filter wants.
    pub fn matches(&self, r: &Record) -> bool {
        fn is(want: &Option<String>, have: Option<&str>) -> bool {
            want.as_deref().is_none_or(|w| have == Some(w))
        }
        is(&self.decision, Some(&r.decision))
            && is(&self.server, Some(&r.server))
            && is(&self.tool, r.tool.as_deref())
            && is(&self.agent, Some(&r.agent))
            && is(&self.rule, r.rule.as_deref())
            && is(&self.kind, Some(r.kind.as_deref().unwrap_or("call")))
            && self.since.is_none_or(|t| r.ts_unix_ms >= t)
            && self.until.is_none_or(|t| r.ts_unix_ms < t)
    }
}

/// Where a page stopped: the oldest record it read, by its `seq` and the
/// offset its line starts at. A client hands its text, `<seq>.<offset>`,
/// back for the next page, and need not know what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    seq: u64,
    offset: u64,
}

impl Cursor {
    /// The cursor a page's [`Display`](fmt::Display) wrote; `None` for
    /// anything else.
    pub fn parse(text: &str) -> Option<Cursor> {
        let (seq, offset) = text.split_once('.')?;
        let number = |s: &str| {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        };
        Some(Cursor {
            seq: number(seq)?,
            offset: number(offset)?,
        })
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.seq, self.offset)
    }
}

/// A page of records, newest first.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub records: Vec<Record>,
    /// Where the next, older page starts; `None` when no older record can
    /// match.
    pub next: Option<Cursor>,
    /// How many records the page read, matching or not.
    pub scanned: u64,
}

/// Up to `limit` records that `filter` wants, newest first, from the record
/// before `before` (the newest when `None`), reading at most `budget` records:
/// a page that spends its budget stops short, with a cursor to go on from.
///
/// A cursor that does not point at a line of this file, or whose record is
/// gone, is [`AuditError::Cursor`]. An absent ledger is an empty one.
pub fn page(
    path: impl AsRef<Path>,
    before: Option<Cursor>,
    limit: usize,
    filter: &Filter,
    budget: u64,
) -> Result<Page, AuditError> {
    let mut page = Page {
        records: Vec::new(),
        next: None,
        scanned: 0,
    };
    let Some(file) = open(path.as_ref())? else {
        return Ok(page);
    };
    let mut lines = match before {
        Some(cursor) => {
            let end = at_line(&file, cursor.offset)?;
            Backward::at(file, end)
        }
        None => Backward::at_end(file)?,
    };
    while page.records.len() < limit && page.scanned < budget {
        let Some((offset, line)) = lines.prev()? else {
            page.next = None;
            return Ok(page);
        };
        let record = parse(&line, offset)?;
        if page.scanned == 0 && before.is_some_and(|c| record.seq >= c.seq) {
            return Err(AuditError::Cursor(
                "the ledger changed under this cursor".into(),
            ));
        }
        page.scanned += 1;
        if filter.since.is_some_and(|t| record.ts_unix_ms < t) {
            // Older than wanted, and so is every record before it.
            page.next = None;
            return Ok(page);
        }
        page.next = (offset > 0).then_some(Cursor {
            seq: record.seq,
            offset,
        });
        if filter.matches(&record) {
            page.records.push(record);
        }
    }
    Ok(page)
}

/// The record numbered `seq`, if the ledger holds it.
pub fn find(path: impl AsRef<Path>, seq: u64) -> Result<Option<Record>, AuditError> {
    let Some(mut file) = open(path.as_ref())? else {
        return Ok(None);
    };
    let end = complete_end(&mut file)?;
    let offset = first_from(&mut file, end, seq)?;
    match line_from(&mut file, offset, end)? {
        Some((at, line, _)) => {
            let record = parse(&line, at)?;
            Ok((record.seq == seq).then_some(record))
        }
        None => Ok(None),
    }
}

/// The records of a ledger from a point on, read as they are appended.
pub struct Follow {
    file: File,
    /// Where the next record's line starts.
    offset: u64,
}

impl Follow {
    /// Every record, from the first.
    pub fn start(path: impl AsRef<Path>) -> Result<Follow, AuditError> {
        Ok(Follow {
            file: File::open(path)?,
            offset: 0,
        })
    }

    /// The records after the one numbered `seq`, or, when `seq` is `None` or
    /// not yet written, those appended from now on.
    pub fn after(path: impl AsRef<Path>, seq: Option<u64>) -> Result<Follow, AuditError> {
        let mut file = File::open(path)?;
        let end = complete_end(&mut file)?;
        let offset = match seq.and_then(|s| s.checked_add(1)) {
            Some(next) => first_from(&mut file, end, next)?,
            None => end,
        };
        Ok(Follow { file, offset })
    }

    /// Up to `max` records appended since the last read, in order, each with
    /// its line as written.
    ///
    /// A file now shorter than what was read is [`AuditError::Shrunk`]: it
    /// was cut short or replaced, and following it on would skip or repeat.
    pub fn read(&mut self, max: usize) -> Result<Vec<(Record, String)>, AuditError> {
        let len = self.file.metadata()?.len();
        if len < self.offset {
            return Err(AuditError::Shrunk {
                len,
                read: self.offset,
            });
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        let mut reader = BufReader::with_capacity(CHUNK as usize, &mut self.file);
        let mut out = Vec::new();
        let mut line = Vec::new();
        while out.len() < max {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            if n == 0 || line.last() != Some(&b'\n') {
                break;
            }
            let at = self.offset;
            self.offset += n as u64;
            line.pop();
            if line.trim_ascii().is_empty() {
                continue;
            }
            let record = parse(&line, at)?;
            let text = String::from_utf8(std::mem::take(&mut line)).map_err(|e| {
                AuditError::CorruptAt {
                    offset: at,
                    detail: e.to_string(),
                }
            })?;
            out.push((record, text));
        }
        Ok(out)
    }
}

/// The ledger at `path` open for reading, or `None` if there is none yet.
fn open(path: &Path) -> Result<Option<File>, AuditError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn parse(line: &[u8], offset: u64) -> Result<Record, AuditError> {
    serde_json::from_slice(line).map_err(|e| AuditError::CorruptAt {
        offset,
        detail: e.to_string(),
    })
}

/// `offset`, once it is known to start a line of `file`: the start of the
/// file, or just after a newline within it.
fn at_line(mut file: &File, offset: u64) -> Result<u64, AuditError> {
    let refused = || AuditError::Cursor("not a cursor this ledger gave".into());
    if offset == 0 {
        return Ok(0);
    }
    if offset > file.metadata()?.len() {
        return Err(refused());
    }
    let mut byte = [0u8];
    file.seek(SeekFrom::Start(offset - 1))?;
    file.read_exact(&mut byte)?;
    if byte[0] == b'\n' {
        Ok(offset)
    } else {
        Err(refused())
    }
}

/// Where the file's complete lines end: after its last newline.
fn complete_end(file: &mut File) -> std::io::Result<u64> {
    let mut pos = file.metadata()?.len();
    let mut chunk = Vec::new();
    while pos > 0 {
        let take = pos.min(CHUNK);
        let from = pos - take;
        chunk.resize(take as usize, 0);
        file.seek(SeekFrom::Start(from))?;
        file.read_exact(&mut chunk)?;
        if let Some(i) = chunk.iter().rposition(|&b| b == b'\n') {
            return Ok(from + i as u64 + 1);
        }
        pos = from;
    }
    Ok(0)
}

/// The first complete, non-blank line that starts at or after `pos` and
/// before `end`: where it starts, the line without its newline, and where the
/// next one starts.
fn line_from(file: &mut File, pos: u64, end: u64) -> std::io::Result<Option<(u64, Vec<u8>, u64)>> {
    // From the byte before `pos`, so that a line starting exactly at `pos` is
    // taken whole and one that started before it is passed over.
    let mut at = pos.saturating_sub(1);
    file.seek(SeekFrom::Start(at))?;
    let mut reader = BufReader::with_capacity(8 * 1024, file);
    let mut line = Vec::new();
    if pos > 0 {
        let n = reader.read_until(b'\n', &mut line)?;
        if line.last() != Some(&b'\n') {
            return Ok(None);
        }
        at += n as u64;
    }
    loop {
        if at >= end {
            return Ok(None);
        }
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if line.last() != Some(&b'\n') {
            return Ok(None);
        }
        let next = at + n as u64;
        line.pop();
        if !line.trim_ascii().is_empty() {
            return Ok(Some((at, line, next)));
        }
        at = next;
    }
}

/// Where the first record numbered `seq` or later starts, before `end`; `end`
/// if there is none. A binary search over the file's bytes, reading a line at
/// each step.
fn first_from(file: &mut File, end: u64, seq: u64) -> Result<u64, AuditError> {
    let (mut lo, mut hi, mut found) = (0, end, end);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match line_from(file, mid, end)? {
            Some((at, line, next)) if at < hi => {
                if parse(&line, at)?.seq >= seq {
                    // No line starts between `mid` and `at`.
                    found = at;
                    hi = mid;
                } else {
                    lo = next;
                }
            }
            _ => hi = mid,
        }
    }
    Ok(found)
}

/// The lines of a file read backward, from a line's start.
struct Backward {
    file: File,
    /// Where the part not yet returned ends: the start of the last line
    /// returned.
    end: u64,
    /// Where `buf` starts in the file: `buf` holds the bytes from here to
    /// `end`.
    start: u64,
    buf: Vec<u8>,
}

impl Backward {
    /// Reading back from `end`, which starts a line.
    fn at(file: File, end: u64) -> Backward {
        Backward {
            file,
            end,
            start: end,
            buf: Vec::new(),
        }
    }

    /// Reading back from the end of the file's complete lines: a line after
    /// the last newline is still being written.
    fn at_end(file: File) -> std::io::Result<Backward> {
        let len = file.metadata()?.len();
        let mut lines = Backward::at(file, len);
        loop {
            if let Some(i) = lines.buf.iter().rposition(|&b| b == b'\n') {
                lines.end = lines.start + i as u64 + 1;
                break;
            }
            if lines.start == 0 {
                lines.end = 0;
                break;
            }
            lines.fill()?;
        }
        lines.buf.truncate((lines.end - lines.start) as usize);
        Ok(lines)
    }

    /// Takes the chunk before `start` into `buf`.
    fn fill(&mut self) -> std::io::Result<()> {
        let take = self.start.min(CHUNK);
        let from = self.start - take;
        let mut chunk = vec![0u8; take as usize];
        self.file.seek(SeekFrom::Start(from))?;
        self.file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&self.buf);
        self.buf = chunk;
        self.start = from;
        Ok(())
    }

    /// The line before the last one returned, without its newline, and where
    /// it starts; `None` at the start of the file. Blank lines are passed over.
    fn prev(&mut self) -> std::io::Result<Option<(u64, Vec<u8>)>> {
        loop {
            if self.end == 0 {
                return Ok(None);
            }
            if self.start == self.end {
                self.fill()?;
            }
            // `buf` ends with this line's newline.
            let body = self.buf.len() - 1;
            let begins = match self.buf[..body].iter().rposition(|&b| b == b'\n') {
                Some(i) => i + 1,
                None if self.start == 0 => 0,
                None => {
                    self.fill()?;
                    continue;
                }
            };
            let line = self.buf[begins..body].to_vec();
            let at = self.start + begins as u64;
            self.buf.truncate(begins);
            self.end = at;
            if !line.trim_ascii().is_empty() {
                return Ok(Some((at, line)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attrs, Entry, Kind, Ledger};
    use mcpdef_core::Decision;
    use std::io::Write;

    /// A ledger of `n` records in `dir`: every third denied under `rule-<k>`,
    /// servers `a` to `c` in turn, tools `t0` to `t4`, every fifth an admin
    /// record with agent `mcpdef`.
    fn ledger(dir: &Path, n: u64) -> std::path::PathBuf {
        let path = dir.join("audit.log");
        let mut ledger = Ledger::open(&path).unwrap();
        for i in 0..n {
            let admin = i % 5 == 4;
            ledger
                .append(Entry {
                    agent: if admin {
                        "mcpdef".into()
                    } else {
                        "agent:x".into()
                    },
                    server: ["a", "b", "c"][(i % 3) as usize].into(),
                    method: Some("tools/call".into()),
                    tool: Some(format!("t{}", i % 5)),
                    decision: if i % 3 == 2 {
                        Decision::Deny {
                            rule: format!("rule-{}", i % 2),
                            reason: String::new(),
                        }
                    } else {
                        Decision::Allow
                    },
                    latency_ms: i,
                    attrs: Attrs {
                        kind: if admin { Kind::Admin } else { Kind::Call },
                        ..Attrs::default()
                    },
                })
                .unwrap();
        }
        path
    }

    fn seqs(records: &[Record]) -> Vec<u64> {
        records.iter().map(|r| r.seq).collect()
    }

    #[test]
    fn paging_over_ten_thousand_records_reads_each_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 10_000);
        let all = Filter::default();
        let (mut seen, mut scanned, mut cursor, mut pages) = (Vec::new(), 0, None, 0);
        loop {
            let page = page(&path, cursor, 500, &all, u64::MAX).unwrap();
            assert_eq!(page.scanned, page.records.len() as u64);
            scanned += page.scanned;
            seen.extend(seqs(&page.records));
            pages += 1;
            match page.next {
                Some(next) => cursor = Some(Cursor::parse(&next.to_string()).unwrap()),
                None => break,
            }
        }
        assert_eq!(pages, 20);
        assert_eq!(scanned, 10_000);
        assert_eq!(seen, (0..10_000).rev().collect::<Vec<_>>());
    }

    #[test]
    fn every_filter_takes_only_its_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 60);
        let records = crate::read_all(&path).unwrap();
        // What each filter should take, by the records `ledger` writes.
        type Wants = fn(&Record) -> bool;
        let cases: Vec<(Filter, Wants)> = vec![
            (
                Filter {
                    decision: Some("deny".into()),
                    ..Filter::default()
                },
                |r| r.seq % 3 == 2,
            ),
            (
                Filter {
                    server: Some("b".into()),
                    ..Filter::default()
                },
                |r| r.seq % 3 == 1,
            ),
            (
                Filter {
                    tool: Some("t3".into()),
                    ..Filter::default()
                },
                |r| r.seq % 5 == 3,
            ),
            (
                Filter {
                    agent: Some("mcpdef".into()),
                    ..Filter::default()
                },
                |r| r.seq % 5 == 4,
            ),
            (
                Filter {
                    rule: Some("rule-1".into()),
                    ..Filter::default()
                },
                |r| r.seq % 3 == 2 && r.seq % 2 == 1,
            ),
            (
                Filter {
                    kind: Some("admin".into()),
                    ..Filter::default()
                },
                |r| r.seq % 5 == 4,
            ),
            (
                Filter {
                    kind: Some("call".into()),
                    ..Filter::default()
                },
                |r| r.seq % 5 != 4,
            ),
            (
                Filter {
                    decision: Some("deny".into()),
                    server: Some("c".into()),
                    ..Filter::default()
                },
                |r| r.seq % 3 == 2,
            ),
        ];
        for (filter, wanted) in &cases {
            let expected: Vec<u64> = records
                .iter()
                .rev()
                .filter(|r| wanted(r))
                .map(|r| r.seq)
                .collect();
            assert!(!expected.is_empty(), "{filter:?}");
            // In pages of 4, so that a filtered page goes on from its cursor.
            let (mut seen, mut cursor) = (Vec::new(), None);
            loop {
                let page = page(&path, cursor, 4, filter, u64::MAX).unwrap();
                seen.extend(seqs(&page.records));
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            assert_eq!(seen, expected, "{filter:?}");
        }
    }

    #[test]
    fn the_time_filters_take_a_window_and_stop_at_since() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 60);
        // Ten milliseconds apart: the chain no longer verifies, which a read
        // does not check.
        let lines: Vec<String> = crate::read_all(&path)
            .unwrap()
            .into_iter()
            .map(|mut r| {
                r.ts_unix_ms = 1000 + 10 * r.seq;
                serde_json::to_string(&r).unwrap() + "\n"
            })
            .collect();
        std::fs::write(&path, lines.concat()).unwrap();
        let window = Filter {
            since: Some(1200),
            until: Some(1400),
            ..Filter::default()
        };
        let page = page(&path, None, 100, &window, u64::MAX).unwrap();
        assert_eq!(seqs(&page.records), (20..40).rev().collect::<Vec<_>>());
        // 59 down to 40 passed over, 39 to 20 taken, and 19 the last read.
        assert_eq!((page.scanned, page.next), (41, None));
    }

    #[test]
    fn a_page_stops_at_its_budget_and_goes_on_from_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 100);
        let rare = Filter {
            tool: Some("t0".into()),
            server: Some("a".into()),
            ..Filter::default()
        };
        let first = page(&path, None, 50, &rare, 10).unwrap();
        assert_eq!(first.scanned, 10);
        assert_eq!(seqs(&first.records), [90]);
        let next = page(&path, first.next, 50, &rare, u64::MAX).unwrap();
        assert_eq!(seqs(&next.records), [75, 60, 45, 30, 15, 0]);
        assert_eq!(next.next, None);
    }

    #[test]
    fn a_cursor_is_checked_against_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 10);
        let all = Filter::default();
        let first = page(&path, None, 3, &all, u64::MAX).unwrap();
        let cursor = first.next.unwrap();
        // Not a line's start.
        let inside = Cursor {
            offset: cursor.offset + 1,
            ..cursor
        };
        assert!(matches!(
            page(&path, Some(inside), 3, &all, u64::MAX),
            Err(AuditError::Cursor(_))
        ));
        // Past the end.
        let past = Cursor {
            offset: 1 << 40,
            ..cursor
        };
        assert!(matches!(
            page(&path, Some(past), 3, &all, u64::MAX),
            Err(AuditError::Cursor(_))
        ));
        // A line's start, but not where that record is: the ledger changed.
        let moved = Cursor { seq: 2, ..cursor };
        assert!(matches!(
            page(&path, Some(moved), 3, &all, u64::MAX),
            Err(AuditError::Cursor(_))
        ));
        for text in ["", "7", "7.", ".7", "a.1", "1.-2", "+1.2", "1.2.3"] {
            assert_eq!(Cursor::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_line_being_written_is_not_read_until_it_ends() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 5);
        let mut follow = Follow::after(&path, None).unwrap();
        let mut raw = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let mut sixth = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_string();
        sixth = sixth.replacen("\"seq\":4", "\"seq\":5", 1);
        let (head, tail) = sixth.split_at(20);
        raw.write_all(head.as_bytes()).unwrap();
        let all = Filter::default();
        assert_eq!(
            seqs(&page(&path, None, 10, &all, u64::MAX).unwrap().records),
            [4, 3, 2, 1, 0]
        );
        assert!(follow.read(10).unwrap().is_empty());
        assert_eq!(find(&path, 4).unwrap().map(|r| r.seq), Some(4));
        assert_eq!(find(&path, 5).unwrap(), None);
        raw.write_all(tail.as_bytes()).unwrap();
        raw.write_all(b"\n").unwrap();
        let read = follow.read(10).unwrap();
        assert_eq!(read.iter().map(|(r, _)| r.seq).collect::<Vec<_>>(), [5]);
        assert_eq!(read[0].1, sixth);
        assert_eq!(
            seqs(&page(&path, None, 2, &all, u64::MAX).unwrap().records),
            [5, 4]
        );
    }

    #[test]
    fn find_takes_each_record_by_its_seq() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 257);
        for seq in 0..257 {
            assert_eq!(find(&path, seq).unwrap().map(|r| r.seq), Some(seq));
        }
        assert_eq!(find(&path, 257).unwrap(), None);
        assert_eq!(find(&path, u64::MAX).unwrap(), None);
        assert_eq!(find(dir.path().join("absent.log"), 0).unwrap(), None);
    }

    #[test]
    fn following_resumes_after_a_seq_without_a_gap_or_a_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let path = ledger(dir.path(), 30);
        for after in [
            None,
            Some(0),
            Some(13),
            Some(28),
            Some(29),
            Some(500),
            Some(u64::MAX),
        ] {
            let mut follow = Follow::after(&path, after).unwrap();
            let got: Vec<u64> = follow
                .read(1000)
                .unwrap()
                .iter()
                .map(|(r, _)| r.seq)
                .collect();
            let from = match after {
                Some(s) if s < 29 => s + 1,
                _ => 30,
            };
            assert_eq!(got, (from..30).collect::<Vec<_>>(), "{after:?}");
        }
        // In batches, then what is appended after.
        let mut follow = Follow::start(&path).unwrap();
        let mut got = Vec::new();
        loop {
            let batch = follow.read(7).unwrap();
            if batch.is_empty() {
                break;
            }
            got.extend(batch.iter().map(|(r, _)| r.seq));
        }
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .append(Entry {
                agent: "agent:x".into(),
                server: "a".into(),
                method: None,
                tool: None,
                decision: Decision::Allow,
                latency_ms: 0,
                attrs: Attrs::default(),
            })
            .unwrap();
        got.extend(follow.read(7).unwrap().iter().map(|(r, _)| r.seq));
        assert_eq!(got, (0..31).collect::<Vec<_>>());
        // A ledger cut short under a reader.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &text[..text.len() / 2]).unwrap();
        assert!(matches!(follow.read(7), Err(AuditError::Shrunk { .. })));
    }

    #[test]
    fn an_empty_or_absent_ledger_has_no_pages() {
        let dir = tempfile::tempdir().unwrap();
        let all = Filter::default();
        let absent = page(dir.path().join("absent.log"), None, 10, &all, u64::MAX).unwrap();
        assert_eq!((absent.records.len(), absent.next), (0, None));
        let empty = dir.path().join("empty.log");
        std::fs::write(&empty, "\n\n").unwrap();
        let page = page(&empty, None, 10, &all, u64::MAX).unwrap();
        assert_eq!((page.records.len(), page.next), (0, None));
    }
}
