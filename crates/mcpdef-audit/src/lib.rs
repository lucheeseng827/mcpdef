// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-audit` — the tamper-evident audit ledger.
//!
//! Every governed call appends one [`Record`] to an append-only file as a single
//! JSON line. Each record carries the previous record's `hash` in `prev_hash`
//! and its own `hash = SHA-256(canonical-fields ‖ prev_hash)`, so the file is a
//! hash chain: editing or deleting an **interior** record breaks every `hash`
//! downstream, which [`verify`] detects offline.
//!
//! **What plain `verify` does *not* catch:** truncating the tail (removing the
//! last N records) or replacing the whole file with a shorter valid chain leaves
//! it internally consistent. Detecting that needs a `(head, count)` sealed
//! out-of-band — see [`verify_against`]. (`append` itself uses a userspace
//! `flush`, not `fsync`, so a crash can also lose the last unsynced record(s);
//! a durable/`sync_all` mode is a later option — see [`Ledger::append`].)
//!
//! This is the Phase-1 shape from the [ROADMAP](../../../ROADMAP.md): local,
//! hash-linked, never paywalled. SIEM export (OCSF/CEF/syslog/OTel) layers on
//! later without changing the on-disk chain.

use mcpdef_core::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The hash-chain anchor for the first record (64 hex zeros).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt ledger at line {line}: {detail}")]
    Corrupt { line: u64, detail: String },
}

/// One audit record. `seq` is monotonic from 0; `hash` chains to `prev_hash`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub ts_unix_ms: u64,
    pub agent: String,
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule: Option<String>,
    pub latency_ms: u64,
    pub prev_hash: String,
    pub hash: String,
}

impl Record {
    /// Recompute this record's hash from its fields + `prev_hash`. Deterministic
    /// and independent of JSON field ordering (it hashes an explicit, delimited
    /// field encoding, not the serialized line).
    fn compute_hash(&self) -> String {
        // Unit separator (0x1f) cannot appear in these fields, so the encoding is
        // unambiguous.
        const US: char = '\u{1f}';
        let mut h = Sha256::new();
        h.update(
            format!(
                "{seq}{US}{ts}{US}{agent}{US}{server}{US}{method}{US}{tool}{US}{decision}{US}{rule}{US}{latency}{US}{prev}",
                seq = self.seq,
                ts = self.ts_unix_ms,
                agent = self.agent,
                server = self.server,
                method = self.method.as_deref().unwrap_or(""),
                tool = self.tool.as_deref().unwrap_or(""),
                decision = self.decision,
                rule = self.rule.as_deref().unwrap_or(""),
                latency = self.latency_ms,
                prev = self.prev_hash,
            )
            .as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

/// The data the gateway hands the ledger for one call; the ledger stamps `seq`,
/// `ts`, `prev_hash`, and `hash`.
#[derive(Debug, Clone)]
pub struct Entry {
    pub agent: String,
    pub server: String,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub decision: Decision,
    pub latency_ms: u64,
}

/// An append-only, hash-linked ledger backed by a file. Re-opening an existing
/// file resumes the chain from its current head.
pub struct Ledger {
    path: PathBuf,
    file: File,
    head: String,
    next_seq: u64,
}

impl Ledger {
    /// Open (creating if absent) the ledger at `path`, resuming the hash chain
    /// and sequence from any existing records.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let (head, next_seq) = match File::open(&path) {
            Ok(f) => {
                let mut head = GENESIS.to_string();
                let mut count: u64 = 0;
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let rec: Record =
                        serde_json::from_str(&line).map_err(|e| AuditError::Corrupt {
                            line: count,
                            detail: e.to_string(),
                        })?;
                    head = rec.hash;
                    count += 1;
                }
                (head, count)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (GENESIS.to_string(), 0),
            Err(e) => return Err(e.into()),
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Ledger {
            path,
            file,
            head,
            next_seq,
        })
    }

    /// The current head hash (the last record's hash, or [`GENESIS`] if empty).
    pub fn head(&self) -> &str {
        &self.head
    }

    /// The sequence number the next appended record will take.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry, returning the stamped, hash-linked record.
    ///
    /// Durability: this `write` + userspace `flush` is **not** an `fsync`, so a
    /// crash can lose records the OS had not yet written to disk. A durable mode
    /// (`sync_all` per append, at a throughput cost) is a later option; the
    /// hash chain proves *integrity*, not *durability*.
    pub fn append(&mut self, entry: Entry) -> Result<Record, AuditError> {
        let (rule, decision) = match &entry.decision {
            Decision::Allow => (None, "allow".to_string()),
            Decision::Deny { rule, .. } => (Some(rule.clone()), "deny".to_string()),
        };
        let mut rec = Record {
            seq: self.next_seq,
            ts_unix_ms: now_unix_ms(),
            agent: entry.agent,
            server: entry.server,
            method: entry.method,
            tool: entry.tool,
            decision,
            rule,
            latency_ms: entry.latency_ms,
            prev_hash: self.head.clone(),
            hash: String::new(),
        };
        rec.hash = rec.compute_hash();

        let line = serde_json::to_string(&rec).expect("Record serializes");
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;

        self.head = rec.hash.clone();
        self.next_seq += 1;
        Ok(rec)
    }
}

/// Read every record from a ledger file in order, **without** checking the hash
/// chain (use [`verify`] for integrity). Blank lines are skipped; a line that
/// does not parse as a [`Record`] is a [`AuditError::Corrupt`]. This is the read
/// side behind `mcpdef audit tail`.
pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<Record>, AuditError> {
    let file = match File::open(path.as_ref()) {
        Ok(f) => f,
        // An absent ledger is an empty one — a fresh gateway has nothing to tail.
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line).map_err(|e| AuditError::Corrupt {
            line: out.len() as u64,
            detail: e.to_string(),
        })?;
        out.push(rec);
    }
    Ok(out)
}

/// The last `n` records of the ledger (all of them if it holds fewer than `n`),
/// in chain order. `n == 0` returns an empty vec.
pub fn tail(path: impl AsRef<Path>, n: usize) -> Result<Vec<Record>, AuditError> {
    let mut all = read_all(path)?;
    if all.len() > n {
        all.drain(..all.len() - n);
    }
    Ok(all)
}

/// The outcome of verifying a ledger file's hash chain.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub records: u64,
    pub head: String,
    /// `None` if the chain is intact; `Some(seq)` of the first broken record.
    pub broken_at: Option<u64>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Verify a ledger file offline: every record's `hash` must recompute, each
/// `prev_hash` must equal the prior record's `hash` (genesis for the first), and
/// `seq` must increase by one. Returns the first break, if any.
pub fn verify(path: impl AsRef<Path>) -> Result<VerifyReport, AuditError> {
    let file = File::open(path)?;
    let mut prev = GENESIS.to_string();
    let mut expected_seq: u64 = 0;
    let mut records: u64 = 0;
    let mut head = GENESIS.to_string();
    let mut broken_at: Option<u64> = None;

    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line).map_err(|e| AuditError::Corrupt {
            line: records,
            detail: e.to_string(),
        })?;

        let recomputed = rec.compute_hash();
        let intact = recomputed == rec.hash && rec.prev_hash == prev && rec.seq == expected_seq;
        if !intact && broken_at.is_none() {
            broken_at = Some(rec.seq);
        }

        prev = rec.hash.clone();
        head = rec.hash;
        // `checked_add` (not `wrapping_add`): in a tamper-evidence routine an
        // overflow must surface as a break, never silently wrap `u64::MAX` → 0
        // and let a `seq == 0` record masquerade as valid continuity.
        expected_seq = match rec.seq.checked_add(1) {
            Some(next) => next,
            None => {
                if broken_at.is_none() {
                    broken_at = Some(rec.seq);
                }
                rec.seq // unchanged → any following record fails continuity
            }
        };
        records += 1;
    }

    Ok(VerifyReport {
        records,
        head,
        broken_at,
    })
}

/// Verify the chain **and** that it still matches a head + record count sealed
/// out-of-band. Plain [`verify`] proves only *internal* consistency, and a
/// tail-truncated or wholesale-replaced ledger is still internally consistent —
/// so removing the last N records, or swapping the whole file for a shorter
/// valid chain, passes [`verify`] undetected. To catch that you must compare
/// against a `(head, count)` recorded somewhere the same attacker cannot also
/// edit (e.g. anchored by the `ee/` control plane, or a separate sealed file).
///
/// Returns a report whose `broken_at` is set if the chain is internally broken
/// **or** diverges from the seal (`records != expected_count` or
/// `head != expected_head`).
pub fn verify_against(
    path: impl AsRef<Path>,
    expected_head: &str,
    expected_count: u64,
) -> Result<VerifyReport, AuditError> {
    let mut report = verify(path)?;
    if report.broken_at.is_none()
        && (report.records != expected_count || report.head != expected_head)
    {
        // Internally consistent but shorter than / different from the seal:
        // flag the first divergent/missing position.
        report.broken_at = Some(report.records.min(expected_count));
    }
    Ok(report)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// SIEM export shapes for a ledger [`Record`]. Every governed call already lands
/// in the local ledger; these formatters let a security team stream that stream
/// into a SIEM **from the free binary** (the export is OSS; only fleet-scale
/// managed pipelines are `ee/`). Each formatter emits **one line per record**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// The raw record as a single JSON line (the on-disk shape).
    Json,
    /// An OCSF "API Activity" (class 6003) event, JSON, one line.
    Ocsf,
    /// ArcSight Common Event Format (CEF:0), one line.
    Cef,
    /// RFC 5424 syslog line (epoch carried in structured data + as RFC3339).
    Syslog,
}

impl ExportFormat {
    /// Parse a `--format` value; `None` for an unknown format.
    pub fn parse(s: &str) -> Option<ExportFormat> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Some(ExportFormat::Json),
            "ocsf" => Some(ExportFormat::Ocsf),
            "cef" => Some(ExportFormat::Cef),
            "syslog" => Some(ExportFormat::Syslog),
            _ => None,
        }
    }

    /// The accepted format names, for help text / error messages.
    pub const NAMES: &'static [&'static str] = &["json", "ocsf", "cef", "syslog"];
}

impl Record {
    /// Render this record in `fmt` as a single line (no trailing newline).
    pub fn export(&self, fmt: ExportFormat) -> String {
        match fmt {
            ExportFormat::Json => serde_json::to_string(self).expect("Record serializes"),
            ExportFormat::Ocsf => self.to_ocsf(),
            ExportFormat::Cef => self.to_cef(),
            ExportFormat::Syslog => self.to_syslog(),
        }
    }

    fn is_deny(&self) -> bool {
        self.decision == "deny"
    }

    /// OCSF "API Activity" (category 6 / class 6003). `time` is epoch-ms (OCSF
    /// accepts epoch); allow → status Success(1), deny → Failure(2). MCPdef-specific
    /// fields the schema has no home for go under `unmapped`.
    fn to_ocsf(&self) -> String {
        let (status, status_id, severity_id) = if self.is_deny() {
            ("Failure", 2, 2) // Low
        } else {
            ("Success", 1, 1) // Informational
        };
        let activity_id = if self.is_deny() { 2 } else { 1 };
        let obj = serde_json::json!({
            "category_uid": 6,
            "category_name": "Application Activity",
            "class_uid": 6003,
            "class_name": "API Activity",
            "type_uid": 6003 * 100 + activity_id,
            "activity_id": activity_id,
            "time": self.ts_unix_ms,
            "severity_id": severity_id,
            "status": status,
            "status_id": status_id,
            "message": self.summary(),
            "metadata": {
                // `product.version` is mcpdef's own version; `metadata.version` is
                // the OCSF *schema* version this record conforms to (not the
                // product version) — keep it a fixed schema constant.
                "product": { "name": "mcpdef", "vendor_name": "mcpdef", "version": env!("CARGO_PKG_VERSION") },
                "version": "1.4.0",
                "uid": self.hash,
            },
            "actor": { "user": { "name": self.agent } },
            "api": {
                "operation": self.method.clone().unwrap_or_default(),
                "service": { "name": self.server },
            },
            "unmapped": {
                "seq": self.seq,
                "tool": self.tool,
                "decision": self.decision,
                "rule": self.rule,
                "latency_ms": self.latency_ms,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
        });
        serde_json::to_string(&obj).expect("ocsf object serializes")
    }

    /// ArcSight CEF:0. Header pipes/backslashes and extension `=`/backslashes are
    /// escaped per the CEF spec. Severity: allow → 2, deny → 7.
    fn to_cef(&self) -> String {
        let severity = if self.is_deny() { 7 } else { 2 };
        let signature = self.decision.clone();
        let name = self.summary();
        let mut ext = format!(
            "rt={rt} suser={agent} dvchost={server} act={act} externalId={seq} cn1Label=latencyMs cn1={lat}",
            rt = self.ts_unix_ms,
            agent = cef_ext_escape(&self.agent),
            server = cef_ext_escape(&self.server),
            act = cef_ext_escape(&self.decision),
            seq = self.seq,
            lat = self.latency_ms,
        );
        if let Some(tool) = &self.tool {
            ext.push_str(&format!(" cs1Label=tool cs1={}", cef_ext_escape(tool)));
        }
        if let Some(rule) = &self.rule {
            ext.push_str(&format!(" cs2Label=rule cs2={}", cef_ext_escape(rule)));
        }
        format!(
            "CEF:0|mcpdef|mcpdef|{ver}|{sig}|{name}|{sev}|{ext}",
            ver = env!("CARGO_PKG_VERSION"),
            sig = cef_header_escape(&signature),
            name = cef_header_escape(&name),
            sev = severity,
        )
    }

    /// RFC 5424 syslog. Facility 10 (security/authorization); severity 6 (info)
    /// for allow, 4 (warning) for deny. The event detail rides in an `mcpdef@0`
    /// structured-data element; the human message follows.
    fn to_syslog(&self) -> String {
        let severity = if self.is_deny() { 4 } else { 6 };
        let pri = 10 * 8 + severity;
        let ts = rfc3339_utc(self.ts_unix_ms);
        let sd = format!(
            "[mcpdef@0 seq=\"{seq}\" server=\"{server}\" tool=\"{tool}\" decision=\"{dec}\" rule=\"{rule}\" latencyMs=\"{lat}\" hash=\"{hash}\"]",
            seq = self.seq,
            server = sd_escape(&self.server),
            tool = sd_escape(self.tool.as_deref().unwrap_or("")),
            dec = sd_escape(&self.decision),
            rule = sd_escape(self.rule.as_deref().unwrap_or("")),
            lat = self.latency_ms,
            hash = sd_escape(&self.hash),
        );
        format!(
            "<{pri}>1 {ts} - mcpdef - {msgid} {sd} {msg}",
            msgid = one_line(self.method.as_deref().unwrap_or("-")),
            msg = one_line(&self.summary()),
        )
    }

    /// A one-line human summary used as the `message`/`name` field across formats.
    fn summary(&self) -> String {
        match &self.tool {
            Some(tool) => format!(
                "{decision} {method} {server}.{tool}",
                decision = self.decision,
                method = self.method.as_deref().unwrap_or("?"),
                server = self.server,
            ),
            None => format!(
                "{decision} {method} {server}",
                decision = self.decision,
                method = self.method.as_deref().unwrap_or("?"),
                server = self.server,
            ),
        }
    }
}

/// Collapse CR/LF to spaces. A SIEM record is one line; a `\r`/`\n` in a
/// caller-controlled field (e.g. a crafted `tool`/`method` name) must not be
/// able to split it into two and forge a second log entry (CWE-117).
fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// Escape a CEF *header* field: `\` and `|` are reserved (newlines stripped first).
fn cef_header_escape(s: &str) -> String {
    one_line(s).replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a CEF *extension* value: `\` and `=` are reserved (newlines stripped first).
fn cef_ext_escape(s: &str) -> String {
    one_line(s).replace('\\', "\\\\").replace('=', "\\=")
}

/// Escape a syslog structured-data param value: `"`, `\`, and `]` are reserved
/// (newlines stripped first).
fn sd_escape(s: &str) -> String {
    one_line(s)
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// Format a Unix-epoch-millis timestamp as RFC 3339 UTC
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), using Howard Hinnant's `civil_from_days`
/// algorithm so the crate needs no date/time dependency.
fn rfc3339_utc(ts_unix_ms: u64) -> String {
    let secs = (ts_unix_ms / 1000) as i64;
    let millis = ts_unix_ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days: days since 1970-01-01 → (year, month, day).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server: &str, tool: &str, decision: Decision) -> Entry {
        Entry {
            agent: "agent:test".into(),
            server: server.into(),
            method: Some("tools/call".into()),
            tool: Some(tool.into()),
            decision,
            latency_ms: 1,
        }
    }

    #[test]
    fn appends_and_chains_then_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let r0;
        let r1;
        {
            let mut led = Ledger::open(&path).unwrap();
            assert_eq!(led.head(), GENESIS);
            r0 = led
                .append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
            r1 = led
                .append(entry(
                    "github",
                    "delete_repo",
                    Decision::Deny {
                        rule: "deny-glob".into(),
                        reason: "x".into(),
                    },
                ))
                .unwrap();
            assert_eq!(led.head(), r1.hash);
        }

        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_hash, GENESIS);
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_hash, r0.hash);

        let report = verify(&path).unwrap();
        assert!(report.ok());
        assert_eq!(report.records, 2);
        assert_eq!(report.head, r1.hash);
    }

    #[test]
    fn reopen_resumes_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let first_head;
        {
            let mut led = Ledger::open(&path).unwrap();
            first_head = led
                .append(entry("files", "read_file", Decision::Allow))
                .unwrap()
                .hash;
        }
        let mut led = Ledger::open(&path).unwrap();
        assert_eq!(led.head(), first_head);
        assert_eq!(led.next_seq(), 1);
        let r = led
            .append(entry("files", "read_file", Decision::Allow))
            .unwrap();
        assert_eq!(r.seq, 1);
        assert_eq!(r.prev_hash, first_head);
        assert!(verify(&path).unwrap().ok());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut led = Ledger::open(&path).unwrap();
            led.append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
            led.append(entry("github", "get_file_contents", Decision::Allow))
                .unwrap();
            led.append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
        }
        // Rewrite record 1's tool — its stored hash no longer matches its fields.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[1] = lines[1].replace("get_file_contents", "exfiltrate_secrets");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify(&path).unwrap();
        assert!(!report.ok());
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn read_all_and_tail_return_records_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut led = Ledger::open(&path).unwrap();
            for tool in ["a", "b", "c"] {
                led.append(entry("github", tool, Decision::Allow)).unwrap();
            }
        }
        let all = read_all(&path).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].tool.as_deref(), Some("a"));
        assert_eq!(all[2].seq, 2);

        let last_two = tail(&path, 2).unwrap();
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[0].tool.as_deref(), Some("b"));
        assert_eq!(last_two[1].tool.as_deref(), Some("c"));

        // n larger than the ledger returns all of it; absent file → empty.
        assert_eq!(tail(&path, 99).unwrap().len(), 3);
        assert!(read_all(dir.path().join("missing.log")).unwrap().is_empty());
    }

    #[test]
    fn export_formats_render_one_line_each() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let deny = Decision::Deny {
            rule: "deny-glob".into(),
            reason: "x".into(),
        };
        let rec = {
            let mut led = Ledger::open(&path).unwrap();
            led.append(entry("github", "delete_repo", deny)).unwrap()
        };

        // JSON round-trips back to the same record.
        let j = rec.export(ExportFormat::Json);
        assert!(!j.contains('\n'));
        let back: Record = serde_json::from_str(&j).unwrap();
        assert_eq!(back, rec);

        // OCSF is valid JSON with the API-Activity class and a Failure status.
        let o = rec.export(ExportFormat::Ocsf);
        let v: serde_json::Value = serde_json::from_str(&o).unwrap();
        assert_eq!(v["class_uid"], 6003);
        assert_eq!(v["status"], "Failure");
        assert_eq!(v["unmapped"]["tool"], "delete_repo");

        // CEF header + a couple of extensions.
        let c = rec.export(ExportFormat::Cef);
        assert!(c.starts_with("CEF:0|mcpdef|mcpdef|"));
        assert!(c.contains("act=deny"));
        assert!(c.contains("cs1=delete_repo"));

        // Syslog: a PRI + version 1 + structured data, no embedded newline.
        let s = rec.export(ExportFormat::Syslog);
        assert!(s.starts_with('<') && s.contains(">1 "));
        assert!(s.contains("[mcpdef@0 "));
        assert!(!s.contains('\n'));

        assert_eq!(ExportFormat::parse("OCSF"), Some(ExportFormat::Ocsf));
        assert_eq!(ExportFormat::parse("nope"), None);
    }

    #[test]
    fn cef_and_syslog_scrub_embedded_newlines() {
        // A caller-controlled field (here the tool name) carrying CR/LF must not
        // be able to split a single record into multiple CEF/syslog lines and
        // forge a second SIEM entry (CWE-117 log injection).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let rec = {
            let mut led = Ledger::open(&path).unwrap();
            led.append(entry("github", "evil\nfake=injected", Decision::Allow))
                .unwrap()
        };

        let c = rec.export(ExportFormat::Cef);
        assert!(!c.contains('\n'), "CEF must be single-line: {c:?}");
        assert!(!c.contains('\r'));

        let s = rec.export(ExportFormat::Syslog);
        assert!(!s.contains('\n'), "syslog must be single-line: {s:?}");
        assert!(!s.contains('\r'));
    }

    #[test]
    fn rfc3339_utc_formats_known_epochs() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        // millisecond component is preserved and zero-padded
        assert_eq!(rfc3339_utc(1_700_000_000_007), "2023-11-14T22:13:20.007Z");
    }

    #[test]
    fn tail_truncation_passes_verify_but_fails_verify_against() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let (sealed_head, sealed_count);
        {
            let mut led = Ledger::open(&path).unwrap();
            led.append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
            led.append(entry("github", "get_file_contents", Decision::Allow))
                .unwrap();
            led.append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
            sealed_head = led.head().to_string(); // seal head + count out-of-band
            sealed_count = led.next_seq();
        }
        assert_eq!(sealed_count, 3);

        // Drop the last record: the remaining chain is still internally valid.
        let content = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = content.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        // Plain verify is fooled — the truncated chain verifies clean.
        assert!(verify(&path).unwrap().ok());

        // verify_against catches it against the sealed head + count.
        let report = verify_against(&path, &sealed_head, sealed_count).unwrap();
        assert!(!report.ok());
        assert_eq!(report.records, 2);
    }
}
