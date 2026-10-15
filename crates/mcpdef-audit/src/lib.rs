// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-audit` — the tamper-evident audit ledger.
//!
//! Every governed call appends one [`Record`] to an append-only file as a single
//! JSON line. Each record carries the previous record's `hash` in `prev_hash`
//! and its own `hash = SHA-256(canonical-fields ‖ prev_hash ‖ later-members)`
//! (the exact rule is on [`Record`]), so the file is a hash chain: editing or
//! deleting an **interior** record breaks every `hash` downstream, which
//! [`verify`] detects offline.
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
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::btree_map::{BTreeMap, Entry as MapEntry};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

mod read;
pub use read::{find, page, Cursor, Filter, Follow, Page};

/// The hash-chain anchor for the first record (64 hex zeros).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt ledger at line {line}: {detail}")]
    Corrupt { line: u64, detail: String },
    #[error("corrupt ledger at byte {offset}: {detail}")]
    CorruptAt { offset: u64, detail: String },
    /// A page's cursor that does not belong to this ledger, or no longer does.
    #[error("{0}")]
    Cursor(String),
    /// The file is shorter than a reader had already read: it was cut short
    /// or replaced.
    #[error("the ledger is {len} bytes, and {read} had been read: it was cut short or replaced")]
    Shrunk { len: u64, read: u64 },
}

/// One audit record. `seq` is monotonic from 0; `hash` chains to `prev_hash`.
///
/// # Members
///
/// `seq` through `latency_ms`, with `prev_hash` and `hash`, are the v1 record.
/// Every later member is optional and absent from a plain governed call: `kind`,
/// `uri`, `transforms`, `actor`, `peer`, `config_from`, `config_to` and
/// `tool_changes`, and any member a later release adds, which this one keeps in
/// [`Record::extra`].
///
/// # The hash
///
/// `hash` is the lowercase hex SHA-256 of:
///
/// 1. the v1 encoding: `seq`, `ts_unix_ms`, `agent`, `server`, `method`, `tool`,
///    `decision`, `rule`, `latency_ms` and `prev_hash`, in that order, joined by
///    U+001F, with an absent optional field written as the empty string;
/// 2. then, only if the record has any later member, U+001F followed by all of
///    them as one JSON object. The object is compact, sorts members by name (by
///    code point) at every level, and leaves out a member whose value is `null`.
///    Its strings escape `"`, `\` and control characters, the last as `\u00xx`
///    in lowercase hex except `\b`, `\t`, `\n`, `\f` and `\r`. For strings,
///    integers up to 2^53, booleans, arrays and objects with ASCII member names,
///    that is exactly the RFC 8785 (JCS) form.
///
/// A record with no later member hashes exactly as it did in 0.2.1. Adding,
/// removing or changing any later member changes the hash. That includes a
/// member this version has never heard of, so a ledger written by a later
/// release still verifies here, as long as that release follows the same rule.
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
    /// What the record is about: a governed MCP request (`call`) when absent, or
    /// `admin`, `reload` or `upstream` (see [`Kind`]). Kept as written, so a kind
    /// named by a later release round-trips.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<String>,
    /// The resource URI the request named (`resources/read`, for example).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uri: Option<String>,
    /// The `transform` rules that fired, in the order they applied. Rule names
    /// only, never the values they changed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transforms: Option<Vec<String>>,
    /// A second identity behind the record, when there is one besides `agent`:
    /// the console user behind an `admin` record, or the client certificate's
    /// identity when `agent` is a bearer token's subject.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub actor: Option<String>,
    /// The network peer the request came from: the socket address, or the client
    /// address a trusted proxy forwarded.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub peer: Option<String>,
    /// On a `reload` record, the digest of the configuration in effect before it
    /// (`sha256:<hex>`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub config_from: Option<String>,
    /// On a `reload` record, the digest of the configuration it read: in effect
    /// from then on if the reload was applied, refused if not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub config_to: Option<String>,
    /// On an upstream's `tools-changed` record: how many of its tools it added,
    /// removed and changed, and how many of them now drift from their pins.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_changes: Option<ToolChanges>,
    /// Members this release does not know, from a ledger a later one wrote.
    #[serde(flatten)]
    pub extra: Extra,
    pub prev_hash: String,
    pub hash: String,
}

/// The field separator of the hash encoding (U+001F, the ASCII unit separator).
const US: char = '\u{1f}';

impl Record {
    /// Recompute this record's hash from its fields + `prev_hash`. Deterministic
    /// and independent of JSON field ordering (it hashes an explicit, delimited
    /// field encoding, not the serialized line).
    ///
    /// The encoding joins the fields with [`US`], so it is unambiguous only while
    /// no field contains one. [`Ledger::append`] guarantees that for every record
    /// it writes; a record from before it did is reported by [`verify`] in
    /// [`VerifyReport::ambiguous`].
    fn compute_hash(&self) -> String {
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
        if let Some(later) = self.later_members() {
            let mut sep = [0u8; 4];
            h.update(US.encode_utf8(&mut sep).as_bytes());
            h.update(later.as_bytes());
        }
        hex::encode(h.finalize())
    }

    /// Every member after the v1 record, as the hash encodes them: one canonical
    /// JSON object. `None` when there are none, so a v1-shaped record hashes as
    /// it always did.
    fn later_members(&self) -> Option<String> {
        let mut members: BTreeMap<&str, String> = BTreeMap::new();
        let strings = [
            ("kind", &self.kind),
            ("uri", &self.uri),
            ("actor", &self.actor),
            ("peer", &self.peer),
            ("config_from", &self.config_from),
            ("config_to", &self.config_to),
        ];
        for (name, value) in strings {
            if let Some(value) = value {
                members.insert(name, json_str(value));
            }
        }
        if let Some(transforms) = &self.transforms {
            let names: Vec<Value> = transforms.iter().cloned().map(Value::String).collect();
            members.insert("transforms", canonical_json(&Value::Array(names)));
        }
        if let Some(changes) = &self.tool_changes {
            members.insert("tool_changes", canonical_json(&changes.to_value()));
        }
        for (name, value) in self.extra.iter() {
            if !value.is_null() {
                members.insert(name, canonical_json(value));
            }
        }
        if members.is_empty() {
            return None;
        }
        let body: Vec<String> = members
            .iter()
            .map(|(name, value)| format!("{}:{value}", json_str(name)))
            .collect();
        Some(format!("{{{}}}", body.join(",")))
    }

    /// Whether a field holds the encoding's separator. The hash of such a record
    /// does not pin where one field ends and the next begins: a record denying a
    /// crafted tool name `x<US>allow` hashes the same as one *allowing* tool `x`
    /// with the rule `deny<US>…`.
    fn has_separator(&self) -> bool {
        let optional = [&self.method, &self.tool, &self.rule];
        self.agent.contains(US)
            || self.server.contains(US)
            || optional
                .iter()
                .any(|f| f.as_deref().is_some_and(|s| s.contains(US)))
    }
}

/// A field as the ledger stores it: [`US`] becomes U+241F (`␟`, its visible
/// symbol), so a caller-chosen name cannot carry a field boundary into the hash.
fn without_separator(s: String) -> String {
    if s.contains(US) {
        s.replace(US, "\u{241f}")
    } else {
        s
    }
}

/// A string as a JSON string literal.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("a string always serializes")
}

/// `value` as compact JSON with object members sorted by name at every level,
/// so the bytes depend only on the value, never on the order a line listed it
/// (nor on whether serde_json's `preserve_order` feature is on).
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (name, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_str(name));
                out.push(':');
                write_canonical(member, out);
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Record members this release does not know: written by a later one, and kept
/// as parsed so [`verify`] still covers them.
///
/// A member named twice in one line, at any depth, makes the record
/// [`AuditError::Corrupt`]. Resolving it to either value would let the verifier
/// and a SIEM that picks the other one read different records.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extra(BTreeMap<String, Value>);

impl Extra {
    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// One member's value.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// The members, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(name, value)| (name.as_str(), value))
    }
}

impl Serialize for Extra {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Extra {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExtraVisitor;

        impl<'de> Visitor<'de> for ExtraVisitor {
            type Value = Extra;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("record members")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Extra, A::Error> {
                collect_members(map).map(Extra)
            }
        }

        deserializer.deserialize_map(ExtraVisitor)
    }
}

/// An object's members, refusing one that is named twice.
fn collect_members<'de, A: MapAccess<'de>>(
    mut map: A,
) -> Result<BTreeMap<String, Value>, A::Error> {
    let mut members = BTreeMap::new();
    while let Some((name, Strict(value))) = map.next_entry::<String, Strict>()? {
        match members.entry(name) {
            MapEntry::Vacant(slot) => {
                slot.insert(value);
            }
            MapEntry::Occupied(slot) => {
                return Err(de::Error::custom(format_args!(
                    "duplicate field `{}`",
                    slot.key()
                )));
            }
        }
    }
    Ok(members)
}

/// A JSON value parsed by a visitor that refuses an object naming a member twice.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }

    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }

    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Strict, D::Error> {
        Strict::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Strict(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Strict, A::Error> {
        let members = collect_members(map)?;
        Ok(Strict(Value::Object(
            members.into_iter().collect::<Map<_, _>>(),
        )))
    }
}

/// The data the gateway hands the ledger for one record; the ledger stamps `seq`,
/// `ts`, `prev_hash`, and `hash`.
#[derive(Debug, Clone)]
pub struct Entry {
    pub agent: String,
    pub server: String,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub decision: Decision,
    pub latency_ms: u64,
    /// Everything beyond a plain governed call; `Attrs::default()` for one.
    pub attrs: Attrs,
}

/// The optional parts of an [`Entry`]; each lands in the [`Record`] member of
/// the same name. The default is a plain governed call and adds nothing to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    pub kind: Kind,
    pub uri: Option<String>,
    /// The `transform` rules that fired, in order. Empty records nothing.
    pub transforms: Vec<String>,
    pub actor: Option<String>,
    pub peer: Option<String>,
    /// On a reload: the digest of the configuration in effect before it.
    pub config_from: Option<String>,
    /// On a reload: the digest of the configuration it read.
    pub config_to: Option<String>,
    /// The rule behind an allowed record, when one applies: an upstream
    /// connected without checking its certificate is `tls-verify-disabled`.
    /// A denied record's rule is the one its decision names, and this is not
    /// read for it.
    pub rule: Option<String>,
    /// On an upstream's `tools-changed` record: how its tools changed.
    pub tool_changes: Option<ToolChanges>,
}

/// How an upstream's tools changed when it listed them again: the names it
/// added and removed, those whose definition changed, and how many of its tools
/// now drift from their pins that did not before.
///
/// All four counts are written, and a line whose `tool_changes` holds any other
/// member is corrupt: a member keeps the shape it first had, and a release that
/// needs to say more adds a member beside it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolChanges {
    pub added: u32,
    pub removed: u32,
    pub changed: u32,
    pub drifted: u32,
}

impl ToolChanges {
    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        *self == ToolChanges::default()
    }

    /// As the record and the exports write it: an object of the four counts.
    fn to_value(self) -> Value {
        serde_json::to_value(self).expect("tool changes serialize")
    }
}

/// What a record is about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Kind {
    /// A governed MCP request. Recorded by leaving `kind` out.
    #[default]
    Call,
    /// An action taken through the admin API or the console.
    Admin,
    /// A configuration reload, applied or refused.
    Reload,
    /// An upstream event: down, restarted, or connected without its
    /// certificate checked.
    Upstream,
}

impl Kind {
    /// The name a record stores.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Call => "call",
            Kind::Admin => "admin",
            Kind::Reload => "reload",
            Kind::Upstream => "upstream",
        }
    }
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
    ///
    /// A U+001F in any field is stored as U+241F (`␟`): the hash encoding uses
    /// U+001F as its separator, and a caller-chosen tool name must not be able to
    /// move a field boundary (see [`VerifyReport::ambiguous`]).
    pub fn append(&mut self, entry: Entry) -> Result<Record, AuditError> {
        let Attrs {
            kind,
            uri,
            transforms,
            actor,
            peer,
            config_from,
            config_to,
            rule,
            tool_changes,
        } = entry.attrs;
        let (rule, decision) = match &entry.decision {
            Decision::Allow => (rule, "allow".to_string()),
            Decision::Deny { rule, .. } => (Some(rule.clone()), "deny".to_string()),
        };
        let mut rec = Record {
            seq: self.next_seq,
            ts_unix_ms: now_unix_ms(),
            agent: without_separator(entry.agent),
            server: without_separator(entry.server),
            method: entry.method.map(without_separator),
            tool: entry.tool.map(without_separator),
            decision,
            rule: rule.map(without_separator),
            latency_ms: entry.latency_ms,
            kind: (kind != Kind::Call).then(|| kind.as_str().to_string()),
            uri,
            transforms: (!transforms.is_empty()).then_some(transforms),
            actor,
            peer,
            config_from,
            config_to,
            tool_changes,
            extra: Extra::default(),
            prev_hash: self.head.clone(),
            hash: String::new(),
        };
        rec.hash = rec.compute_hash();

        // The line and its newline in one write, so that a reader sees a
        // partial line as rarely as it can; it never reads one as a record.
        let mut line = serde_json::to_vec(&rec).expect("Record serializes");
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;

        self.head = rec.hash.clone();
        self.next_seq += 1;
        Ok(rec)
    }
}

/// A cloneable handle to one [`Ledger`], for appending from many tasks at once.
///
/// Appends take turns on a first-in, first-out async lock, and the holder writes
/// its record before letting go. The lock's order is therefore the chain's order:
/// `seq` stays contiguous and every `prev_hash` names the record before it.
///
/// - [`append`](Self::append) resolves once the record is written, with the same
///   write + flush as [`Ledger::append`] (not an `fsync`).
/// - While another append is writing, `append` waits its turn: backpressure,
///   never a dropped record.
/// - Nothing is awaited between taking the lock and writing, so an append that
///   has its turn always writes its record, even if its caller then stops
///   waiting. A caller dropped while still waiting has handed nothing over.
///
/// Whoever holds the lock writes, so there is no hand-off to a writer task or
/// thread. That is the point: sending each record to a writer on another thread
/// and waking the caller again measured +12 to +63 µs per append (+46 µs p50 on a
/// denied call through the gateway), against about 4 µs for the write itself. A
/// durable mode would keep this lock for ordering and add a commit task that
/// `fsync`s after a group of writes and releases the appends it covers.
#[derive(Clone)]
pub struct LedgerHandle {
    shared: Arc<tokio::sync::Mutex<Shared>>,
    state: watch::Receiver<Head>,
    path: Arc<PathBuf>,
}

/// The ledger, and where each append publishes the new head.
struct Shared {
    ledger: Ledger,
    publish: watch::Sender<Head>,
}

/// The chain's position after the last write.
struct Head {
    hash: String,
    next_seq: u64,
}

impl Head {
    fn of(ledger: &Ledger) -> Head {
        Head {
            hash: ledger.head().to_string(),
            next_seq: ledger.next_seq(),
        }
    }
}

impl LedgerHandle {
    pub fn new(ledger: Ledger) -> LedgerHandle {
        let (publish, state) = watch::channel(Head::of(&ledger));
        let path = Arc::new(ledger.path().to_path_buf());
        LedgerHandle {
            shared: Arc::new(tokio::sync::Mutex::new(Shared { ledger, publish })),
            state,
            path,
        }
    }

    /// Append one entry, returning the stamped, hash-linked record once it is
    /// written. See [`LedgerHandle`] for ordering, backpressure and cancellation.
    pub async fn append(&self, entry: Entry) -> Result<Record, AuditError> {
        let mut shared = self.shared.lock().await;
        let record = shared.ledger.append(entry)?;
        let head = Head::of(&shared.ledger);
        shared.publish.send_replace(head);
        Ok(record)
    }

    /// The head hash after the last write (or [`GENESIS`] for an empty ledger).
    pub fn head(&self) -> String {
        self.state.borrow().hash.clone()
    }

    /// The sequence number the next appended record will take.
    pub fn next_seq(&self) -> u64 {
        self.state.borrow().next_seq
    }

    /// How many records the ledger holds and the head they end in, read
    /// together.
    pub fn written(&self) -> (u64, String) {
        let head = self.state.borrow();
        (head.next_seq, head.hash.clone())
    }

    /// What wakes a reader each time records are appended.
    pub fn appends(&self) -> Appends {
        let mut state = self.state.clone();
        state.mark_unchanged();
        Appends(state)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Wakes a reader of a [`LedgerHandle`]'s file when records are appended.
pub struct Appends(watch::Receiver<Head>);

impl Appends {
    /// Waits until a record is appended after the last wait (or, the first
    /// time, after this was made); `false` once the ledger is gone. Several
    /// appends between two waits wake it once.
    pub async fn wait(&mut self) -> bool {
        self.0.changed().await.is_ok()
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
    /// Records whose fields contain U+001F, the hash encoding's separator. The
    /// chain still covers them, but their hash does not pin where one field ends
    /// and the next begins, so their fields could have been re-split without
    /// breaking it. [`Ledger::append`] never writes one; an older gateway did, for
    /// a crafted tool or method name.
    pub ambiguous: Vec<u64>,
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
    verify_marked(path, None).map(|(report, _)| report)
}

/// [`verify`], taking on the way the `hash` of the record numbered `mark`,
/// if the file holds one: what a reader that knows how far a gateway had
/// written compares, to see that what it wrote is still there.
pub fn verify_marked(
    path: impl AsRef<Path>,
    mark: Option<u64>,
) -> Result<(VerifyReport, Option<String>), AuditError> {
    let file = File::open(path)?;
    let mut marked = None;
    let mut prev = GENESIS.to_string();
    let mut expected_seq: u64 = 0;
    let mut records: u64 = 0;
    let mut head = GENESIS.to_string();
    let mut broken_at: Option<u64> = None;
    let mut ambiguous = Vec::new();

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
        if rec.has_separator() {
            ambiguous.push(rec.seq);
        }
        if marked.is_none() && mark == Some(rec.seq) {
            marked = Some(rec.hash.clone());
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

    Ok((
        VerifyReport {
            records,
            head,
            broken_at,
            ambiguous,
        },
        marked,
    ))
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
    /// fields the schema has no home for go under `unmapped`: every later member is
    /// there, including any this release does not know, and `peer` and `uri` also
    /// fill `src_endpoint` and `resources`.
    fn to_ocsf(&self) -> String {
        let (status, status_id, severity_id) = if self.is_deny() {
            ("Failure", 2, 2) // Low
        } else {
            ("Success", 1, 1) // Informational
        };
        let activity_id = if self.is_deny() { 2 } else { 1 };
        let mut obj = serde_json::json!({
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
        if let Some(peer) = &self.peer {
            obj["src_endpoint"] = ocsf_endpoint(peer);
        }
        if let Some(uri) = &self.uri {
            obj["resources"] = serde_json::json!([{ "uid": uri }]);
        }
        let unmapped = &mut obj["unmapped"];
        let strings = [
            ("kind", &self.kind),
            ("uri", &self.uri),
            ("actor", &self.actor),
            ("peer", &self.peer),
            ("config_from", &self.config_from),
            ("config_to", &self.config_to),
        ];
        for (name, value) in strings {
            if let Some(value) = value {
                unmapped[name] = Value::String(value.clone());
            }
        }
        if let Some(transforms) = &self.transforms {
            unmapped["transforms"] = Value::from(transforms.clone());
        }
        if let Some(changes) = &self.tool_changes {
            unmapped["tool_changes"] = changes.to_value();
        }
        for (name, value) in self.extra.iter() {
            unmapped[name] = value.clone();
        }
        serde_json::to_string(&obj).expect("ocsf object serializes")
    }

    /// ArcSight CEF:0. Header pipes/backslashes and extension `=`/backslashes are
    /// escaped per the CEF spec. Severity: allow → 2, deny → 7. The later members
    /// map to `cs3` (kind), `cs4` (actor), `cs5` (transforms, as a JSON array),
    /// `cs6` (tool_changes, as a JSON object), `request` (uri), `src`/`c6a2` +
    /// `spt` or `shost` (peer), and `oldFileHash` and `fileHash` (a reload's
    /// `config_from` and `config_to`). Members this release does not know are left
    /// to the JSON and OCSF exports.
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
        if let Some(kind) = &self.kind {
            ext.push_str(&format!(" cs3Label=kind cs3={}", cef_ext_escape(kind)));
        }
        if let Some(actor) = &self.actor {
            ext.push_str(&format!(" cs4Label=actor cs4={}", cef_ext_escape(actor)));
        }
        if let Some(transforms) = &self.transforms {
            let list = canonical_json(&Value::from(transforms.clone()));
            ext.push_str(&format!(
                " cs5Label=transforms cs5={}",
                cef_ext_escape(&list)
            ));
        }
        if let Some(changes) = &self.tool_changes {
            let counts = canonical_json(&changes.to_value());
            ext.push_str(&format!(
                " cs6Label=toolChanges cs6={}",
                cef_ext_escape(&counts)
            ));
        }
        if let Some(uri) = &self.uri {
            ext.push_str(&format!(" request={}", cef_ext_escape(uri)));
        }
        if let Some(from) = &self.config_from {
            ext.push_str(&format!(" oldFileHash={}", cef_ext_escape(from)));
        }
        if let Some(to) = &self.config_to {
            ext.push_str(&format!(" fileHash={}", cef_ext_escape(to)));
        }
        if let Some(peer) = &self.peer {
            // CEF's `src` is an IPv4 address; an IPv6 source has its own field.
            let port = |port: u16| format!(" spt={port}");
            match parse_peer(peer) {
                Some((IpAddr::V4(ip), p)) => {
                    ext.push_str(&format!(" src={ip}"));
                    ext.extend(p.map(port));
                }
                Some((IpAddr::V6(ip), p)) => {
                    ext.push_str(&format!(" c6a2Label=Source IPv6 Address c6a2={ip}"));
                    ext.extend(p.map(port));
                }
                None => ext.push_str(&format!(" shost={}", cef_ext_escape(peer))),
            }
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
    /// structured-data element; the human message follows. The later members are
    /// parameters of that element when present (`transforms` as a JSON array,
    /// `tool_changes` as a JSON object); members this release does not know are
    /// left to the JSON and OCSF exports.
    fn to_syslog(&self) -> String {
        let severity = if self.is_deny() { 4 } else { 6 };
        let pri = 10 * 8 + severity;
        let ts = rfc3339_utc(self.ts_unix_ms);
        let mut sd = format!(
            "[mcpdef@0 seq=\"{seq}\" server=\"{server}\" tool=\"{tool}\" decision=\"{dec}\" rule=\"{rule}\" latencyMs=\"{lat}\"",
            seq = self.seq,
            server = sd_escape(&self.server),
            tool = sd_escape(self.tool.as_deref().unwrap_or("")),
            dec = sd_escape(&self.decision),
            rule = sd_escape(self.rule.as_deref().unwrap_or("")),
            lat = self.latency_ms,
        );
        let strings = [
            ("kind", &self.kind),
            ("uri", &self.uri),
            ("actor", &self.actor),
            ("peer", &self.peer),
            ("config_from", &self.config_from),
            ("config_to", &self.config_to),
        ];
        for (name, value) in strings {
            if let Some(value) = value {
                sd.push_str(&format!(" {name}=\"{}\"", sd_escape(value)));
            }
        }
        if let Some(transforms) = &self.transforms {
            let list = canonical_json(&Value::from(transforms.clone()));
            sd.push_str(&format!(" transforms=\"{}\"", sd_escape(&list)));
        }
        if let Some(changes) = &self.tool_changes {
            let counts = canonical_json(&changes.to_value());
            sd.push_str(&format!(" tool_changes=\"{}\"", sd_escape(&counts)));
        }
        sd.push_str(&format!(" hash=\"{}\"]", sd_escape(&self.hash)));
        format!(
            "<{pri}>1 {ts} - mcpdef - {msgid} {sd} {msg}",
            msgid = syslog_msgid(self.method.as_deref()),
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

/// A method as an RFC 5424 MSGID: 1 to 32 printable US-ASCII characters, with
/// anything else (a space, a control or non-ASCII character) as `_`, and `-` (the
/// nil value) for none. The method is caller-chosen: a space left in it would end
/// the MSGID early and let the rest pose as structured data. The full method is
/// still in the message text.
fn syslog_msgid(method: Option<&str>) -> String {
    let id: String = method
        .unwrap_or_default()
        .chars()
        .take(32)
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    if id.is_empty() {
        "-".to_string()
    } else {
        id
    }
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

/// A peer's IP and port when it is a socket address, or its IP when it is only
/// that. `None` for anything else (a hostname, say).
fn parse_peer(peer: &str) -> Option<(IpAddr, Option<u16>)> {
    match peer.parse::<SocketAddr>() {
        Ok(addr) => Some((addr.ip(), Some(addr.port()))),
        Err(_) => peer.parse::<IpAddr>().ok().map(|ip| (ip, None)),
    }
}

/// An OCSF network endpoint for a peer: its IP (and port) when it has one, its
/// name otherwise.
fn ocsf_endpoint(peer: &str) -> Value {
    match parse_peer(peer) {
        Some((ip, Some(port))) => serde_json::json!({ "ip": ip.to_string(), "port": port }),
        Some((ip, None)) => serde_json::json!({ "ip": ip.to_string() }),
        None => serde_json::json!({ "name": peer }),
    }
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
            attrs: Attrs::default(),
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

    /// RFC 5424's MSGID is 1 to 32 printable US-ASCII characters, and syslog
    /// takes it from `method`, which a caller chooses (a forwarded method is
    /// audited as sent). A space in it would end the MSGID early and let the rest
    /// pose as the record's structured data.
    #[test]
    fn a_crafted_method_cannot_pose_as_syslog_structured_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut led = Ledger::open(&path).unwrap();
        let methods = [
            (
                Some("x [mcpdef@0 decision=\"allow\" tool=\"safe\"]"),
                "x_[mcpdef@0_decision=\"allow\"_too",
            ),
            (
                Some("notifications/resources/list_changed"),
                "notifications/resources/list_cha",
            ),
            (Some("résumé"), "r_sum_"),
            (Some(""), "-"),
            (None, "-"),
        ];
        for (method, msgid) in methods {
            let mut e = entry("github", "delete_repo", Decision::Allow);
            e.method = method.map(String::from);
            let s = led.append(e).unwrap().export(ExportFormat::Syslog);
            // PRI+VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
            let header: Vec<&str> = s.splitn(7, ' ').collect();
            assert_eq!(header[5], msgid, "{s}");
            assert!(header[6].starts_with("[mcpdef@0 seq=\""), "{s}");
        }
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

    /// Every later member, plus two a later release might add (one nested, its
    /// members out of order) and one that is `null`. The expected value comes
    /// from an independent implementation of the rule on [`Record`]: Python's
    /// `json.dumps(members, sort_keys=True, separators=(",", ":"),
    /// ensure_ascii=False)` after the v1 encoding.
    #[test]
    fn later_members_hash_to_the_reference_vector() {
        let line = r#"{"seq":3,"ts_unix_ms":1790000000000,"agent":"sub:alice","server":"github","method":"resources/read","decision":"deny","rule":"resource-not-allowed","latency_ms":7,"kind":"upstream","uri":"file:///etc/\"quoted\"\npath","transforms":["clamp-limit","redact-secrets"],"actor":"spiffe://example.org/agent","peer":"203.0.113.7:51234","zeta":{"b":[1,"two",true,null],"a":"é\u001f"},"config":"sha256:abc","gone":null,"prev_hash":"abababababababababababababababababababababababababababababababab","hash":""}"#;
        let rec: Record = serde_json::from_str(line).unwrap();
        assert_eq!(rec.extra.get("config"), Some(&Value::from("sha256:abc")));
        assert_eq!(
            rec.compute_hash(),
            "2de95b75d3127fab69e43a403da680abe3d71316045391b8b62183ce117a599d"
        );
    }

    /// A typed later member hashes as the same member would under the generic
    /// rule, so a verifier that has never heard of it still agrees.
    #[test]
    fn a_config_digest_hashes_as_an_unknown_member_would() {
        let typed: Record = serde_json::from_str(
            r#"{"seq":0,"ts_unix_ms":1,"agent":"mcpdef","server":"(config)","method":"reload","decision":"allow","latency_ms":2,"kind":"reload","config_from":"sha256:aa","config_to":"sha256:bb","prev_hash":"","hash":""}"#,
        )
        .unwrap();
        assert_eq!(typed.config_to.as_deref(), Some("sha256:bb"));
        let mut unknown = typed.clone();
        (unknown.config_from, unknown.config_to) = (None, None);
        unknown.extra = serde_json::from_value(serde_json::json!({
            "config_from": "sha256:aa",
            "config_to": "sha256:bb",
        }))
        .unwrap();
        assert_eq!(typed.compute_hash(), unknown.compute_hash());
        assert_ne!(typed.compute_hash(), {
            let mut plain = typed.clone();
            plain.config_to = None;
            plain.compute_hash()
        });
    }

    /// The same for `tool_changes`, an object: 0.4.0-alpha.1 keeps it as a
    /// member it does not know, and hashes it to the same value.
    #[test]
    fn tool_changes_hash_as_an_unknown_member_would() {
        let typed: Record = serde_json::from_str(
            r#"{"seq":0,"ts_unix_ms":1,"agent":"mcpdef","server":"files","method":"tools-changed","decision":"allow","latency_ms":2,"kind":"upstream","tool_changes":{"drifted":0,"removed":2,"changed":3,"added":1},"prev_hash":"","hash":""}"#,
        )
        .unwrap();
        assert_eq!(
            typed.tool_changes,
            Some(ToolChanges {
                added: 1,
                removed: 2,
                changed: 3,
                drifted: 0
            })
        );
        let mut unknown = typed.clone();
        unknown.tool_changes = None;
        unknown.extra = serde_json::from_value(serde_json::json!({
            "tool_changes": { "added": 1, "changed": 3, "drifted": 0, "removed": 2 },
        }))
        .unwrap();
        assert_eq!(typed.compute_hash(), unknown.compute_hash());
        for changed in [
            ToolChanges::default(),
            ToolChanges {
                drifted: 1,
                ..typed.tool_changes.unwrap()
            },
        ] {
            let mut other = typed.clone();
            other.tool_changes = Some(changed);
            assert_ne!(typed.compute_hash(), other.compute_hash(), "{changed:?}");
        }
    }

    /// A ledger from a later release that added a member under the same rule
    /// verifies here, and dropping that member breaks it.
    #[test]
    fn a_member_from_a_later_release_is_covered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let mut led = Ledger::open(&path).unwrap();
            led.append(entry("github", "list_issues", Decision::Allow))
                .unwrap();
            led.append(entry("github", "get_issue", Decision::Allow))
                .unwrap();
        }
        // What the later writer would have produced for record 1.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
        rec.extra = serde_json::from_value(serde_json::json!({
            "config": "sha256:abc",
            "approval": { "by": "carol", "ticket": 42 },
        }))
        .unwrap();
        rec.hash = rec.compute_hash();
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify(&path).unwrap();
        assert!(report.ok(), "broken at {:?}", report.broken_at);
        let back = read_all(&path).unwrap();
        assert_eq!(
            back[1].extra.get("config"),
            Some(&Value::from("sha256:abc"))
        );
        assert_eq!(back[1], rec);

        let mut member: Value = serde_json::from_str(&lines[1]).unwrap();
        member.as_object_mut().unwrap().remove("approval");
        lines[1] = member.to_string();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert_eq!(verify(&path).unwrap().broken_at, Some(1));
    }
}
