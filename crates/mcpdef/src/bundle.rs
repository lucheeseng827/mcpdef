// SPDX-License-Identifier: Apache-2.0
//! Signed policy bundles: a node's config at a revision, signed, so that a
//! node can be handed its policy and check it before it takes it, as a node
//! with no route out is.
//!
//! A bundle is one JSON object:
//!
//! ```json
//! {
//!   "config": "<the mcpdef.toml, as text>",
//!   "issued_at": "2026-10-27T16:30:00.000Z",
//!   "mcpdef_bundle": 1,
//!   "revision": 7,
//!   "signature": { "alg": "EdDSA", "kid": "mcpdef:bundle:…", "sig": "…" }
//! }
//! ```
//!
//! The signature is Ed25519 over the RFC 8785 (JCS) form of the object
//! without its `signature`, in lowercase hex, as a receipt's is. A bundle
//! with any other member, or another format, is not one this release reads.
//!
//! A node takes a bundle with [`apply`], which refuses:
//!
//! - one that no key the node trusts signed, or whose signature does not
//!   verify. The keys come from the node, never from the bundle;
//! - a revision lower than the highest the node applied, its floor, kept in
//!   `state_dir`, and one equal to it with another config. The same bundle
//!   again changes nothing;
//! - a config that does not parse or validate, or names a file the node does
//!   not have.
//!
//! What it applies, it raises the floor to, writes in place of the config at
//! once, and records in the ledger, as it records each refusal. A bundle's
//! revision only goes up: a rollback is the earlier config signed again at a
//! new revision, and an old bundle replayed is refused like any older one.
//!
//! [`apply`] keeps the bundle beside the config too, as `mcpdef.toml.bundle`
//! ([`beside`]). A gateway started with `--bundle-trust` holds its config to
//! it: at the start ([`admit`]) and at each reload, it runs the config only
//! when a key it trusts signed that bundle, the bundle holds the config as it
//! is ([`held`]), and its revision is no lower than the floor's or the one it
//! runs ([`succeeds`]). A config changed in place, or put back from an older
//! bundle, is refused, and a running gateway keeps the configuration it had.

use crate::config::Config;
use crate::reload::Snapshot;
use anyhow::{bail, Context, Result};
use mcpdef_audit::receipt::{canonical, Keys, SigningKey, EDDSA};
use mcpdef_audit::{rfc3339_utc, Attrs, BundleRef, Entry, Kind, GATEWAY_AGENT};
use mcpdef_core::Decision;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The format of bundle this release writes and reads: its `mcpdef_bundle`.
pub const FORMAT: u64 = 1;

/// What the `kid` of a key `mcpdef bundle key` makes starts with.
pub const KID_PREFIX: &str = "mcpdef:bundle:";

/// The highest revision: the highest integer JCS writes exactly.
pub const MAX_REVISION: u64 = (1 << 53) - 1;

/// The file in `state_dir` that holds a node's floor.
pub const FLOOR_FILE: &str = "bundle.json";

/// A bundle as its file holds it, before its signature is checked. A
/// member it does not have, or one named twice, is refused as it is read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    config: String,
    issued_at: String,
    mcpdef_bundle: u64,
    revision: u64,
    signature: WireSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    alg: String,
    kid: String,
    sig: String,
}

/// A bundle whose signature a key the node trusts verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// It goes up from one bundle to the next.
    pub revision: u64,
    /// When it was signed, as the signer's clock had it: RFC 3339, UTC.
    pub issued_at: String,
    /// The config, as `mcpdef.toml` holds it.
    pub config: String,
    /// The key that signed it.
    pub kid: String,
    /// `sha256:<hex>` of the bundle as its file holds it.
    pub file: String,
}

impl Bundle {
    /// `sha256:<hex>` of its config's text: which config the floor names.
    pub fn config_digest(&self) -> String {
        sha256(self.config.as_bytes())
    }

    /// As the ledger's `bundle` member names it.
    pub fn named(&self) -> BundleRef {
        BundleRef {
            sha256: self.file.clone(),
            revision: Some(self.revision),
            kid: Some(self.kid.clone()),
        }
    }
}

/// Why a bundle is not applied. Its [`rule`](Refused::rule) is the ledger's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not a bundle, signed by no key the node trusts, or not as it is now.
    Unverified(String),
    /// Lower than the floor, or at the floor with another config.
    Older(String),
    /// A config that does not parse or validate.
    Invalid(Vec<String>),
}

impl Refused {
    /// As the ledger's `rule` names it.
    pub fn rule(&self) -> &'static str {
        match self {
            Refused::Unverified(_) => "bundle-unverified",
            Refused::Older(_) => "bundle-older",
            Refused::Invalid(_) => "bundle-invalid",
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::Unverified(why) | Refused::Older(why) => f.write_str(why),
            Refused::Invalid(errors) => {
                write!(f, "its config is not valid: {}", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for Refused {}

/// `sha256:<hex>` of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Now, in RFC 3339, as a bundle's `issued_at` has it.
pub fn now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    rfc3339_utc(ms)
}

/// The bundle of `config` at `revision`, signed with `key` at `issued_at`, as
/// the text of its file. Check the config first: a node refuses one that
/// does not validate.
pub fn sign(config: &str, revision: u64, issued_at: &str, key: &SigningKey) -> Result<String> {
    if !(1..=MAX_REVISION).contains(&revision) {
        bail!("a revision is from 1 to {MAX_REVISION}, and {revision} is not");
    }
    let mut bundle = json!({
        "config": config,
        "issued_at": issued_at,
        "mcpdef_bundle": FORMAT,
        "revision": revision,
    });
    let signed = canonical(&bundle)?;
    bundle["signature"] = json!({
        "alg": EDDSA,
        "kid": key.kid(),
        "sig": hex::encode(key.sign(signed.as_bytes())),
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&bundle)?))
}

/// The bundle `text` holds, if a key in `keys` signed it as it is.
pub fn open(text: &str, keys: &Keys) -> Result<Bundle, Refused> {
    let unverified = |why: String| Refused::Unverified(why);
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(doc)) if !doc.contains_key("signature") => {
            return Err(unverified("it is not signed: it has no `signature`".into()))
        }
        Ok(Value::Object(_)) => {}
        Ok(_) => {
            return Err(unverified(
                "it is not a bundle: a bundle is a JSON object".into(),
            ))
        }
        Err(e) => return Err(unverified(format!("it is not a bundle: {e}"))),
    }
    // Read again, typed, so that a member named twice is refused rather than
    // taken at its last: what is signed is then all there is.
    let wire: Wire = serde_json::from_str(text)
        .map_err(|e| unverified(format!("it is not a bundle of format {FORMAT}: {e}")))?;
    if wire.mcpdef_bundle != FORMAT {
        return Err(unverified(format!(
            "it is not a bundle of format {FORMAT}: its `mcpdef_bundle` is {}",
            wire.mcpdef_bundle
        )));
    }
    if !(1..=MAX_REVISION).contains(&wire.revision) {
        return Err(unverified(format!(
            "its `revision` is not an integer from 1 to {MAX_REVISION}"
        )));
    }
    let WireSignature { alg, kid, sig } = wire.signature;
    if alg != EDDSA {
        return Err(unverified(format!(
            "it is signed with {alg}: a bundle is signed with {EDDSA}"
        )));
    }
    let sig = lower_hex(&sig).ok_or_else(|| unverified("its `sig` is not lowercase hex".into()))?;
    let signed = json!({
        "config": wire.config,
        "issued_at": wire.issued_at,
        "mcpdef_bundle": wire.mcpdef_bundle,
        "revision": wire.revision,
    });
    let message =
        canonical(&signed).map_err(|e| unverified(format!("it has no canonical form: {e}")))?;
    keys.verify(&kid, &alg, message.as_bytes(), &sig)
        .map_err(Refused::Unverified)?;
    Ok(Bundle {
        revision: wire.revision,
        issued_at: wire.issued_at,
        config: wire.config,
        kid,
        file: sha256(text.as_bytes()),
    })
}

fn lower_hex(text: &str) -> Option<Vec<u8>> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(text).ok()
}

/// The highest revision a node applied, in its `state_dir`: a bundle below
/// it is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub revision: u64,
    /// `sha256:<hex>` of that revision's config text.
    pub config: String,
    /// The key that signed it.
    pub kid: String,
    /// When the node applied it: RFC 3339, UTC.
    pub applied_at: String,
}

impl Floor {
    /// The floor at `bundle`, applied at `applied_at`.
    pub fn of(bundle: &Bundle, applied_at: String) -> Floor {
        Floor {
            revision: bundle.revision,
            config: bundle.config_digest(),
            kid: bundle.kid.clone(),
            applied_at,
        }
    }

    /// The floor kept in `state_dir`, `None` when there is none. One that is
    /// there and does not read is an error, never no floor.
    pub fn read(state_dir: &Path) -> Result<Option<Floor>> {
        let path = state_dir.join(FLOOR_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        serde_json::from_str(&text).map(Some).with_context(|| {
            format!(
                "{} is not a bundle floor: fix it, or remove it to let any revision in",
                path.display()
            )
        })
    }

    /// Keep this floor in `state_dir`, in place of the one there.
    pub fn write(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        let text = format!("{}\n", serde_json::to_string_pretty(self)?);
        let path = state_dir.join(FLOOR_FILE);
        replace(&path, &text, &path)
    }
}

/// The highest floor kept in any of `dirs`, `None` when there is none.
pub fn highest_floor(dirs: &[PathBuf]) -> Result<Option<Floor>> {
    let mut floor: Option<Floor> = None;
    for dir in dirs {
        if let Some(found) = Floor::read(dir)? {
            if floor.as_ref().is_none_or(|f| found.revision > f.revision) {
                floor = Some(found);
            }
        }
    }
    Ok(floor)
}

/// Whether `bundle` may be applied over `floor`: `true` to apply it, `false`
/// for the bundle the floor is already at.
pub fn admits(floor: Option<&Floor>, bundle: &Bundle) -> Result<bool, Refused> {
    let Some(floor) = floor else {
        return Ok(true);
    };
    match bundle.revision.cmp(&floor.revision) {
        Ordering::Greater => Ok(true),
        Ordering::Equal if bundle.config_digest() == floor.config => Ok(false),
        Ordering::Equal => Err(Refused::Older(format!(
            "revision {} is the one this node applied, with another config: a new config takes \
             a new revision",
            bundle.revision
        ))),
        Ordering::Less => Err(Refused::Older(format!(
            "revision {} is older than revision {}, which this node applied: to go back, sign \
             the earlier config again at a revision above {}",
            bundle.revision, floor.revision, floor.revision
        ))),
    }
}

/// The file beside a config that holds the bundle [`apply`] put the config in
/// place from: `mcpdef.toml.bundle` beside `mcpdef.toml`.
pub fn beside(config: &Path) -> PathBuf {
    named_after(config, "", ".bundle")
}

/// Run `f` holding the lock an apply holds while it changes the config at
/// `config`, so that what `f` reads of the config, the bundle beside it and
/// the floor is all from before an apply or all from after it. Where the lock
/// cannot be opened, `f` runs without it: it may then read an apply half
/// done, which [`held`] and [`succeeds`] refuse, and never let in.
pub fn holding<T>(config: &Path, f: impl FnOnce() -> T) -> T {
    let path = lock_beside(config);
    let opened = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        // Made by another user, it can still be locked if it can be read.
        .or_else(|_| File::open(&path));
    let Ok(file) = opened else {
        return f();
    };
    let mut lock = fd_lock::RwLock::new(file);
    // Held while `f` runs, where it could be taken.
    let _turn = lock.write();
    f()
}

/// Whether the config `text`, read from `config`, is one the bundle beside it
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The ledger's `bundle` member: `None` when there is no bundle beside
    /// the config. Its revision and key are there once its signature verified.
    pub named: Option<BundleRef>,
    /// The bundle, if a key trusted signed it as it is and it holds the config
    /// as it was read; or why not.
    pub verdict: Result<Bundle, Refused>,
}

/// Whether the config `text`, read from `config`, is held by the bundle
/// beside it: signed by a key in `keys`, as it is, and holding `text` as it
/// is. Read the config first: [`apply`] writes the bundle beside it before
/// the config, so a config read is one whose bundle was there already.
pub fn held(config: &Path, text: &[u8], keys: &Keys) -> Held {
    let path = beside(config);
    let unverified = |why: String| Refused::Unverified(format!("{}: {why}", path.display()));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => Refused::Unverified(format!(
                    "there is no {}: `mcpdef bundle apply` keeps one beside the config it puts \
                     in place",
                    path.display()
                )),
                _ => unverified(format!("reading it: {e}")),
            };
            return Held {
                named: None,
                verdict: Err(why),
            };
        }
    };
    let unnamed = BundleRef {
        sha256: sha256(&bytes),
        revision: None,
        kid: None,
    };
    let opened = std::str::from_utf8(&bytes)
        .map_err(|_| Refused::Unverified("it is not a bundle: it is not UTF-8".into()))
        .and_then(|text| open(text, keys));
    let bundle = match opened {
        Ok(bundle) => bundle,
        Err(refusal) => {
            return Held {
                named: Some(unnamed),
                verdict: Err(unverified(refusal.to_string())),
            }
        }
    };
    let named = Some(bundle.named());
    if bundle.config.as_bytes() != text {
        return Held {
            named,
            verdict: Err(Refused::Unverified(format!(
                "{} is not the config that {}, revision {}, holds: put a signed one in place \
                 with `mcpdef bundle apply`",
                config.display(),
                path.display(),
                bundle.revision
            ))),
        };
    }
    Held {
        named,
        verdict: Ok(bundle),
    }
}

/// Whether `bundle` may take the place of `running`, the bundle a gateway
/// runs, whose config keeps its floor in `state_dir`: its revision no lower
/// than the floor's, there and in the `state_dir` its own config names, nor
/// than `running`'s, and at the same revision, the same config. `Err` when a
/// floor does not read.
pub fn succeeds(
    bundle: &Bundle,
    running: &Bundle,
    state_dir: &Path,
) -> Result<Result<(), Refused>> {
    // The floor of the state kept now, and of the one the bundle names,
    // which a bundle may move, as `apply` reads them.
    let mut dirs = vec![state_dir.to_path_buf()];
    if let Ok(new) = Config::parse(&bundle.config) {
        dirs.push(PathBuf::from(new.gateway.state_dir));
        dirs.dedup();
    }
    let floor = highest_floor(&dirs)?;
    // The revision running is a floor too, should the one kept be gone.
    let running = Floor::of(running, String::new());
    let verdict = [floor.as_ref(), Some(&running)]
        .into_iter()
        .try_for_each(|floor| admits(floor, bundle).map(drop));
    Ok(verdict)
}

/// A config a gateway started with `--bundle-trust` may run, as [`admit`]
/// read it.
#[derive(Debug, Clone)]
pub struct Admitted {
    /// The config, as its file holds it.
    pub text: String,
    pub config: Config,
    /// The bundle beside it, which holds it.
    pub bundle: Bundle,
}

/// The config at `config`, for a gateway that runs only one a signed bundle
/// holds: refused unless the bundle beside it holds it ([`held`]) at a
/// revision no lower than the floor in the `state_dir` it names. Raise the
/// floor to it with [`raise`] once it is to run.
pub fn admit(config: &Path, keys: &Keys) -> Result<Admitted> {
    holding(config, || {
        let text = std::fs::read_to_string(config)
            .with_context(|| format!("reading config {}", config.display()))?;
        let not_run = |refusal: Refused| {
            anyhow::Error::new(refusal).context(format!(
                "not running {}: --bundle-trust runs only a config the signed bundle beside it \
                 holds",
                config.display()
            ))
        };
        // What no bundle holds is refused before anything else is said of it.
        let bundle = held(config, text.as_bytes(), keys)
            .verdict
            .map_err(not_run)?;
        let parsed =
            Config::parse(&text).with_context(|| format!("parsing TOML {}", config.display()))?;
        let floor = highest_floor(&[PathBuf::from(&parsed.gateway.state_dir)])?;
        admits(floor.as_ref(), &bundle).map_err(not_run)?;
        Ok(Admitted {
            text,
            config: parsed,
            bundle,
        })
    })
}

/// Raise the floor in `state_dir` to `bundle`, which the gateway runs, where
/// it is lower or there is none: `true` if it was. Call it [`holding`] the
/// lock, which an apply that raises it too holds.
pub fn raise(state_dir: &Path, bundle: &Bundle) -> Result<bool> {
    if Floor::read(state_dir)?.is_some_and(|f| f.revision >= bundle.revision) {
        return Ok(false);
    }
    Floor::of(bundle, now()).write(state_dir)?;
    Ok(true)
}

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The bundle's config is in place, over the revision `from` (`None` on
    /// a node that had applied none).
    Applied { bundle: Bundle, from: Option<u64> },
    /// The bundle is the one the node applied last: nothing changed.
    Already(Bundle),
}

/// Apply the bundle at `bundle`, checked against `keys`, in place of the
/// config at `config`. Each outcome but [`Applied::Already`] is recorded in
/// the ledger: that of the config in effect before it, which a running
/// gateway writes to, or the bundle's when there is none. A refusal is an
/// error, and leaves the config and the floor as they were.
///
/// One apply at a time: each holds a lock beside the config throughout, so
/// that two cannot both read the floor before either raises it. It keeps the
/// bundle beside the config too ([`beside`]), which a gateway started with
/// `--bundle-trust` holds the config to.
pub fn apply(bundle: &Path, keys: &Keys, config: &Path) -> Result<Applied> {
    let started = Instant::now();
    let lock_path = lock_beside(config);
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    let mut lock = fd_lock::RwLock::new(lock_file);
    let _turn = lock
        .write()
        .with_context(|| format!("locking {}", lock_path.display()))?;
    let bytes = std::fs::read(bundle).with_context(|| format!("reading {}", bundle.display()))?;
    let file = sha256(&bytes);
    let before = std::fs::read(config).ok();
    let old = before
        .as_deref()
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|text| Config::parse(text).ok());
    let from = match (&before, &old) {
        (Some(text), Some(old)) => Some(Snapshot::take(text, old).digest().to_string()),
        (Some(text), None) => Some(sha256(text)),
        (None, _) => None,
    };
    let refused = |refusal: Refused, verified: Option<&Bundle>, cfg: Option<&Config>| {
        let named = BundleRef {
            sha256: file.clone(),
            revision: verified.map(|b| b.revision),
            kid: verified.map(|b| b.kid.clone()),
        };
        if let Some(cfg) = cfg {
            let entry = entry(Some(refusal.rule()), named, from.clone(), None, started);
            if let Err(e) = crate::hook::record(cfg, entry) {
                eprintln!("mcpdef: the refusal is not in the ledger: {e:#}");
            }
        }
        anyhow::Error::new(refusal).context(format!("{} is not applied", bundle.display()))
    };

    let text = String::from_utf8(bytes).map_err(|_| {
        refused(
            Refused::Unverified("it is not a bundle: it is not UTF-8".into()),
            None,
            old.as_ref(),
        )
    })?;
    let opened = open(&text, keys).map_err(|r| refused(r, None, old.as_ref()))?;
    // The ledger the refusal of a verified bundle goes to: the one in effect,
    // else the bundle's own, which a trusted key vouches for.
    let new = match Config::parse(&opened.config) {
        Ok(new) => new,
        Err(e) => {
            let errors = vec![format!("{e:#}")];
            return Err(refused(
                Refused::Invalid(errors),
                Some(&opened),
                old.as_ref(),
            ));
        }
    };
    let ledger = old.as_ref().unwrap_or(&new);
    let mut errors = new.check(false).errors;
    errors.extend(
        new.referenced_files()
            .into_iter()
            .filter(|f| !Path::new(f).exists())
            .map(|f| format!("it names {f}, which this host does not have: carry it in first")),
    );
    if !errors.is_empty() {
        return Err(refused(
            Refused::Invalid(errors),
            Some(&opened),
            Some(ledger),
        ));
    }
    // The floor of the state the node keeps now, and of the one the bundle
    // names, which a bundle may move.
    let mut dirs = vec![PathBuf::from(&new.gateway.state_dir)];
    if let Some(old) = &old {
        dirs.insert(0, PathBuf::from(&old.gateway.state_dir));
        dirs.dedup();
    }
    let floor = highest_floor(&dirs)?;
    let copy = beside(config);
    let holds = before.as_deref() == Some(opened.config.as_bytes())
        && std::fs::read(&copy).ok().as_deref() == Some(text.as_bytes());
    match admits(floor.as_ref(), &opened) {
        Ok(true) => {}
        Ok(false) if holds => return Ok(Applied::Already(opened)),
        // The floor is at it and the config, or the bundle beside it, is
        // not: put them back.
        Ok(false) => {}
        Err(refusal) => return Err(refused(refusal, Some(&opened), Some(ledger))),
    }

    // The floor first, then the bundle beside the config, then the config,
    // which a gateway holding its config to the bundle reads first: a config
    // it reads is one whose bundle and floor are there already. Stopped in
    // between, the node has a config one revision behind its floor, which
    // this bundle applied again puts right, never a floor behind its config,
    // which a replay could roll back.
    Floor::of(&opened, now()).write(Path::new(&new.gateway.state_dir))?;
    // As readable as the config, which it holds.
    replace(&copy, &text, config)?;
    replace(config, &opened.config, config)?;
    let to = Snapshot::take(opened.config.as_bytes(), &new)
        .digest()
        .to_string();
    crate::hook::record(ledger, entry(None, opened.named(), from, Some(to), started))
        .context("the config is applied, and its record is not in the ledger")?;
    Ok(Applied::Applied {
        bundle: opened,
        from: floor.map(|f| f.revision),
    })
}

/// The ledger record of a bundle applied, or refused under `refused`.
fn entry(
    refused: Option<&str>,
    bundle: BundleRef,
    from: Option<String>,
    to: Option<String>,
    started: Instant,
) -> Entry {
    let decision = match refused {
        None => Decision::Allow,
        Some(rule) => Decision::Deny {
            rule: rule.to_string(),
            reason: String::new(),
        },
    };
    Entry {
        agent: GATEWAY_AGENT.to_string(),
        server: "(config)".to_string(),
        method: Some("bundle".to_string()),
        tool: None,
        decision,
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        attrs: Attrs {
            kind: Kind::Reload,
            config_from: from,
            config_to: to,
            bundle: Some(bundle),
            ..Attrs::default()
        },
    }
}

/// The lock an apply holds, beside the config it replaces: `.mcpdef.toml.lock`.
fn lock_beside(config: &Path) -> PathBuf {
    named_after(config, ".", ".lock")
}

/// A file beside `config`, named after it.
fn named_after(config: &Path, prefix: &str, suffix: &str) -> PathBuf {
    let mut name = OsString::from(prefix);
    name.push(config.file_name().unwrap_or(OsStr::new("mcpdef.toml")));
    name.push(suffix);
    config.with_file_name(name)
}

/// Put `text` at `path` at once: written beside it, then moved over it, so
/// that a gateway reading it sees the old file or the new one, never half of
/// one. The new file is readable by whom `like` is, and owned by its owner
/// where this process may give it.
fn replace(path: &Path, text: &str, like: &Path) -> Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".mcpdef-bundle-");
    #[cfg(unix)]
    let old = std::fs::metadata(like).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = old
            .as_ref()
            .map_or(0o644, |m| m.permissions().mode() & 0o777);
        builder.permissions(std::fs::Permissions::from_mode(mode));
    }
    let mut partial = builder
        .tempfile_in(dir)
        .with_context(|| format!("writing beside {}", path.display()))?;
    partial
        .write_all(text.as_bytes())
        .and_then(|()| partial.as_file().sync_all())
        .with_context(|| format!("writing beside {}", path.display()))?;
    #[cfg(unix)]
    if let Some(old) = &old {
        use std::os::unix::fs::MetadataExt as _;
        // Only its owner, or root, can give a file away: for anyone else the
        // new file is theirs already.
        let _ = std::os::unix::fs::chown(partial.path(), Some(old.uid()), Some(old.gid()));
    }
    partial
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "[[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [\"mock\"]\ntools = [\"echo\"]\n";

    fn new_key() -> SigningKey {
        SigningKey::from_jwk(&SigningKey::generate_named(KID_PREFIX).unwrap()).unwrap()
    }

    fn trusting(key: &SigningKey) -> Keys {
        Keys::from_jwks(&key.jwks().to_string()).unwrap()
    }

    #[test]
    fn a_bundle_signed_by_a_key_trusted_opens() {
        let key = new_key();
        assert!(key.kid().starts_with(KID_PREFIX), "{}", key.kid());
        let text = sign(CONFIG, 7, "2026-10-27T16:30:00.000Z", &key).unwrap();
        let bundle = open(&text, &trusting(&key)).unwrap();
        assert_eq!(
            bundle,
            Bundle {
                revision: 7,
                issued_at: "2026-10-27T16:30:00.000Z".into(),
                config: CONFIG.into(),
                kid: key.kid().into(),
                file: sha256(text.as_bytes()),
            }
        );
        // Signed the same, the same bytes.
        assert_eq!(
            text,
            sign(CONFIG, 7, "2026-10-27T16:30:00.000Z", &key).unwrap()
        );
    }

    #[test]
    fn a_bundle_changed_or_signed_by_another_key_is_unverified() {
        let key = new_key();
        let keys = trusting(&key);
        let text = sign(CONFIG, 7, "2026-10-27T16:30:00.000Z", &key).unwrap();
        let mut doc: Value = serde_json::from_str(&text).unwrap();

        let mut edited = doc.clone();
        edited["config"] = json!(CONFIG.replace("echo", "delete_repo"));
        let mut older = doc.clone();
        older["revision"] = json!(8);
        let mut unknown = doc.clone();
        unknown["not_before"] = json!("2027-01-01T00:00:00Z");
        let mut upper = doc.clone();
        let sig = upper["signature"]["sig"].as_str().unwrap().to_uppercase();
        upper["signature"]["sig"] = json!(sig);
        let mut other = doc.clone();
        other["signature"]["alg"] = json!("ES256");
        for (bad, why) in [
            (edited, "its signature does not verify"),
            (older, "its signature does not verify"),
            (unknown, "unknown field `not_before`"),
            (upper, "not lowercase hex"),
            (other, "it is signed with ES256"),
        ] {
            let refused = open(&bad.to_string(), &keys).unwrap_err();
            assert_eq!(refused.rule(), "bundle-unverified");
            assert!(refused.to_string().contains(why), "{refused}");
        }

        // A member named twice: the one the signature covers is not the
        // only one there.
        let twice = text.replacen(
            "\"config\":",
            "\"config\": \"[gateway]\\n\",\n  \"config\":",
            1,
        );
        assert_ne!(twice, text);
        let refused = open(&twice, &keys).unwrap_err();
        assert!(
            refused.to_string().contains("duplicate field `config`"),
            "{refused}"
        );

        let stranger = new_key();
        let refused = open(&text, &trusting(&stranger)).unwrap_err();
        assert!(
            refused.to_string().contains("no key it trusts is named"),
            "{refused}"
        );
        doc.as_object_mut().unwrap().remove("signature");
        let refused = open(&doc.to_string(), &keys).unwrap_err();
        assert!(
            refused.to_string().contains("it is not signed"),
            "{refused}"
        );
        assert!(open("[gateway]\n", &keys).is_err());
    }

    #[test]
    fn a_revision_goes_up_and_the_same_bundle_again_is_nothing() {
        let key = new_key();
        let open_at = |revision: u64, config: &str| {
            let text = sign(config, revision, "2026-10-27T16:30:00.000Z", &key).unwrap();
            open(&text, &trusting(&key)).unwrap()
        };
        let seven = open_at(7, CONFIG);
        let floor = Floor {
            revision: 7,
            config: seven.config_digest(),
            kid: key.kid().into(),
            applied_at: "2026-10-27T16:31:00.000Z".into(),
        };
        assert_eq!(admits(None, &seven), Ok(true));
        assert_eq!(admits(Some(&floor), &seven), Ok(false));
        assert_eq!(admits(Some(&floor), &open_at(8, CONFIG)), Ok(true));
        let other = open_at(7, &CONFIG.replace("echo", "list"));
        assert_eq!(
            admits(Some(&floor), &other).unwrap_err().rule(),
            "bundle-older"
        );
        let six = admits(Some(&floor), &open_at(6, CONFIG)).unwrap_err();
        assert_eq!(six.rule(), "bundle-older");
        assert!(six.to_string().contains("at a revision above 7"), "{six}");
        assert!(sign(CONFIG, 0, "", &key).is_err());
        assert!(sign(CONFIG, MAX_REVISION + 1, "", &key).is_err());
    }

    /// A config that keeps its state in `state`.
    fn kept_in(state: &Path, tools: &str) -> String {
        format!(
            "[gateway]\nstate_dir = {:?}\n\n{}",
            state.to_str().unwrap(),
            CONFIG.replace("[\"echo\"]", tools)
        )
    }

    /// `config` at `revision`, signed with `key`, opened as a node would.
    fn bundle_of(config: &str, revision: u64, key: &SigningKey) -> (String, Bundle) {
        let text = sign(config, revision, "2026-10-28T09:00:00.000Z", key).unwrap();
        let bundle = open(&text, &trusting(key)).unwrap();
        (text, bundle)
    }

    #[test]
    fn the_bundle_and_the_lock_are_named_after_the_config() {
        let config = Path::new("/etc/mcpdef/gateway.toml");
        assert_eq!(beside(config), Path::new("/etc/mcpdef/gateway.toml.bundle"));
        assert_eq!(
            lock_beside(config),
            Path::new("/etc/mcpdef/.gateway.toml.lock")
        );
        assert_eq!(
            beside(Path::new("mcpdef.toml")),
            Path::new("mcpdef.toml.bundle")
        );
        // Run with the lock as it was not: one that cannot be opened is no
        // reason not to read.
        assert_eq!(holding(Path::new("/nonexistent/mcpdef.toml"), || 7), 7);
    }

    #[test]
    fn a_config_runs_only_as_the_bundle_beside_it_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("mcpdef.toml");
        let (key, stranger) = (new_key(), new_key());
        let keys = trusting(&key);
        let (text, bundle) = bundle_of(CONFIG, 7, &key);

        let none = held(&config, CONFIG.as_bytes(), &keys);
        assert_eq!(none.named, None);
        let refused = none.verdict.unwrap_err();
        assert_eq!(refused.rule(), "bundle-unverified");
        assert!(refused.to_string().contains("there is no "), "{refused}");

        // Signed by a key not trusted: named by its file alone.
        let (forged, _) = bundle_of(CONFIG, 8, &stranger);
        std::fs::write(beside(&config), &forged).unwrap();
        let unknown = held(&config, CONFIG.as_bytes(), &keys);
        assert_eq!(
            unknown.named,
            Some(BundleRef {
                sha256: sha256(forged.as_bytes()),
                revision: None,
                kid: None,
            })
        );
        assert_eq!(unknown.verdict.unwrap_err().rule(), "bundle-unverified");

        std::fs::write(beside(&config), &text).unwrap();
        let edited = CONFIG.replace("echo", "delete_repo");
        let changed = held(&config, edited.as_bytes(), &keys);
        assert_eq!(changed.named, Some(bundle.named()));
        let refused = changed.verdict.unwrap_err();
        assert_eq!(refused.rule(), "bundle-unverified");
        assert!(
            refused.to_string().contains(", revision 7, holds"),
            "{refused}"
        );

        let same = held(&config, CONFIG.as_bytes(), &keys);
        assert_eq!(same.verdict, Ok(bundle.clone()));
        assert_eq!(same.named, Some(bundle.named()));
    }

    #[test]
    fn a_bundle_succeeds_the_one_running_only_upward() {
        let dir = tempfile::tempdir().unwrap();
        let (here, there) = (dir.path().join("here"), dir.path().join("there"));
        let key = new_key();
        let (_, seven) = bundle_of(&kept_in(&here, "[\"echo\"]"), 7, &key);
        let at = |revision: u64, tools: &str| bundle_of(&kept_in(&here, tools), revision, &key).1;
        let verdict = |bundle: &Bundle| succeeds(bundle, &seven, &here).unwrap();

        assert_eq!(verdict(&at(8, "[\"echo\", \"list\"]")), Ok(()));
        // The same bundle again: a file it names may have changed.
        assert_eq!(verdict(&seven), Ok(()));
        let older = verdict(&at(6, "[\"echo\"]")).unwrap_err();
        assert_eq!(older.rule(), "bundle-older");
        let other = verdict(&at(7, "[\"list\"]")).unwrap_err();
        assert!(other.to_string().contains("with another config"), "{other}");

        // A floor above the one running, here or where the bundle keeps its
        // state, refuses what is above the one running and below it.
        let nine = at(9, "[\"echo\"]");
        Floor::of(&nine, now()).write(&here).unwrap();
        assert_eq!(
            verdict(&at(8, "[\"echo\"]")).unwrap_err().rule(),
            "bundle-older"
        );
        assert_eq!(verdict(&at(10, "[\"echo\"]")), Ok(()));
        std::fs::remove_file(here.join(FLOOR_FILE)).unwrap();
        Floor::of(&nine, now()).write(&there).unwrap();
        let moved = bundle_of(&kept_in(&there, "[\"echo\"]"), 8, &key).1;
        assert_eq!(verdict(&moved).unwrap_err().rule(), "bundle-older");

        std::fs::write(there.join(FLOOR_FILE), "{").unwrap();
        assert!(
            succeeds(&moved, &seven, &here).is_err(),
            "a floor that does not read"
        );
    }

    #[test]
    fn a_gateway_admits_a_config_its_bundle_holds_and_raises_the_floor_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let (config, state) = (dir.path().join("mcpdef.toml"), dir.path().join("state"));
        let key = new_key();
        let keys = trusting(&key);
        let put = |revision: u64, tools: &str| {
            let text = kept_in(&state, tools);
            let (signed, bundle) = bundle_of(&text, revision, &key);
            std::fs::write(&config, &text).unwrap();
            std::fs::write(beside(&config), signed).unwrap();
            bundle
        };

        // Carried in, not applied: no floor yet.
        let three = put(3, "[\"echo\"]");
        let admitted = admit(&config, &keys).unwrap();
        assert_eq!(admitted.bundle, three);
        assert_eq!(admitted.text, std::fs::read_to_string(&config).unwrap());
        assert_eq!(Floor::read(&state).unwrap(), None);
        assert!(holding(&config, || raise(&state, &three)).unwrap());
        assert_eq!(Floor::read(&state).unwrap().map(|f| f.revision), Some(3));
        assert!(!raise(&state, &three).unwrap(), "at it already");

        put(2, "[\"echo\", \"delete_repo\"]");
        let older = admit(&config, &keys).unwrap_err();
        assert!(
            format!("{older:#}").contains("revision 2 is older than revision 3"),
            "{older:#}"
        );

        put(4, "[\"echo\", \"list\"]");
        std::fs::write(&config, kept_in(&state, "[\"echo\", \"delete_repo\"]")).unwrap();
        let edited = admit(&config, &keys).unwrap_err();
        assert!(format!("{edited:#}").contains("not running "), "{edited:#}");
    }

    #[test]
    fn a_floor_that_does_not_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Floor::read(dir.path()).unwrap(), None);
        let floor = Floor {
            revision: 3,
            config: "sha256:00".into(),
            kid: "mcpdef:bundle:x".into(),
            applied_at: "2026-10-27T16:31:00.000Z".into(),
        };
        floor.write(dir.path()).unwrap();
        assert_eq!(Floor::read(dir.path()).unwrap(), Some(floor));
        std::fs::write(dir.path().join(FLOOR_FILE), "{").unwrap();
        assert!(Floor::read(dir.path()).is_err());
    }
}
