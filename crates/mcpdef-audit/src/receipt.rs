// SPDX-License-Identifier: Apache-2.0
//! Signed decision receipts: the ledger's tool calls as the Access Decision
//! Receipts of `draft-farley-acta-signed-receipts-03`, which anyone with the
//! issuer's public key can check offline.
//!
//! A receipt is one JSON object, `{"payload": {…}, "signature": {"alg",
//! "kid", "sig"}}`: the draft's envelope shape (§2.1). The payload comes
//! from one ledger [`Record`] and nothing else: its tool, its decision and
//! the rule behind it, its time, and where it is in the ledger. The
//! signature is Ed25519 (RFC 8032) over the payload's RFC 8785 (JCS) form,
//! in lowercase hex. Each receipt after the first carries, in
//! `previousReceiptHash`, the `sha256:` of the whole receipt before it
//! (§6.7), so the receipts are a chain as the ledger is.
//!
//! Ed25519 signs deterministically, so signing the same ledger with the
//! same key again gives the same bytes.
//!
//! What a receipt shows, and what it does not (§9.7, §9.8):
//!
//! - It shows that whoever holds the key vouches that the gateway made this
//!   decision at this time. It does not show that the tool then ran, nor
//!   what the tool returned.
//! - The chain shows that no receipt between two others was changed, taken
//!   out or moved. It cannot show that none were taken off the end. To catch
//!   that, compare the last receipt's hash and the count with ones recorded
//!   somewhere else, as [`Checked::matches`] does.

use crate::{rfc3339_utc, AuditError, Kind, Record, GENESIS};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// The `type` of an Access Decision Receipt (§3.1).
pub const DECISION: &str = "protectmcp:decision";

/// The signature algorithm receipts are signed with: Ed25519, under its JOSE
/// name.
pub const EDDSA: &str = "EdDSA";

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    /// A key file that is not an Ed25519 private JWK, or a key set with no
    /// key a receipt could be checked with.
    #[error("{0}")]
    Key(String),
    /// A value RFC 8785 has no form for.
    #[error("{0}")]
    Canonical(String),
}

/// `value` in RFC 8785 (JCS) form, which receipts are signed and hashed
/// over. It is compact, and object members are sorted by their UTF-16 code
/// units at every level. Strings are escaped and numbers written as
/// ECMAScript writes them.
pub fn canonical(value: &Value) -> Result<String, ReceiptError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), ReceiptError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        // JCS numbers are IEEE 754 doubles. An integer past 2^53 is the double
        // nearest it, as ECMAScript reads it.
        Value::Number(n) => match n.as_f64().filter(|f| f.is_finite()) {
            Some(f) => out.push_str(&ecmascript(f)),
            None => return Err(ReceiptError::Canonical(format!("{n} has no RFC 8785 form"))),
        },
        // `"`, `\` and control characters, the last as `\u00xx` in lowercase
        // hex but for `\b`, `\t`, `\n`, `\f` and `\r`: RFC 8785 §3.2.2.2.
        Value::String(s) => out.push_str(&crate::json_str(s)),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_unstable_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&crate::json_str(name));
                out.push(':');
                write_canonical(member, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A finite `f` as ECMAScript's `Number::toString` writes it (ECMA-262
/// §7.1.12.1), which RFC 8785 requires. It uses the shortest digits that read
/// back as `f`, in plain notation from 1e-6 up to 1e21 and in exponent
/// notation outside that range.
fn ecmascript(f: f64) -> String {
    if f == 0.0 {
        return "0".into(); // -0 too
    }
    // Rust's `{:e}` writes the shortest digits that read back as `f`, as
    // `d.ddde±x`. Where two are as near to `f`, it takes the higher one, and
    // ECMAScript the even one. Written to that many digits, which rounds a tie
    // to even, they are the even one, when that also reads back as `f`.
    let shortest = format!("{:e}", f.abs());
    let k = shortest
        .split_once('e')
        .map_or(1, |(mantissa, _)| mantissa.replace('.', "").len());
    let even = format!("{:.*e}", k - 1, f.abs());
    let sci = if even.parse::<f64>() == Ok(f.abs()) {
        even
    } else {
        shortest
    };
    let (mantissa, exp) = sci.split_once('e').expect("`{:e}` writes an exponent");
    let digits = mantissa.replace('.', "");
    let k = digits.len() as i64;
    // Where the decimal point falls, counted from the left of the digits.
    let n = exp
        .parse::<i64>()
        .expect("`{:e}` writes an integer exponent")
        + 1;
    let mut out = String::new();
    if f < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.push_str(&"0".repeat((n - k) as usize));
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(n as usize);
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(n.unsigned_abs() as usize));
        out.push_str(&digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if n > 0 { '+' } else { '-' });
        out.push_str(&(n - 1).unsigned_abs().to_string());
    }
    out
}

/// The key id the draft recommends (§2.1.1): `sb:issuer:` and the first 12
/// characters of the public key in Base58.
fn kid_of(public: &[u8]) -> String {
    named("sb:issuer:", public)
}

/// `prefix` and the first 12 characters of the public key in Base58.
fn named(prefix: &str, public: &[u8]) -> String {
    let b58 = base58(public);
    format!("{prefix}{}", &b58[..b58.len().min(12)])
}

/// `bytes` in Base58, in the alphabet the draft's key ids use (Bitcoin's).
fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Base-58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    // Each leading zero byte is a leading `1`.
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|d| char::from(ALPHABET[usize::from(*d)])),
        )
        .collect()
}

/// A JWK member that holds base64url bytes.
fn jwk_bytes(jwk: &Value, name: &str) -> Result<Vec<u8>, ReceiptError> {
    let text = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ReceiptError::Key(format!("it has no `{name}`")))?;
    B64.decode(text)
        .map_err(|_| ReceiptError::Key(format!("its `{name}` is not base64url")))
}

/// The Ed25519 key receipts are signed with. Its file is a private JWK
/// (RFC 8037): `{"kty": "OKP", "crv": "Ed25519", "kid", "x", "d"}`.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    kid: String,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A new key from the system's random source, as the private JWK a key
    /// file holds, one line of JSON and a newline. Its `kid` is the one the
    /// draft recommends.
    pub fn generate() -> Result<String, ReceiptError> {
        Self::generate_named("sb:issuer:")
    }

    /// [`generate`](Self::generate), with a `kid` of `prefix` and the first
    /// 12 characters of the public key in Base58: a key that signs something
    /// other than receipts, named for what it signs.
    pub fn generate_named(prefix: &str) -> Result<String, ReceiptError> {
        let mut seed = [0u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| ReceiptError::Key("the system's random source failed".into()))?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|e| ReceiptError::Key(format!("making a key: {e}")))?;
        let x = pair.public_key().as_ref();
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": named(prefix, x),
            "x": B64.encode(x),
            "d": B64.encode(seed),
        });
        Ok(format!("{}\n", canonical(&jwk)?))
    }

    /// The key a private JWK holds. Its `x` must be the public key of its
    /// `d`. Its `kid` names it in each receipt; without one, it gets the one
    /// the draft recommends.
    pub fn from_jwk(text: &str) -> Result<SigningKey, ReceiptError> {
        let jwk: Value = serde_json::from_str(text)
            .map_err(|e| ReceiptError::Key(format!("it is not a JWK: {e}")))?;
        if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
            || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        {
            return Err(ReceiptError::Key(
                "it is not an Ed25519 key: a receipt key has \"kty\": \"OKP\" and \"crv\": \"Ed25519\"".into(),
            ));
        }
        if jwk.get("d").is_none() {
            return Err(ReceiptError::Key(
                "it has no `d`: it is a public key, and receipts are signed with the private one"
                    .into(),
            ));
        }
        let (d, x) = (jwk_bytes(&jwk, "d")?, jwk_bytes(&jwk, "x")?);
        let pair = Ed25519KeyPair::from_seed_and_public_key(&d, &x)
            .map_err(|_| ReceiptError::Key("its `x` is not the public key of its `d`".into()))?;
        let kid = match jwk.get("kid") {
            Some(Value::String(kid)) if !kid.is_empty() => kid.clone(),
            Some(_) => return Err(ReceiptError::Key("its `kid` is not a name".into())),
            None => kid_of(&x),
        };
        Ok(SigningKey { pair, kid })
    }

    /// The name each receipt gives this key: its `kid`, and its `issuer_id`.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The Ed25519 signature of `message`, 64 bytes. The same message and
    /// key always give the same signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }

    /// The public half as a JWK Set (RFC 7517), to publish where verifiers
    /// fetch it. The draft suggests `/.well-known/acta-keys.json` (§5.3).
    pub fn jwks(&self) -> Value {
        json!({ "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "x": B64.encode(self.pair.public_key().as_ref()),
            "use": "sig",
        }]})
    }
}

/// The `sha256:` a receipt is linked to by the next one: of its whole JCS
/// form, signature and all (§6.7).
fn chain_hash(canonical_receipt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_receipt.as_bytes()))
    )
}

/// What a record's receipt says, or `None` for a record that is not a
/// decision on a tool call.
fn payload(rec: &Record, kid: &str, before: Option<&str>) -> Option<Map<String, Value>> {
    let call = rec.kind.as_deref().is_none_or(|k| k == Kind::Call.as_str());
    let tool = rec
        .tool
        .as_deref()
        .filter(|_| call && rec.method.as_deref() == Some("tools/call"))?;
    let decision = match (rec.decision.as_str(), rec.rule.as_deref()) {
        ("allow", _) => "allow",
        ("deny", Some("rate-limited")) => "rate_limit",
        ("deny", _) => "deny",
        _ => return None,
    };
    let mut p = Map::new();
    p.insert("type".into(), DECISION.into());
    p.insert("tool_name".into(), tool.into());
    p.insert("decision".into(), decision.into());
    if let Some(rule) = &rec.rule {
        p.insert("reason".into(), rule.as_str().into());
    }
    p.insert("issued_at".into(), rfc3339_utc(rec.ts_unix_ms).into());
    p.insert("issuer_id".into(), kid.into());
    // The first receipt leaves it out, not null nor empty: §2.2.
    if let Some(before) = before {
        p.insert("previousReceiptHash".into(), before.into());
    }
    // Which server the tool is on, as the ledger names it, and the `seq` of
    // the record this receipt is for. Not the record's hash: that commits to
    // the caller and its address too, which a guess could then be checked
    // against.
    p.insert(
        "mcpdef".into(),
        json!({ "server": rec.server, "seq": rec.seq }),
    );
    Some(p)
}

/// Receipts for a ledger's records in order, each linked to the one before.
pub struct Receipts<'k> {
    key: &'k SigningKey,
    last: Option<String>,
    count: u64,
}

impl<'k> Receipts<'k> {
    pub fn new(key: &'k SigningKey) -> Receipts<'k> {
        Receipts {
            key,
            last: None,
            count: 0,
        }
    }

    /// The receipt for `rec`, as one line of JCS. It is `None` for a record
    /// that is not a decision on a tool call: an admin action, a reload, an
    /// upstream's change, or a request for something other than a tool,
    /// which the draft's receipt types do not cover.
    ///
    /// Its `tool_name` is the tool as its server names it, as the ledger
    /// records it. With `tool_namespace = "prefix"`, the client saw it under
    /// its server's prefix.
    pub fn sign(&mut self, rec: &Record) -> Option<String> {
        let payload = payload(rec, &self.key.kid, self.last.as_deref())?;
        let payload = Value::Object(payload);
        let signed = canonical(&payload).expect("a payload is strings and integers");
        let sig = hex::encode(self.key.pair.sign(signed.as_bytes()));
        let receipt = json!({
            "payload": payload,
            "signature": { "alg": EDDSA, "kid": self.key.kid, "sig": sig },
        });
        let line = canonical(&receipt).expect("a receipt is strings and integers");
        self.last = Some(chain_hash(&line));
        self.count += 1;
        Some(line)
    }

    /// The `sha256:` of the last receipt made, which the next one links to.
    pub fn last(&self) -> Option<&str> {
        self.last.as_deref()
    }

    /// How many receipts were made.
    pub fn count(&self) -> u64 {
        self.count
    }
}

/// What [`export`] signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    /// The ledger's records it read, all of them checked.
    pub records: u64,
    /// The receipts it wrote: one per tool call among them.
    pub receipts: u64,
    /// The ledger's head after the last record it read.
    pub head: String,
    /// The `sha256:` of the last receipt, if it wrote any.
    pub last: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A record that does not verify, or a ledger that does not end where
    /// the seal says.
    #[error("{0}")]
    Refused(String),
}

/// Sign the ledger at `path` as receipts, one line each, to `out`: a receipt
/// per tool call, in order, each linked to the one before.
///
/// It reads the file once, through one handle, and checks each record as it
/// reads it, as [`verify`](crate::verify) does: its `hash`, its link to the
/// record before and its `seq`. It refuses:
///
/// - a record that fails;
/// - a record with U+001F in a field, which an older gateway let in (see
///   [`VerifyReport::ambiguous`](crate::VerifyReport::ambiguous)): a receipt
///   for it could say what the gateway never decided;
/// - a ledger that ends anywhere but where `seal` says, a head and a count
///   recorded somewhere else.
///
/// The receipts are written as the records are read, so on an error what
/// `out` was given must be thrown away. `mcpdef receipts export` writes to a
/// file it keeps only when this returns `Ok`. A last line with no newline yet
/// is one the gateway is still writing: it waits for the next export.
pub fn export(
    path: impl AsRef<Path>,
    key: &SigningKey,
    seal: Option<(&str, u64)>,
    out: &mut impl Write,
) -> Result<Exported, ExportError> {
    let mut file = BufReader::new(File::open(path.as_ref())?);
    let mut receipts = Receipts::new(key);
    let (mut records, mut head, mut line) = (0u64, GENESIS.to_string(), Vec::new());
    loop {
        line.clear();
        if file.read_until(b'\n', &mut line)? == 0 || line.last() != Some(&b'\n') {
            break;
        }
        let corrupt = |detail: String| AuditError::Corrupt {
            line: records,
            detail,
        };
        let text = std::str::from_utf8(&line).map_err(|e| corrupt(e.to_string()))?;
        if text.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(text).map_err(|e| corrupt(e.to_string()))?;
        if rec.seq != records || rec.prev_hash != head || rec.compute_hash() != rec.hash {
            return Err(ExportError::Refused(format!(
                "the ledger's chain is broken at seq {}: `mcpdef audit verify` says more",
                rec.seq
            )));
        }
        if rec.has_separator() {
            return Err(ExportError::Refused(format!(
                "record {} has U+001F in a field, which an older gateway let in: its hash does \
                 not pin where one field ends and the next begins, so a receipt for it could say \
                 what the gateway never decided",
                rec.seq
            )));
        }
        if let Some(receipt) = receipts.sign(&rec) {
            writeln!(out, "{receipt}")?;
        }
        head = rec.hash;
        records += 1;
    }
    if let Some((sealed, count)) = seal {
        if records != count || head != sealed {
            return Err(ExportError::Refused(format!(
                "the ledger holds {records} record(s) up to head {head}, and the seal {count} up \
                 to head {sealed}"
            )));
        }
    }
    out.flush()?;
    Ok(Exported {
        records,
        receipts: receipts.count(),
        head,
        last: receipts.last().map(str::to_string),
    })
}

/// A public key receipts can be checked with.
enum PublicKey {
    Ed25519(Vec<u8>),
    /// P-256, as the uncompressed point `04 ‖ x ‖ y`.
    P256(Vec<u8>),
}

impl PublicKey {
    fn verify(&self, alg: &str, message: &[u8], sig: &[u8]) -> Result<(), String> {
        let (algorithm, key): (&'static dyn signature::VerificationAlgorithm, &[u8]) =
            match (alg, self) {
                (EDDSA, PublicKey::Ed25519(key)) => (&signature::ED25519, key),
                ("ES256", PublicKey::P256(key)) => (&signature::ECDSA_P256_SHA256_FIXED, key),
                (EDDSA | "ES256", _) => {
                    return Err(format!(
                        "it is signed with {alg}, and its kid names another kind of key"
                    ))
                }
                _ => {
                    return Err(format!(
                        "it is signed with {alg}, which this verifier does not check"
                    ))
                }
            };
        UnparsedPublicKey::new(algorithm, key)
            .verify(message, sig)
            .map_err(|_| "its signature does not verify".to_string())
    }
}

/// The public keys a verifier trusts, by key id. They come from a JWK Set or
/// one JWK that the verifier got from somewhere other than the receipts
/// (§9.5): a key a receipt carries proves nothing.
pub struct Keys(BTreeMap<String, PublicKey>);

impl Keys {
    /// The Ed25519 (`OKP`) and P-256 (`EC`) keys of a JWK Set, or of one
    /// JWK. Other kinds are passed over. A key with no `kid` gets the one the
    /// draft recommends for an Ed25519 key.
    pub fn from_jwks(text: &str) -> Result<Keys, ReceiptError> {
        let doc: Value = serde_json::from_str(text)
            .map_err(|e| ReceiptError::Key(format!("it is not a JWK Set: {e}")))?;
        let listed: Vec<&Value> = match doc.get("keys") {
            Some(Value::Array(keys)) => keys.iter().collect(),
            Some(_) => return Err(ReceiptError::Key("its `keys` is not a list".into())),
            None => vec![&doc],
        };
        let mut keys = BTreeMap::new();
        for (i, jwk) in listed.into_iter().enumerate() {
            let which = |e: ReceiptError| ReceiptError::Key(format!("key {}: {e}", i + 1));
            let kind = (
                jwk.get("kty").and_then(Value::as_str),
                jwk.get("crv").and_then(Value::as_str),
            );
            let key = match kind {
                (Some("OKP"), Some("Ed25519")) => {
                    PublicKey::Ed25519(jwk_bytes(jwk, "x").map_err(which)?)
                }
                (Some("EC"), Some("P-256")) => {
                    let mut point = vec![4u8];
                    point.extend(jwk_bytes(jwk, "x").map_err(which)?);
                    point.extend(jwk_bytes(jwk, "y").map_err(which)?);
                    PublicKey::P256(point)
                }
                _ => continue,
            };
            let kid = match (jwk.get("kid").and_then(Value::as_str), &key) {
                (Some(kid), _) => kid.to_string(),
                (None, PublicKey::Ed25519(x)) => kid_of(x),
                (None, PublicKey::P256(_)) => {
                    return Err(which(ReceiptError::Key("it has no `kid`".into())))
                }
            };
            keys.insert(kid, key);
        }
        if keys.is_empty() {
            return Err(ReceiptError::Key(
                "it holds no Ed25519 or P-256 key to check a receipt with".into(),
            ));
        }
        Ok(Keys(keys))
    }

    /// Check `sig`, made with `alg` (`EdDSA` or `ES256`), over `message`,
    /// against the trusted key named `kid`.
    pub fn verify(&self, kid: &str, alg: &str, message: &[u8], sig: &[u8]) -> Result<(), String> {
        self.0
            .get(kid)
            .ok_or_else(|| format!("no key it trusts is named {kid}"))?
            .verify(alg, message, sig)
    }
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The receipts that verified, in order, up to the first that did not.
    pub receipts: u64,
    /// How many runs of linked receipts they make. The first receipt starts
    /// one, as does each later one without a `previousReceiptHash`. An
    /// export by MCPdef is one run.
    pub chains: u64,
    /// The `sha256:` of the last receipt that verified.
    pub last: Option<String>,
    /// Whether the first receipt links to one before it that is not here:
    /// these receipts start in the middle of a chain, as a later part of a
    /// longer export does, or as one does whose first receipts were taken off.
    pub starts_mid_chain: bool,
    /// The first receipt that did not verify, by line (from 1), and why.
    pub broken: Option<(u64, String)>,
}

impl Checked {
    pub fn ok(&self) -> bool {
        self.broken.is_none()
    }

    /// Whether every receipt verified and they end where a seal recorded
    /// somewhere else says: at the receipt whose hash is `last`, after `count`
    /// of them. That catches receipts taken off the end, which a chain alone
    /// cannot (§9.7).
    pub fn matches(&self, last: &str, count: u64) -> bool {
        self.ok() && self.receipts == count && self.last.as_deref() == Some(last)
    }
}

/// Check receipts, one JSON object per line, against `keys`. For each it
/// checks the signature, by the algorithm the receipt names, over its
/// payload's JCS form, and that its `issuer_id` is its `kid`. A
/// `previousReceiptHash` must be the hash of the receipt before it, when
/// one is. It stops at the first receipt that fails.
///
/// It checks the envelope shape, the one MCPdef writes; a receipt in the
/// draft's older flat shape is reported as one it does not check. A receipt
/// that names a member twice fails: a reader that keeps the first one would
/// read what was never signed. It checks integrity, not completeness: see
/// [`Checked::matches`].
pub fn verify(text: impl BufRead, keys: &Keys) -> Result<Checked, std::io::Error> {
    let mut checked = Checked {
        receipts: 0,
        chains: 0,
        last: None,
        starts_mid_chain: false,
        broken: None,
    };
    for (i, line) in text.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match check(&line, keys, checked.last.as_deref()) {
            Ok((hash, linked)) => {
                if checked.receipts == 0 {
                    checked.starts_mid_chain = linked;
                }
                if !linked || checked.receipts == 0 {
                    checked.chains += 1;
                }
                checked.receipts += 1;
                checked.last = Some(hash);
            }
            Err(why) => {
                checked.broken = Some((i as u64 + 1, why));
                break;
            }
        }
    }
    Ok(checked)
}

/// One receipt's hash, and whether it links to the one before, or why it
/// fails.
fn check(line: &str, keys: &Keys, before: Option<&str>) -> Result<(String, bool), String> {
    // RFC 8785 §3.1: a member named twice has no canonical form.
    let receipt =
        crate::parse_strict(line).map_err(|e| format!("it is not a JSON receipt: {e}"))?;
    let Value::Object(members) = &receipt else {
        return Err("it is not a JSON object".into());
    };
    let (Some(Value::Object(payload)), Some(Value::Object(sig)), 2) = (
        members.get("payload"),
        members.get("signature"),
        members.len(),
    ) else {
        return Err(match members.get("signature") {
            Some(Value::String(_)) => {
                "it is a flat receipt, and this verifier checks the envelope shape only".into()
            }
            _ => "it is not a receipt: a receipt has a payload and a signature, and nothing else"
                .into(),
        });
    };
    let member = |name: &str| {
        sig.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("its signature has no `{name}`"))
    };
    let (alg, kid, sig_hex) = (member("alg")?, member("kid")?, member("sig")?);
    if payload.get("issuer_id").and_then(Value::as_str) != Some(kid) {
        return Err(format!("its issuer_id is not its kid, {kid}"));
    }
    let key = keys
        .0
        .get(kid)
        .ok_or_else(|| format!("no key you trust has the kid {kid}"))?;
    let sig = lower_hex(sig_hex).ok_or("its signature is not lowercase hex")?;
    let signed = canonical(&Value::Object(payload.clone())).map_err(|e| e.to_string())?;
    key.verify(alg, signed.as_bytes(), &sig)?;
    let linked = match payload.get("previousReceiptHash") {
        None => false,
        Some(Value::String(link)) => {
            // `sha256:` and lowercase hex, or the bare hex earlier drafts
            // wrote (§6.7).
            let hex_part = match link.split_once(':') {
                Some(("sha256", hex_part)) => hex_part,
                Some((other, _)) => {
                    let why = "which this verifier does not check";
                    return Err(format!("its previousReceiptHash is a {other} hash, {why}"));
                }
                None => link.as_str(),
            };
            if hex_part.len() != 64 || lower_hex(hex_part).is_none() {
                return Err("its previousReceiptHash is not a SHA-256 in lowercase hex".into());
            }
            if let Some(before) = before {
                if before.strip_prefix("sha256:") != Some(hex_part) {
                    return Err(
                        "its previousReceiptHash is not the receipt before it: one between them is missing, or they are out of order"
                            .into(),
                    );
                }
            }
            true
        }
        Some(_) => return Err("its previousReceiptHash is not a string".into()),
    };
    let hash = chain_hash(&canonical(&receipt).map_err(|e| e.to_string())?);
    Ok((hash, linked))
}

/// `text`'s bytes, when it is lowercase hex, the form the draft gives `sig`
/// (§2.1.1) and a chain hash (§6.7).
fn lower_hex(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attrs, Decision, Entry, Ledger};

    /// RFC 8037 A.1: the key of RFC 8032's first Ed25519 test vector.
    const RFC8037_KEY: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    fn record(seq: u64, tool: &str, decision: &str, rule: Option<&str>) -> Record {
        Record {
            seq,
            ts_unix_ms: 1_774_190_324_102 + seq,
            agent: "agent:test".into(),
            server: "github".into(),
            method: Some("tools/call".into()),
            tool: Some(tool.into()),
            decision: decision.into(),
            rule: rule.map(str::to_string),
            latency_ms: 3,
            kind: None,
            uri: None,
            transforms: None,
            actor: None,
            peer: Some("127.0.0.1:50000".into()),
            config_from: None,
            config_to: None,
            tool_changes: None,
            drift: None,
            bundle: None,
            trace_id: None,
            parent_id: None,
            tool_digest: None,
            hook: None,
            extra: Default::default(),
            prev_hash: GENESIS.into(),
            hash: format!("{seq:064x}"),
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_jwk(RFC8037_KEY).unwrap()
    }

    fn keys_for(key: &SigningKey) -> Keys {
        Keys::from_jwks(&key.jwks().to_string()).unwrap()
    }

    fn verify_lines(lines: &[String], keys: &Keys) -> Checked {
        verify(lines.join("\n").as_bytes(), keys).unwrap()
    }

    #[test]
    fn canonical_form_is_rfc_8785s() {
        // RFC 8785 §3.2.2, and the canonical form §3.2.3 gives for it.
        let parsed: Value = serde_json::from_str(
            r#"{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
                "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
                "literals": [null, true, false]}"#,
        )
        .unwrap();
        assert_eq!(
            canonical(&parsed).unwrap(),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn members_sort_by_utf16_code_units() {
        // RFC 8785 §3.2.3's test data, and the order it expects.
        let parsed: Value = serde_json::from_str(
            r#"{"€": "Euro Sign", "\r": "Carriage Return",
                "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
                "😀": "Emoji: Grinning Face", "\u0080": "Control",
                "ö": "Latin Small Letter O With Diaeresis"}"#,
        )
        .unwrap();
        let text = canonical(&parsed).unwrap();
        let expected = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let mut found: Vec<(usize, &str)> = expected
            .iter()
            .map(|v| (text.find(v).unwrap(), *v))
            .collect();
        found.sort_unstable();
        let order: Vec<&str> = found.into_iter().map(|(_, v)| v).collect();
        assert_eq!(order, expected);
    }

    #[test]
    fn numbers_are_written_as_ecmascript_writes_them() {
        // RFC 8785 Appendix B: an IEEE 754 double by its bits, and its form.
        let samples = [
            (0x0000000000000000_u64, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, form) in samples {
            assert_eq!(ecmascript(f64::from_bits(bits)), form, "{bits:016x}");
        }
        // An integer is written as the double it reads as.
        assert_eq!(
            canonical(&json!(9_007_199_254_740_993_u64)).unwrap(),
            "9007199254740992"
        );
        assert_eq!(canonical(&json!(41)).unwrap(), "41");
    }

    #[test]
    fn base58_is_bitcoins() {
        for (bytes, text) in [
            (&b""[..], ""),
            (&[0x61][..], "2g"),
            (&[0x62, 0x62, 0x62][..], "a3gV"),
            (&b"simply a long string"[..], "2cFupjhnEsSn59qHXstmK2ffpLv2"),
            (&[0, 0, 0x28, 0x7f, 0xb4, 0xcd][..], "11233QC4"),
            (&[0, 0, 0][..], "111"),
        ] {
            assert_eq!(base58(bytes), text, "{bytes:?}");
        }
    }

    #[test]
    fn a_key_signs_as_rfc_8032_says() {
        // RFC 8032 §7.1, TEST 1: the empty message.
        let key = key();
        assert_eq!(
            hex::encode(key.pair.sign(b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(key.kid().starts_with("sb:issuer:"));
        assert_eq!(key.kid().len(), "sb:issuer:".len() + 12);
        let jwks = key.jwks();
        assert_eq!(
            jwks["keys"][0]["x"],
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        );
        assert_eq!(jwks["keys"][0]["kid"], key.kid());
        assert!(jwks["keys"][0].get("d").is_none(), "the public half only");
    }

    #[test]
    fn a_generated_key_round_trips_through_its_file() {
        let text = SigningKey::generate().unwrap();
        let key = SigningKey::from_jwk(&text).unwrap();
        let jwk: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(jwk["kid"], key.kid());
        assert_ne!(SigningKey::generate().unwrap(), text, "each key is new");
        assert!(!format!("{key:?}").contains(jwk["d"].as_str().unwrap()));
    }

    #[test]
    fn a_key_file_that_is_not_a_private_ed25519_jwk_is_refused() {
        let public = key().jwks()["keys"][0].to_string();
        for (text, says) in [
            ("{", "not a JWK"),
            (r#"{"kty":"RSA"}"#, "not an Ed25519 key"),
            (public.as_str(), "it is a public key"),
            (
                r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                "not the public key of its `d`",
            ),
        ] {
            let err = SigningKey::from_jwk(text).unwrap_err().to_string();
            assert!(err.contains(says), "{text}: {err}");
        }
    }

    #[test]
    fn a_tool_call_becomes_an_access_decision_receipt() {
        let key = key();
        let mut receipts = Receipts::new(&key);
        let line = receipts
            .sign(&record(0, "delete_repo", "deny", Some("tools.deny")))
            .unwrap();
        let r: Value = serde_json::from_str(&line).unwrap();
        let p = &r["payload"];
        assert_eq!(p["type"], DECISION);
        assert_eq!(p["tool_name"], "delete_repo");
        assert_eq!(p["decision"], "deny");
        assert_eq!(p["reason"], "tools.deny");
        assert_eq!(p["issued_at"], "2026-03-22T14:38:44.102Z");
        assert_eq!(p["issuer_id"], key.kid());
        assert!(
            p.get("previousReceiptHash").is_none(),
            "the first leaves it out"
        );
        assert_eq!(p["mcpdef"], json!({ "server": "github", "seq": 0 }));
        assert_eq!(r["signature"]["alg"], "EdDSA");
        assert_eq!(r["signature"]["kid"], key.kid());
        assert_eq!(r["signature"]["sig"].as_str().unwrap().len(), 128);
        // No identity or address of the caller (§9.3), and the line is JCS.
        assert!(!line.contains("agent:test") && !line.contains("127.0.0.1"));
        assert_eq!(canonical(&r).unwrap(), line);
        assert_eq!(receipts.last(), Some(chain_hash(&line).as_str()));
    }

    #[test]
    fn only_tool_calls_get_receipts_and_a_rate_limit_is_its_own_decision() {
        let key = key();
        let mut receipts = Receipts::new(&key);
        let mut read = record(0, "x", "allow", None);
        read.method = Some("resources/read".into());
        read.tool = None;
        let mut admin = record(1, "x", "allow", None);
        admin.kind = Some("admin".into());
        assert!(receipts.sign(&read).is_none());
        assert!(receipts.sign(&admin).is_none());
        let line = receipts
            .sign(&record(2, "search", "deny", Some("rate-limited")))
            .unwrap();
        let r: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            (
                r["payload"]["decision"].as_str(),
                r["payload"]["reason"].as_str()
            ),
            (Some("rate_limit"), Some("rate-limited"))
        );
        let allowed = receipts.sign(&record(3, "search", "allow", None)).unwrap();
        let r: Value = serde_json::from_str(&allowed).unwrap();
        assert_eq!(r["payload"]["decision"], "allow");
        assert!(r["payload"].get("reason").is_none());
        assert_eq!(receipts.count(), 2);
    }

    #[test]
    fn receipts_chain_and_the_same_ledger_signs_the_same() {
        let key = key();
        let sign_all = || {
            let mut receipts = Receipts::new(&key);
            (0..3)
                .filter_map(|seq| receipts.sign(&record(seq, "list_issues", "allow", None)))
                .collect::<Vec<_>>()
        };
        let lines = sign_all();
        assert_eq!(lines, sign_all(), "Ed25519 signs deterministically");
        for pair in lines.windows(2) {
            let next: Value = serde_json::from_str(&pair[1]).unwrap();
            assert_eq!(next["payload"]["previousReceiptHash"], chain_hash(&pair[0]));
        }
        let checked = verify_lines(&lines, &keys_for(&key));
        assert!(checked.ok(), "{checked:?}");
        assert_eq!((checked.receipts, checked.chains), (3, 1));
        assert_eq!(checked.last, Some(chain_hash(&lines[2])));
        assert!(checked.matches(&chain_hash(&lines[2]), 3));
    }

    #[test]
    fn verify_finds_a_changed_a_missing_and_an_unknown_receipt() {
        let key = key();
        let keys = keys_for(&key);
        let mut receipts = Receipts::new(&key);
        let lines: Vec<String> = (0..3)
            .filter_map(|seq| receipts.sign(&record(seq, "list_issues", "allow", None)))
            .collect();

        let changed = vec![
            lines[0].clone(),
            lines[1].replace("\"allow\"", "\"deny\""),
            lines[2].clone(),
        ];
        let checked = verify_lines(&changed, &keys);
        assert_eq!(
            checked.broken,
            Some((2, "its signature does not verify".into()))
        );
        assert_eq!(checked.receipts, 1);

        let missing = vec![lines[0].clone(), lines[2].clone()];
        let checked = verify_lines(&missing, &keys);
        assert!(
            checked
                .broken
                .as_ref()
                .unwrap()
                .1
                .contains("not the receipt before it"),
            "{checked:?}"
        );

        // Off the end: every link still holds, and only a seal catches it.
        let short = verify_lines(&lines[..2], &keys);
        assert!(short.ok());
        assert!(!short.matches(&chain_hash(&lines[2]), 3));

        let other = SigningKey::from_jwk(&SigningKey::generate().unwrap()).unwrap();
        let checked = verify_lines(&lines, &keys_for(&other));
        assert!(checked.broken.unwrap().1.contains("no key you trust"));
    }

    #[test]
    fn verify_checks_the_shape_and_the_issuer() {
        let key = key();
        let keys = keys_for(&key);
        let line = Receipts::new(&key)
            .sign(&record(0, "t", "allow", None))
            .unwrap();
        let mut r: Value = serde_json::from_str(&line).unwrap();
        r["payload"]["issuer_id"] = json!("sb:issuer:someone-else");
        let checked = verify_lines(&[r.to_string()], &keys);
        assert!(checked
            .broken
            .unwrap()
            .1
            .contains("issuer_id is not its kid"));

        let flat = json!({ "type": DECISION, "signature": "00" }).to_string();
        let checked = verify_lines(&[flat], &keys);
        assert!(checked.broken.unwrap().1.contains("flat receipt"));

        let mut extra: Value = serde_json::from_str(&line).unwrap();
        extra["note"] = json!("added");
        assert!(verify_lines(&[extra.to_string()], &keys)
            .broken
            .unwrap()
            .1
            .contains("nothing else"));
    }

    #[test]
    fn verify_checks_es256_and_names_an_algorithm_it_does_not() {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref();
        let jwks = json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": "p256",
            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..]) }] });
        let keys = Keys::from_jwks(&jwks.to_string()).unwrap();
        let payload = json!({ "type": DECISION, "tool_name": "t", "decision": "allow",
            "issued_at": "2026-03-22T14:32:04.102Z", "issuer_id": "p256" });
        let sig = pair
            .sign(&rng, canonical(&payload).unwrap().as_bytes())
            .unwrap();
        let receipt = json!({ "payload": payload, "signature": { "alg": "ES256", "kid": "p256", "sig": hex::encode(sig) } });
        let checked = verify_lines(&[receipt.to_string()], &keys);
        assert!(checked.ok(), "{checked:?}");

        let mut pq = receipt.clone();
        pq["signature"]["alg"] = json!("ML-DSA-65");
        let checked = verify_lines(&[pq.to_string()], &keys);
        assert!(checked
            .broken
            .unwrap()
            .1
            .contains("ML-DSA-65, which this verifier does not check"));
    }

    #[test]
    fn export_signs_a_ledger_that_verifies_and_refuses_one_that_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut led = Ledger::open(&path).unwrap();
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
        let last = led
            .append(call(
                "delete_repo",
                Decision::Deny {
                    rule: "tools.deny".into(),
                    reason: "not on the list".into(),
                },
            ))
            .unwrap();
        drop(led);

        let key = key();
        let mut out = Vec::new();
        let done = export(&path, &key, None, &mut out).unwrap();
        assert_eq!((done.records, done.receipts), (3, 2));
        assert_eq!(done.head, last.hash);
        let text = String::from_utf8(out).unwrap();
        let checked = verify(text.as_bytes(), &keys_for(&key)).unwrap();
        assert!(checked.ok(), "{checked:?}");
        assert_eq!(checked.last, done.last);
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[1]["payload"]["mcpdef"]["seq"], 2);
        assert!(export(&path, &key, Some((&last.hash, 3)), &mut Vec::new()).is_ok());

        // A seal it does not match, and a chain that is broken, are refused.
        let err = export(&path, &key, Some((&last.hash, 4)), &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("the seal 4"), "{err}");
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("list_issues", "list_users");
        std::fs::write(&path, edited).unwrap();
        let mut out = Vec::new();
        let err = export(&path, &key, None, &mut out).unwrap_err();
        assert!(err.to_string().contains("broken at seq 0"), "{err}");
        assert!(out.is_empty());
    }

    #[test]
    fn export_refuses_a_record_with_the_separator_in_a_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // As an older gateway wrote it: its hash cannot tell `x␟allow` with
        // `deny` from `x` with `allow`.
        let mut rec = record(0, &format!("x{}allow", '\x1f'), "deny", None);
        rec.hash = rec.compute_hash();
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&rec).unwrap())).unwrap();
        assert!(crate::verify(&path).unwrap().ok(), "the chain itself holds");
        let err = export(&path, &key(), None, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("U+001F"), "{err}");
    }

    #[test]
    fn export_leaves_a_line_still_being_written_for_the_next_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut rec = record(0, "t", "allow", None);
        rec.hash = rec.compute_hash();
        let whole = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, format!("{whole}\n{}", &whole[..20])).unwrap();
        let done = export(&path, &key(), None, &mut Vec::new()).unwrap();
        assert_eq!((done.records, done.receipts), (1, 1));
    }

    #[test]
    fn verify_refuses_a_member_named_twice_and_hex_in_capitals() {
        let key = key();
        let keys = keys_for(&key);
        let line = Receipts::new(&key)
            .sign(&record(0, "t", "deny", Some("tools.deny")))
            .unwrap();
        // A reader that keeps the first `decision` would read "allow".
        let twice = line.replacen("{\"payload\":{", "{\"payload\":{\"decision\":\"allow\",", 1);
        assert_ne!(twice, line);
        let checked = verify_lines(&[twice], &keys);
        assert!(
            checked.broken.unwrap().1.contains("duplicate field"),
            "named twice"
        );

        let r: Value = serde_json::from_str(&line).unwrap();
        let sig = r["signature"]["sig"].as_str().unwrap();
        let capitals = line.replace(sig, &sig.to_ascii_uppercase());
        let checked = verify_lines(&[capitals], &keys);
        assert!(checked.broken.unwrap().1.contains("not lowercase hex"));
    }

    #[test]
    fn verify_says_when_receipts_start_in_the_middle_of_a_chain() {
        let key = key();
        let mut receipts = Receipts::new(&key);
        let lines: Vec<String> = (0..3)
            .filter_map(|seq| receipts.sign(&record(seq, "t", "allow", None)))
            .collect();
        let whole = verify_lines(&lines, &keys_for(&key));
        assert!(whole.ok() && !whole.starts_mid_chain);
        let later = verify_lines(&lines[1..], &keys_for(&key));
        assert!(later.ok() && later.starts_mid_chain, "{later:?}");
        assert_eq!((later.receipts, later.chains), (2, 1));
    }
}
