// SPDX-License-Identifier: Apache-2.0
//! The console's sessions: who signed in, sealed with AES-256-GCM into a
//! cookie the browser keeps, so the gateway holds nothing per session but the
//! key, and the sessions signed out of before they expired.
//!
//! A session lasts [`ABSOLUTE`] at most, and ends after [`IDLE`] unused. Its
//! `seen` is the last time it was sealed: one more than [`RENEW_AFTER`] old is
//! sealed again with `seen` now, so idleness counts from about the last use.
//! Signing out puts its `sid` on a denylist until the session would have
//! expired. The key is `[gateway.admin.session] key`, or
//! `<state_dir>/session.key`, 32 random bytes written `0600` the first time
//! the gateway needs it; `previous_key` is tried second, so that a rotated
//! key signs no one out.

use crate::config::Config;
use base64::Engine as _;
use mcpdef_secrets::ExposeSecret;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// The cookie's name. `__Host-` makes a browser keep it only when it is set
/// `Secure`, on `Path=/`, with no `Domain`: no other host can set it.
pub const COOKIE: &str = "__Host-mcpdef-session";
/// The longest a session lasts.
pub const ABSOLUTE: Duration = Duration::from_secs(8 * 60 * 60);
/// How long a session lasts unused.
pub const IDLE: Duration = Duration::from_secs(30 * 60);
/// How old a session's `seen` grows before it is sealed again.
pub const RENEW_AFTER: Duration = Duration::from_secs(5 * 60);
/// How long a key is.
const KEY_LEN: usize = 32;

/// Who signed in, and when: what a session cookie seals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The session's own id, for signing it out.
    pub sid: String,
    /// The identity provider that signed them in, and whom it named.
    pub iss: String,
    pub sub: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    /// When it began, when it ends, and when it was last sealed: seconds
    /// since the Unix epoch.
    pub iat: u64,
    pub exp: u64,
    pub seen: u64,
}

/// Why a cookie holds no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not one a key here sealed.
    Forged,
    /// Past its end.
    Expired,
    /// Unused for longer than [`IDLE`].
    Idle,
    /// Signed out of.
    SignedOut,
}

/// The keys sessions are sealed with, and the sessions signed out of.
pub struct Sessions {
    /// The key that seals, then the one before it, which only opens.
    keys: Vec<LessSafeKey>,
    random: SystemRandom,
    /// Each session signed out of, until it would have expired.
    signed_out: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    /// Sessions sealed with `key`, and opened with it or `previous`.
    pub fn new(key: &[u8; KEY_LEN], previous: Option<&[u8; KEY_LEN]>) -> Sessions {
        let aead = |key: &[u8; KEY_LEN]| {
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte key"))
        };
        Sessions {
            keys: std::iter::once(key).chain(previous).map(aead).collect(),
            random: SystemRandom::new(),
            signed_out: Mutex::default(),
        }
    }

    /// `n` random bytes, in unpadded base64url: a state, a nonce, a PKCE
    /// verifier.
    pub fn random_text(&self, n: usize) -> String {
        let mut bytes = vec![0u8; n];
        self.random
            .fill(&mut bytes)
            .expect("the system's random source");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A new session for `sub` of `iss`, holding `roles`, from `now`.
    pub fn begin(
        &self,
        iss: &str,
        sub: &str,
        name: Option<String>,
        roles: Vec<String>,
        now: u64,
    ) -> Session {
        let mut sid = [0u8; 16];
        self.random
            .fill(&mut sid)
            .expect("the system's random source");
        Session {
            sid: hex::encode(sid),
            iss: iss.to_string(),
            sub: sub.to_string(),
            name,
            roles,
            iat: now,
            exp: now + ABSOLUTE.as_secs(),
            seen: now,
        }
    }

    /// `value`, sealed for the cookie `cookie`: a random nonce and the
    /// ciphertext, in unpadded base64url. The cookie's name is the
    /// associated data, so what is sealed for one cookie opens as no other.
    pub fn seal_as<T: Serialize>(&self, cookie: &str, value: &T) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .expect("the system's random source");
        let mut sealed = serde_json::to_vec(value).expect("what is sealed serializes");
        self.keys[0]
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(cookie.as_bytes()),
                &mut sealed,
            )
            .expect("what is sealed fits");
        let mut out = nonce.to_vec();
        out.append(&mut sealed);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    }

    /// What `sealed` seals for the cookie `cookie`, if one of the keys
    /// sealed it.
    pub fn open_as<T: serde::de::DeserializeOwned>(&self, cookie: &str, sealed: &str) -> Option<T> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed.trim())
            .ok()?;
        if bytes.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        self.keys.iter().find_map(|key| {
            let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
            let mut opened = ciphertext.to_vec();
            let plain = key
                .open_in_place(nonce, Aad::from(cookie.as_bytes()), &mut opened)
                .ok()?;
            serde_json::from_slice::<T>(plain).ok()
        })
    }

    /// `session`, sealed for its cookie.
    pub fn seal(&self, session: &Session) -> String {
        self.seal_as(COOKIE, session)
    }

    /// The session a cookie's value seals, if one of the keys sealed it and
    /// it has not ended, gone idle or been signed out of, at `now`.
    pub fn open(&self, sealed: &str, now: u64) -> Result<Session, Refused> {
        let session: Session = self.open_as(COOKIE, sealed).ok_or(Refused::Forged)?;
        if now >= session.exp {
            return Err(Refused::Expired);
        }
        if now >= session.seen + IDLE.as_secs() {
            return Err(Refused::Idle);
        }
        if self.signed_out(&session.sid) {
            return Err(Refused::SignedOut);
        }
        Ok(session)
    }

    /// `session` with `seen` now, sealed again, when its `seen` is older
    /// than [`RENEW_AFTER`]; `None` while it is newer.
    pub fn renewed(&self, session: &Session, now: u64) -> Option<(Session, String)> {
        if now < session.seen + RENEW_AFTER.as_secs() {
            return None;
        }
        let renewed = Session {
            seen: now,
            ..session.clone()
        };
        let sealed = self.seal(&renewed);
        Some((renewed, sealed))
    }

    /// Sign `session` out: no cookie that seals it opens again. Those signed
    /// out of that have expired since are let go.
    pub fn sign_out(&self, session: &Session, now: u64) {
        let mut signed_out = self.signed_out.lock().unwrap_or_else(|e| e.into_inner());
        signed_out.retain(|_, exp| *exp > now);
        signed_out.insert(session.sid.clone(), session.exp);
    }

    fn signed_out(&self, sid: &str) -> bool {
        let signed_out = self.signed_out.lock().unwrap_or_else(|e| e.into_inner());
        signed_out.contains_key(sid)
    }
}

/// The `Set-Cookie` value that keeps `sealed` for `session`, until it ends.
pub fn cookie(sealed: &str, session: &Session, now: u64) -> String {
    format!(
        "{COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        session.exp.saturating_sub(now)
    )
}

/// The `Set-Cookie` value that clears the session cookie.
pub fn cleared() -> String {
    format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The keys `cfg` seals sessions with: `[gateway.admin.session] key` and
/// `previous_key`, each 32 bytes in base64 or hex, or else the key in
/// `<state_dir>/session.key`, made the first time.
pub fn keys(cfg: &Config) -> Result<Sessions, String> {
    let session = cfg.gateway.admin.session.as_ref();
    let from_config = |name: &str, key: &mcpdef_secrets::SecretRef| {
        let text = key
            .resolve()
            .map_err(|e| format!("[gateway.admin.session] {name}: {e}"))?;
        decode_key(text.expose_secret()).ok_or_else(|| {
            format!("[gateway.admin.session] {name}: {KEY_LEN} bytes, in base64 or hex")
        })
    };
    let key = match session.and_then(|s| s.key.as_ref()) {
        Some(key) => from_config("key", key)?,
        None => stored_key(&Path::new(&cfg.gateway.state_dir).join("session.key"))?,
    };
    let previous = match session.and_then(|s| s.previous_key.as_ref()) {
        Some(key) => Some(from_config("previous_key", key)?),
        None => None,
    };
    Ok(Sessions::new(&key, previous.as_ref()))
}

/// A key written as base64 (standard or URL-safe, padded or not) or hex.
fn decode_key(text: &str) -> Option<[u8; KEY_LEN]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let text = text.trim();
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok().filter(|b| b.len() == KEY_LEN))
        .or_else(|| hex::decode(text).ok().filter(|b| b.len() == KEY_LEN))?;
    decoded.try_into().ok()
}

/// The key in `path`, made there the first time: 32 random bytes, readable
/// by MCPdef's user alone.
fn stored_key(path: &Path) -> Result<[u8; KEY_LEN], String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            return bytes.try_into().map_err(|bytes: Vec<u8>| {
                format!(
                    "{} holds {} bytes, and a session key is {KEY_LEN}: delete it, and the \
                     gateway makes a new one (signing everyone out)",
                    path.display(),
                    bytes.len()
                )
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    }
    let mut key = [0u8; KEY_LEN];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| "the system's random source failed".to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("making {}: {e}", dir.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    std::io::Write::write_all(&mut file, &key)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    const NOW: u64 = 1_800_000_000;
    const LOGIN: &str = crate::admin::signin::LOGIN_COOKIE;

    fn sessions() -> Sessions {
        Sessions::new(&[7u8; KEY_LEN], None)
    }

    fn ann(s: &Sessions) -> Session {
        s.begin(
            "https://idp.example",
            "ann",
            Some("Ann".into()),
            vec!["console:operator".into()],
            NOW,
        )
    }

    #[test]
    fn a_session_round_trips_and_ends_when_it_should() {
        let s = sessions();
        let session = ann(&s);
        assert_eq!(session.exp, NOW + 8 * 3600);
        assert_eq!(session.sid.len(), 32);
        let sealed = s.seal(&session);
        assert_eq!(s.open(&sealed, NOW + 60), Ok(session.clone()));
        // Two seals of one session differ: each has its own nonce.
        assert_ne!(s.seal(&session), sealed);
        // Idle for 30 minutes, it ends; renewed, it lasts.
        assert_eq!(s.open(&sealed, NOW + IDLE.as_secs()), Err(Refused::Idle));
        assert_eq!(s.renewed(&session, NOW + 60), None);
        let (renewed, resealed) = s.renewed(&session, NOW + 400).unwrap();
        assert_eq!(renewed.seen, NOW + 400);
        assert_eq!(
            s.open(&resealed, NOW + 400 + IDLE.as_secs() - 1),
            Ok(renewed.clone())
        );
        // However used, it ends after 8 hours.
        let late = Session {
            seen: NOW + 8 * 3600 - 10,
            ..renewed
        };
        assert_eq!(
            s.open(&s.seal(&late), NOW + 8 * 3600),
            Err(Refused::Expired)
        );
    }

    #[test]
    fn tampering_a_wrong_key_and_signing_out_each_refuse() {
        let s = sessions();
        let session = ann(&s);
        let sealed = s.seal(&session);
        // Any byte changed.
        let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&sealed)
            .unwrap();
        for i in [0, NONCE_LEN, bytes.len() - 1] {
            bytes[i] ^= 1;
            let changed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
            assert_eq!(s.open(&changed, NOW), Err(Refused::Forged), "byte {i}");
            bytes[i] ^= 1;
        }
        // Another key.
        let other = Sessions::new(&[8u8; KEY_LEN], None);
        assert_eq!(other.open(&sealed, NOW), Err(Refused::Forged));
        // Signed out: refused until it would have ended.
        s.sign_out(&session, NOW + 10);
        assert_eq!(s.open(&sealed, NOW + 20), Err(Refused::SignedOut));
        let another = ann(&s);
        assert!(s.open(&s.seal(&another), NOW + 20).is_ok());
    }

    #[test]
    fn a_rotated_key_still_opens_what_the_old_one_sealed() {
        let (old, new) = ([1u8; KEY_LEN], [2u8; KEY_LEN]);
        let before = Sessions::new(&old, None);
        let session = ann(&before);
        let sealed = before.seal(&session);
        let after = Sessions::new(&new, Some(&old));
        assert_eq!(after.open(&sealed, NOW), Ok(session.clone()));
        // What it seals now, the old key alone does not open.
        assert_eq!(
            before.open(&after.seal(&session), NOW),
            Err(Refused::Forged)
        );
        let dropped = Sessions::new(&new, None);
        assert_eq!(dropped.open(&sealed, NOW), Err(Refused::Forged));
    }

    #[test]
    fn a_key_is_read_as_base64_or_hex_and_one_is_made_once() {
        let key = [9u8; KEY_LEN];
        for text in [
            base64::engine::general_purpose::STANDARD.encode(key),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
            hex::encode(key),
            format!("  {}\n", hex::encode(key)),
        ] {
            assert_eq!(decode_key(&text), Some(key), "{text:?}");
        }
        for text in ["", "short", &hex::encode([1u8; 16])] {
            assert_eq!(decode_key(text), None, "{text:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/session.key");
        let made = stored_key(&path).unwrap();
        assert_eq!(stored_key(&path).unwrap(), made);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::write(&path, b"short").unwrap();
        assert!(stored_key(&path).unwrap_err().contains("holds 5 bytes"));
    }

    #[test]
    fn the_keys_come_from_the_config_or_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |session: &str| {
            Config::parse(&format!(
                "[gateway]\nstate_dir = {:?}\n\n[gateway.admin]\nenabled = true\n{session}\n\n\
                 [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n",
                dir.path().join("state")
            ))
            .unwrap()
        };
        let (old, new) = ([3u8; KEY_LEN], [4u8; KEY_LEN]);
        let b64 = |key: [u8; KEY_LEN]| base64::engine::general_purpose::STANDARD.encode(key);
        // Configured, with the key before it.
        let set = cfg(&format!(
            "[gateway.admin.session]\nkey = {:?}\nprevious_key = {:?}",
            b64(new),
            hex::encode(old)
        ));
        let sealed_before = Sessions::new(&old, None).seal(&ann(&sessions()));
        let rotated = keys(&set).unwrap();
        assert!(rotated.open(&sealed_before, NOW).is_ok());
        // None: the state dir's, made once and kept.
        let made = keys(&cfg("")).unwrap();
        let session = ann(&made);
        let sealed = made.seal(&session);
        assert_eq!(keys(&cfg("")).unwrap().open(&sealed, NOW), Ok(session));
        assert!(dir.path().join("state/session.key").exists());
        // Not a key.
        let wrong = cfg("[gateway.admin.session]\nkey = \"too short\"");
        assert_eq!(
            keys(&wrong).err().unwrap(),
            "[gateway.admin.session] key: 32 bytes, in base64 or hex"
        );
    }

    #[test]
    fn the_cookie_is_host_bound_and_lasts_as_the_session_does() {
        let s = sessions();
        let session = ann(&s);
        assert_eq!(
            cookie("abc", &session, NOW + 100),
            format!(
                "__Host-mcpdef-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
                8 * 3600 - 100
            )
        );
        assert!(cleared().ends_with("Max-Age=0"));
    }

    proptest! {
        /// No byte string opens but one the key sealed.
        #[test]
        fn nothing_opens_but_what_the_key_sealed(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let s = sessions();
            let as_cookie = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
            prop_assert_eq!(s.open(&as_cookie, NOW), Err(Refused::Forged));
            let text = String::from_utf8_lossy(&bytes).to_string();
            prop_assert!(s.open(&text, NOW).is_err());
            prop_assert_eq!(s.open_as::<Value>(LOGIN, &as_cookie), None);
        }

        /// What is sealed for one cookie opens for that cookie alone, and only
        /// as it was sealed: one byte of it changed, wherever, it opens as
        /// nothing.
        #[test]
        fn a_sealed_value_opens_for_its_cookie_alone_and_untouched(
            value in "\\PC{0,64}",
            at in any::<proptest::sample::Index>(),
            flip in 1u8..=255,
        ) {
            let s = sessions();
            let sealed = s.seal_as(LOGIN, &value);
            prop_assert_eq!(s.open_as::<String>(LOGIN, &sealed), Some(value.clone()));
            prop_assert_eq!(s.open_as::<String>(COOKIE, &sealed), None);
            let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut bytes = engine.decode(&sealed).unwrap();
            let i = at.index(bytes.len());
            bytes[i] ^= flip;
            prop_assert_eq!(s.open_as::<String>(LOGIN, &engine.encode(&bytes)), None);
        }
    }
}
