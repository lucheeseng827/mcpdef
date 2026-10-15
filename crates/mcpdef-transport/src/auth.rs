// SPDX-License-Identifier: Apache-2.0
//! Credentials that stay the same from one request to the next: a header
//! whose value holds a secret, read when a client is built, and read again
//! once when the upstream refuses it.

use crate::http::RequestAuth;
use crate::{blocking, TransportError};
use async_trait::async_trait;
use base64::Engine;
use mcpdef_secrets::{ExposeSecret, SecretError, SecretRef, SecretString};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use std::fmt;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroizing;

/// Headers a credential may not be sent in: the ones HTTP itself or MCP's
/// transport sets, or a proxy reads. Each entry that ends in `-` stands for
/// every name that starts with it.
const RESERVED: [&str; 13] = [
    "host",
    "accept",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
    "last-event-id",
    "content-",
    "mcp-",
    "proxy-",
];

/// What a static credential is, and where its secret is read from.
#[derive(Clone)]
pub enum Credential {
    /// `Authorization: Bearer <token>`.
    Bearer(SecretRef),
    /// `<name>: <value>`, for an upstream that wants a header of its own.
    Header { name: HeaderName, value: SecretRef },
    /// `Authorization: Basic <base64 of username:password>`.
    Basic {
        username: String,
        password: SecretRef,
    },
}

impl Credential {
    /// A credential sent as the header `name`, which must be one a request
    /// may carry: not one HTTP or MCP's transport sets, nor a proxy's.
    pub fn header(name: &str, value: SecretRef) -> Result<Self, String> {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("{name:?} is not a header name"))?;
        let reserved = RESERVED.iter().any(|r| match r.strip_suffix('-') {
            Some(prefix) => name.as_str().starts_with(&format!("{prefix}-")),
            None => name.as_str() == *r,
        });
        if reserved {
            return Err(format!(
                "{name} is a header HTTP, MCP's transport or a proxy sets: \
                 send the credential in another"
            ));
        }
        Ok(Credential::Header { name, value })
    }

    /// A credential sent as HTTP Basic authentication. A user name holds no
    /// `:`, which is what separates it from the password.
    pub fn basic(username: &str, password: SecretRef) -> Result<Self, String> {
        if username.contains(':') || username.chars().any(char::is_control) {
            return Err("username holds a `:` or a control character, which Basic \
                        authentication cannot carry"
                .to_string());
        }
        Ok(Credential::Basic {
            username: username.to_string(),
            password,
        })
    }

    /// The header it is sent in.
    pub fn name(&self) -> HeaderName {
        match self {
            Credential::Header { name, .. } => name.clone(),
            Credential::Bearer(_) | Credential::Basic { .. } => AUTHORIZATION,
        }
    }

    /// Where its secret is read from, and what the setting is called.
    pub fn secret(&self) -> (&'static str, &SecretRef) {
        match self {
            Credential::Bearer(token) => ("token", token),
            Credential::Header { value, .. } => ("value", value),
            Credential::Basic { password, .. } => ("password", password),
        }
    }

    /// The header's value, from its secret as `read`. It is marked sensitive,
    /// so that its `Debug` prints no value and HTTP/2 never indexes it. The
    /// buffers it is built in are made to measure, and wiped.
    fn value(
        &self,
        read: Result<SecretString, SecretError>,
    ) -> Result<HeaderValue, TransportError> {
        let (field, secret) = self.secret();
        let failed = |why: String| TransportError::Credentials(format!("{field} {secret}: {why}"));
        let read = read.map_err(|e| {
            // The error names the place already.
            TransportError::Credentials(format!("{field} {e}"))
        })?;
        let read = read.expose_secret();
        let text = match self {
            Credential::Bearer(_) => bearer(read),
            Credential::Header { .. } => Zeroizing::new(read.to_string()),
            Credential::Basic { username, .. } => {
                let mut pair =
                    Zeroizing::new(String::with_capacity(username.len() + 1 + read.len()));
                pair.push_str(username);
                pair.push(':');
                pair.push_str(read);
                basic(&pair)
            }
        };
        sensitive(&text).ok_or_else(|| failed("holds a character no HTTP header can".into()))
    }
}

/// `Bearer <token>`, in a buffer made to measure and wiped.
pub(crate) fn bearer(token: &str) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(7 + token.len()));
    text.push_str("Bearer ");
    text.push_str(token);
    text
}

/// `Basic <base64 of pair>`, in a buffer made to measure and wiped.
pub(crate) fn basic(pair: &str) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(6 + pair.len().div_ceil(3) * 4));
    text.push_str("Basic ");
    base64::engine::general_purpose::STANDARD.encode_string(pair.as_bytes(), &mut text);
    text
}

/// `text` as a header value marked sensitive, so that its `Debug` prints no
/// value and HTTP/2 never indexes it. `None` if a header cannot hold it.
pub(crate) fn sensitive(text: &str) -> Option<HeaderValue> {
    let mut value = HeaderValue::from_str(text).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// Names where the secret comes from, never what it is.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (field, secret) = self.secret();
        write!(f, "{} {field} {secret}", self.name())
    }
}

/// A [`Credential`] on every request: its header, with the value read when
/// it was built. When the upstream refuses it, the secret is read again, once
/// for however many requests were refused at once.
pub struct StaticAuth {
    credential: Credential,
    name: HeaderName,
    current: Mutex<HeaderValue>,
    refreshing: tokio::sync::Mutex<()>,
}

impl StaticAuth {
    /// `credential`, its secret read now, off the async workers: one a
    /// command writes can take seconds.
    pub async fn read(credential: Credential) -> Result<Self, TransportError> {
        let value = value_of(&credential).await?;
        Ok(StaticAuth {
            name: credential.name(),
            current: Mutex::new(value),
            credential,
            refreshing: tokio::sync::Mutex::new(()),
        })
    }

    fn current(&self) -> HeaderValue {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// `credential`'s header value, its secret read now.
async fn value_of(credential: &Credential) -> Result<HeaderValue, TransportError> {
    credential.value(read_secret(credential.secret().1).await)
}

/// `secret`, read now on tokio's blocking pool, off the async workers: one a
/// command writes can take seconds, and a file can sit on a slow mount. The
/// gateway reads every secret a credential or a stdio server's environment
/// holds here, so that one copy of the blocking-pool hop serves them all.
pub async fn read_secret(secret: &SecretRef) -> Result<SecretString, SecretError> {
    let secret = secret.clone();
    blocking(move || secret.resolve()).await
}

#[async_trait]
impl RequestAuth for StaticAuth {
    async fn apply(&self, headers: &mut HeaderMap) -> Result<(), TransportError> {
        headers.insert(self.name.clone(), self.current());
        Ok(())
    }

    /// Read the secret again, unless another refused request already has
    /// since this one was sent: then it retries with what that one read.
    async fn refresh(&self, sent: &HeaderMap) -> Result<bool, TransportError> {
        let _one_at_a_time = self.refreshing.lock().await;
        let current = self.current();
        if sent.get(&self.name) != Some(&current) {
            return Ok(true);
        }
        let fresh = value_of(&self.credential).await?;
        if fresh == current {
            return Ok(false);
        }
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = fresh;
        Ok(true)
    }
}
