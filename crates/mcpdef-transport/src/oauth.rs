// SPDX-License-Identifier: Apache-2.0
//! A bearer token from an OAuth 2.0 authorization server, by the client
//! credentials grant (RFC 6749 §4.4): fetched when a request first needs one,
//! sent until 30 s before it expires, and fetched afresh when the upstream
//! refuses it. However many requests need a token at once, one fetch serves
//! them all.

use crate::auth::{basic, bearer, read_secret, sensitive};
use crate::http::{fetch, RequestAuth};
use crate::tls::TlsSettings;
use crate::{EgressPolicy, TransportError};
use async_trait::async_trait;
use mcpdef_secrets::{ExposeSecret, SecretRef};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::Value;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::form_urlencoded;
use zeroize::Zeroizing;

/// How long before a token expires MCPdef stops sending it. A token that
/// lives less than twice this is sent for the first half of its life.
const MARGIN: Duration = Duration::from_secs(30);

/// How the client proves itself to the token endpoint, by the names RFC 7591
/// gives the methods.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientAuth {
    /// `client_secret_basic`: HTTP Basic authentication, the id and the
    /// secret each form-encoded first (RFC 6749 §2.3.1).
    #[default]
    Basic,
    /// `client_secret_post`: the id and the secret in the request's body.
    Post,
}

/// What to ask a token endpoint for, and how to prove who is asking.
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    /// Read at each fetch, so a rotated secret is used from the next one.
    pub client_secret: SecretRef,
    pub client_auth: ClientAuth,
    /// Sent space-separated as `scope`, when there are any.
    pub scopes: Vec<String>,
    /// RFC 8707's `resource`: the upstream the token is for.
    pub resource: Option<String>,
}

impl ClientCredentials {
    /// The token request's form body, and for `client_secret_basic` its
    /// `Authorization` header. The secret is in one of them. Each is built in
    /// a buffer sized for the most form encoding can make of it, so that it is
    /// never copied as it grows, and wiped.
    fn request(&self, secret: &str) -> (Zeroizing<String>, Option<HeaderValue>) {
        // Form encoding writes a byte as three at most.
        let most = |fields: &[&str]| fields.iter().map(|f| 3 * f.len()).sum::<usize>();
        let scope = self.scopes.join(" ");
        let resource = self.resource.as_deref().unwrap_or_default();
        let credentials = most(&[&self.client_id, secret]);
        let mut body = Zeroizing::new(String::with_capacity(
            96 + most(&[&scope, resource]) + credentials,
        ));
        let mut form = form_urlencoded::Serializer::new(&mut *body);
        form.append_pair("grant_type", "client_credentials");
        if !scope.is_empty() {
            form.append_pair("scope", &scope);
        }
        if let Some(resource) = &self.resource {
            form.append_pair("resource", resource);
        }
        let header = match self.client_auth {
            ClientAuth::Post => {
                form.append_pair("client_id", &self.client_id);
                form.append_pair("client_secret", secret);
                None
            }
            ClientAuth::Basic => {
                let mut pair = Zeroizing::new(String::with_capacity(1 + credentials));
                pair.extend(form_urlencoded::byte_serialize(self.client_id.as_bytes()));
                pair.push(':');
                pair.extend(form_urlencoded::byte_serialize(secret.as_bytes()));
                sensitive(&basic(&pair))
            }
        };
        form.finish();
        (body, header)
    }
}

/// A token, as the header it goes in, and when to stop sending it, if its
/// server said when it expires.
#[derive(Clone)]
struct Token {
    value: HeaderValue,
    until: Option<Instant>,
    /// When it expires, in seconds since the Unix epoch, if its server said.
    expires: Option<i64>,
}

/// The token in a token endpoint's answer (RFC 6749 §5.1), sent until
/// [`MARGIN`] before it expires, counted from `asked`: when the request went.
/// An error answer (§5.2) says its `error` code, one the RFC defines, and not
/// its description, which is the server's own text.
fn token(url: &str, status: StatusCode, answer: &[u8], asked: Instant) -> Result<Token, String> {
    // As text: the binary holds that parser already.
    let answer: Value = std::str::from_utf8(answer)
        .ok()
        .and_then(|answer| serde_json::from_str(answer).ok())
        .unwrap_or_default();
    if !status.is_success() {
        return Err(match answer.get("error").and_then(Value::as_str) {
            Some(code) if is_code(code) => {
                format!("token endpoint {url} answered {status}: {code}")
            }
            _ => format!("token endpoint {url} answered {status}"),
        });
    }
    let Value::Object(mut answer) = answer else {
        return Err(format!("token endpoint {url} answered with no token"));
    };
    // Taken out first, so that it is wiped whatever else is wrong.
    let Some(Value::String(token)) = answer.remove("access_token") else {
        return Err(format!("token endpoint {url} answered with no token"));
    };
    let token = Zeroizing::new(token);
    if token.is_empty() {
        return Err(format!("token endpoint {url} answered with no token"));
    }
    // Required, but some servers leave it out: then it is taken for one.
    let bearer_type = match answer.get("token_type") {
        Some(Value::String(kind)) => kind.eq_ignore_ascii_case("bearer"),
        Some(_) => false,
        None => true,
    };
    if !bearer_type {
        return Err(format!(
            "token endpoint {url} gave a token whose token_type is not Bearer, which MCPdef \
             cannot send"
        ));
    }
    let value = sensitive(&bearer(&token))
        .ok_or_else(|| format!("token endpoint {url} gave a token no HTTP header can carry"))?;
    // A number, as the RFC has it, or a string of one, as some servers send.
    let lifetime = match answer.get("expires_in") {
        Some(Value::Number(secs)) => secs.as_f64(),
        Some(Value::String(secs)) => secs.trim().parse().ok(),
        _ => None,
    };
    let life = lifetime.and_then(|secs| Duration::try_from_secs_f64(secs).ok());
    let until = life.and_then(|life| asked.checked_add(life - (life / 2).min(MARGIN)));
    // As the clock on the wall has it: when the request went, and then its life.
    let expires = life.and_then(|life| {
        let asked_at = SystemTime::now().checked_sub(asked.elapsed())?;
        let expires = asked_at
            .checked_add(life)?
            .duration_since(UNIX_EPOCH)
            .ok()?;
        i64::try_from(expires.as_secs()).ok()
    });
    Ok(Token {
        value,
        until,
        expires,
    })
}

/// Whether `code` is an `error` code as RFC 6749 §5.2 allows one: printable
/// ASCII but `"` and `\`, and short.
fn is_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

/// A bearer token on every request, fetched by the client credentials grant
/// ([`ClientCredentials`]) through the egress guard, with a TLS profile of its
/// own and no redirects.
///
/// - **Fetched when first needed**, and sent until 30 s before it expires, or
///   for half the life of one that lives less than a minute. One whose server
///   does not say when it expires is sent until the upstream refuses it.
/// - **One fetch at a time.** Requests that need a token while one is being
///   fetched wait for it, and take what it gave: the token, or why there is
///   none. A request that needs one after a failure fetches again.
/// - **Refused**, it is fetched afresh, unless another refused request has
///   already: then the request goes again with that one.
/// - **The secret is read at each fetch**, on the blocking pool, and the
///   profile's files too. What the secret and the token pass through is wiped.
pub struct TokenAuth {
    grant: ClientCredentials,
    egress: EgressPolicy,
    tls: TlsSettings,
    cache: Mutex<Cache>,
    fetching: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Cache {
    /// What the latest fetch gave: a token, or why there is none.
    latest: Option<Result<Token, String>>,
    /// How many fetches have finished, however each ended.
    fetches: u64,
}

impl TokenAuth {
    /// Tokens `grant` fetches, through `egress`, verified as `tls` says.
    /// Nothing is fetched or read until a request needs a token.
    pub fn new(grant: ClientCredentials, egress: EgressPolicy, tls: TlsSettings) -> Self {
        TokenAuth {
            grant,
            egress,
            tls,
            cache: Mutex::default(),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The token the first fetch to finish after the `seen`th gave: this
    /// call's, unless another finished while it waited its turn.
    async fn fetch_after(&self, seen: u64) -> Result<HeaderValue, TransportError> {
        let _one_at_a_time = self.fetching.lock().await;
        let latest = {
            let cache = self.cache();
            match &cache.latest {
                Some(latest) if cache.fetches != seen => Some(latest.clone()),
                _ => None,
            }
        };
        let latest = match latest {
            Some(latest) => latest,
            None => {
                let fetched = self.fetch().await;
                let mut cache = self.cache();
                cache.fetches += 1;
                cache.latest = Some(fetched.clone());
                fetched
            }
        };
        latest
            .map(|token| token.value)
            .map_err(TransportError::Credentials)
    }

    /// Ask the token endpoint for a token, now. The error says what failed,
    /// and where the secret comes from, never a secret.
    async fn fetch(&self) -> Result<Token, String> {
        let url = self.grant.token_url.as_str();
        let asked = Instant::now();
        let secret = read_secret(&self.grant.client_secret)
            .await
            .map_err(|e| format!("client_secret {e}"))?;
        let (body, header) = self.grant.request(secret.expose_secret());
        drop(secret);
        let failed = |e: TransportError| format!("token endpoint {url}: {e}");
        let tls = self.tls.load_async().await.map_err(failed)?;
        let post = |client: &reqwest::Client| {
            let request = client
                .post(url)
                .header(ACCEPT, "application/json")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(String::clone(&body));
            match &header {
                Some(value) => request.header(AUTHORIZATION, value.clone()),
                None => request,
            }
        };
        let answer = fetch(url, "POST", &self.egress, &tls, &post)
            .await
            .map_err(failed)?;
        token(url, answer.status, &Zeroizing::new(answer.body), asked)
    }
}

#[async_trait]
impl RequestAuth for TokenAuth {
    async fn apply(&self, headers: &mut HeaderMap) -> Result<(), TransportError> {
        let seen = {
            let cache = self.cache();
            if let Some(Ok(token)) = &cache.latest {
                if token.until.is_none_or(|until| Instant::now() < until) {
                    headers.insert(AUTHORIZATION, token.value.clone());
                    return Ok(());
                }
            }
            cache.fetches
        };
        headers.insert(AUTHORIZATION, self.fetch_after(seen).await?);
        Ok(())
    }

    /// Fetch a token afresh, unless another refused request already has since
    /// this one was sent: then it goes again with that one.
    async fn refresh(&self, sent: &HeaderMap) -> Result<bool, TransportError> {
        let sent = sent.get(AUTHORIZATION);
        let seen = {
            let cache = self.cache();
            let current = match &cache.latest {
                Some(Ok(token)) => Some(&token.value),
                _ => None,
            };
            if sent != current {
                return Ok(true);
            }
            cache.fetches
        };
        let fresh = self.fetch_after(seen).await?;
        Ok(sent != Some(&fresh))
    }

    /// The expiry of the token it holds now. It is fetched afresh only when a
    /// request needs one, so an upstream no one calls holds one that expired.
    fn expires_at(&self) -> Option<i64> {
        match &self.cache().latest {
            Some(Ok(token)) => token.expires,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// When a token is sent until, `asked` plus what that says, for an
    /// answer holding `expires_in`.
    fn sent_for(expires_in: Value) -> Option<Duration> {
        let asked = Instant::now();
        let answer =
            json!({ "access_token": "t", "token_type": "Bearer", "expires_in": expires_in });
        let token = token("u", StatusCode::OK, answer.to_string().as_bytes(), asked).unwrap();
        token.until.map(|until| until - asked)
    }

    #[test]
    fn a_token_is_sent_until_30_s_before_it_expires_or_for_half_a_short_life() {
        let secs = Duration::from_secs;
        assert_eq!(sent_for(json!(3600)), Some(secs(3570)));
        assert_eq!(sent_for(json!(61)), Some(secs(31)));
        assert_eq!(sent_for(json!(60)), Some(secs(30)));
        assert_eq!(sent_for(json!(31)), Some(Duration::from_millis(15_500)));
        assert_eq!(sent_for(json!(1)), Some(Duration::from_millis(500)));
        assert_eq!(sent_for(json!(0)), Some(Duration::ZERO));
        assert_eq!(sent_for(json!("90")), Some(secs(60)));
        assert_eq!(sent_for(json!(90.0)), Some(secs(60)));
        for never in [
            json!(null),
            json!(-1),
            json!(1e300),
            json!("soon"),
            json!([1]),
        ] {
            assert_eq!(sent_for(never.clone()), None, "{never}");
        }
    }
}
