// SPDX-License-Identifier: Apache-2.0
//! Signing in to the console: a relying party of the identity provider
//! `[gateway.admin.oidc]` names, by OpenID Connect's authorization code flow,
//! with PKCE, a `state` and a `nonce`, as a confidential client.
//!
//! - `GET /login` starts it: a `state`, a `nonce` and a PKCE verifier, from
//!   ring's random source, sealed into a ten-minute `__Host-mcpdef-login`
//!   cookie, and the browser sent to the provider.
//! - `GET /callback` finishes it: the `state` compared in constant time with
//!   the cookie's; RFC 9207's `iss` checked when the provider sends it, and
//!   required when it says it does; the code exchanged at the token endpoint,
//!   with the verifier; the ID token verified (signature and algorithm, `iss`,
//!   `aud`, `azp`, `exp`, `iat`, `nonce`); userinfo read when configured; and
//!   the subject and roles taken by `[identity]`, as a bearer token's are. A
//!   caller with a console role gets a session; one with none, a page of the
//!   claims MCPdef received, theirs alone to see. No token is kept.
//! - `POST /logout` signs the session out, and says where the provider signs
//!   them out too, when it says it can.
//!
//! The provider is found from its issuer's metadata (OpenID Connect
//! Discovery's document, else RFC 8414's), through the egress guard and
//! `[gateway.upstream_tls]`, when the gateway starts and, if that failed, at
//! a sign-in: the data plane never waits on it.
//! Signing in, a refusal of it, and signing out are each recorded.

use super::session::{self, Session, Sessions};
use super::{problem, AdminState, Caller, ConsoleRole};
use crate::config::{Config, OidcConfig};
use crate::listener::Fetching;
use arc_swap::{ArcSwap, ArcSwapOption};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use base64::Engine as _;
use mcpdef_auth::{same, AuthError, IdentityModel, Verifier};
use mcpdef_secrets::{ExposeSecret, SecretRef};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The cookie that carries a sign-in from `/login` to `/callback`.
pub const LOGIN_COOKIE: &str = "__Host-mcpdef-login";
/// How long a sign-in may take.
const LOGIN_FOR: u64 = 10 * 60;
/// The most finished sign-ins remembered, so that none finishes twice.
const FINISHED_KEPT: usize = 4096;
/// How many refused sign-ins a minute are recorded, one record each. Anyone
/// who reaches the listener can be refused, so past these one more record
/// says the rest of that minute's are not: the ledger grows by so much at
/// most, however many are refused.
const REFUSALS_RECORDED: u32 = 20;
/// The rule of that record.
const REFUSALS_UNRECORDED: &str = "sign-in-refusals-unrecorded";
/// How long after the provider was looked for and not found a sign-in waits
/// before it is looked for again, so that one down is not asked at each.
const LOOK_AGAIN: Duration = Duration::from_secs(5);

/// The console's sign-in: what `[gateway.admin.oidc]` says, the sessions it
/// begins, and the provider, once found.
pub(crate) struct SignIn {
    oidc: OidcConfig,
    /// `<public_url>/callback`, and `public_url` itself.
    redirect_uri: String,
    public_url: String,
    pub(crate) sessions: Arc<Sessions>,
    /// How its fetches go out: `[gateway.egress]` and
    /// `[gateway.upstream_tls]`, as the last config applied says them.
    fetching: ArcSwap<Fetching>,
    model: IdentityModel,
    provider: ArcSwapOption<Provider>,
    /// When the provider was last looked for, while it is not found, and
    /// why it was not.
    looked: Mutex<Option<(Instant, String)>>,
    /// The state of each sign-in finished, until it would have expired: an
    /// answer replayed with its cookie is refused here, whatever the provider
    /// does with its code. The oldest are let go past [`FINISHED_KEPT`].
    finished: Mutex<VecDeque<(String, u64)>>,
    /// The minute (seconds since the Unix epoch, over 60) sign-ins were last
    /// refused in, and how many were refused in it.
    refused: Mutex<(u64, u32)>,
}

/// An identity provider, as its discovery document describes it.
struct Provider {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    /// Whether it says it sends RFC 9207's `iss` with each answer.
    sends_iss: bool,
    /// Where its keys are, read again when an ID token names one they do
    /// not hold: it has rotated them.
    jwks_uri: String,
    /// Its ID tokens, verified against its keys, with the client as their
    /// audience.
    verifier: Verifier,
    /// The tokens it issues for the admin API, with `api_audience` as their
    /// audience, when that is set.
    api: Option<Verifier>,
}

/// The scopes a token for the admin API may hold, and the console role each
/// gives.
const API_SCOPES: [(&str, &str); 2] = [
    ("mcpdef:admin:read", "console:viewer"),
    ("mcpdef:admin:write", "console:operator"),
];

/// Why a bearer token on the admin API is not taken.
pub(crate) enum ApiRefused {
    /// The provider is not found, so no token of its can be verified.
    Unavailable(String),
    /// The token is not one the provider issued for the admin API, or is no
    /// longer good.
    Invalid(String),
}

/// What `/login` seals for `/callback`.
#[derive(Serialize, Deserialize)]
struct Login {
    state: String,
    nonce: String,
    verifier: String,
    /// Where in the console to go back to.
    then: String,
    iat: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl SignIn {
    /// The sign-in `cfg` asks for, sealing sessions with `sessions`; `None`
    /// without `[gateway.admin.oidc]`.
    pub(crate) fn of(cfg: &Config, sessions: Arc<Sessions>) -> Option<SignIn> {
        let oidc = cfg.gateway.admin.oidc.clone()?;
        let public_url = cfg
            .gateway
            .admin
            .public_url
            .clone()?
            .trim_end_matches('/')
            .to_string();
        Some(SignIn {
            oidc,
            redirect_uri: format!("{public_url}/callback"),
            public_url,
            sessions,
            fetching: ArcSwap::from_pointee(Fetching::of(cfg)),
            model: cfg.identity.model(),
            provider: ArcSwapOption::empty(),
            looked: Mutex::default(),
            finished: Mutex::default(),
            refused: Mutex::default(),
        })
    }

    /// Fetch from now on as `cfg`, a config a reload applied, says: its
    /// `[gateway.egress]` and `[gateway.upstream_tls]`, as the gateway's own
    /// fetches do.
    pub(crate) fn reconfigure(&self, cfg: &Config) {
        self.fetching.store(Arc::new(Fetching::of(cfg)));
    }

    /// The rule a sign-in refused at `now` for `rule` is recorded with: its
    /// own for the first [`REFUSALS_RECORDED`] refused in a minute, then
    /// [`REFUSALS_UNRECORDED`] once, then none, no record, until the next.
    fn record_refusal(&self, rule: &'static str, now: u64) -> Option<&'static str> {
        let minute = now / 60;
        let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        if refused.0 != minute {
            *refused = (minute, 0);
        }
        refused.1 = refused.1.saturating_add(1);
        match refused.1 {
            n if n <= REFUSALS_RECORDED => Some(rule),
            n if n == REFUSALS_RECORDED + 1 => Some(REFUSALS_UNRECORDED),
            _ => None,
        }
    }

    /// Whether the sign-in with `state` finishes now, at `now`, for the
    /// first time; it is remembered until `until`.
    fn first_finish(&self, state: &str, until: u64, now: u64) -> bool {
        let mut finished = self.finished.lock().unwrap_or_else(|e| e.into_inner());
        finished.retain(|(_, until)| *until > now);
        if finished.iter().any(|(seen, _)| seen == state) {
            return false;
        }
        if finished.len() >= FINISHED_KEPT {
            finished.pop_front();
        }
        finished.push_back((state.to_string(), until));
        true
    }

    /// Find the provider: its discovery document, its issuer checked
    /// exactly, and its keys. Kept for each sign-in after; when it is not
    /// found, why is kept, for the sign-ins that come before it is looked
    /// for again.
    pub(crate) async fn discover(&self) -> Result<(), String> {
        let found = self.find().await;
        let mut looked = self.looked.lock().unwrap_or_else(|e| e.into_inner());
        *looked = found
            .as_ref()
            .err()
            .map(|why| (Instant::now(), why.clone()));
        found
    }

    async fn find(&self) -> Result<(), String> {
        let issuer = &self.oidc.issuer;
        let fetching = self.fetching.load_full();
        let tls = fetching
            .tls
            .load_async()
            .await
            .map_err(|e| format!("reading [gateway.upstream_tls], to reach {issuer}: {e}"))?;
        let found = crate::discovery::metadata(issuer, &fetching.egress, &tls).await?;
        let needed = |what: &str, value: Option<String>| {
            value.ok_or_else(|| format!("the metadata of {issuer} names no {what}"))
        };
        let authorization_endpoint =
            needed("authorization_endpoint", found.authorization_endpoint)?;
        let token_endpoint = needed("token_endpoint", found.token_endpoint)?;
        let jwks_uri = needed("jwks_uri", found.jwks_uri)?;
        let keys = mcpdef_transport::fetch_text(&jwks_uri, &fetching.egress, &tls)
            .await
            .map_err(|e| format!("its jwks_uri {jwks_uri}: {e}"))?;
        // Who the token names is read once userinfo's claims are added to
        // its own, by `[identity]`: the verifier checks the token alone.
        let verifier = |audience: &str| {
            Verifier::from_jwks_json(&keys, found.issuer.clone(), audience)
                .map_err(|e| format!("its keys, at {jwks_uri}: {e}"))
        };
        let api = match &self.oidc.api_audience {
            Some(audience) => Some(verifier(audience)?),
            None => None,
        };
        let verifier = verifier(&self.oidc.client_id)?;
        self.provider.store(Some(Arc::new(Provider {
            issuer: found.issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint: found.userinfo_endpoint,
            end_session_endpoint: found.end_session_endpoint,
            sends_iss: found.authorization_response_iss_parameter_supported,
            jwks_uri,
            verifier,
            api,
        })));
        Ok(())
    }

    /// The provider, found now if it was not before, unless it was looked
    /// for within [`LOOK_AGAIN`].
    async fn provider(&self) -> Result<Arc<Provider>, String> {
        if let Some(found) = self.provider.load_full() {
            return Ok(found);
        }
        {
            let mut looked = self.looked.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, why)) = &*looked {
                if at.elapsed() < LOOK_AGAIN {
                    return Err(format!("{why}; it is looked for again in a few seconds"));
                }
            }
            // The sign-ins that come while it is looked for wait for the next
            // look, rather than each looking.
            *looked = Some((
                Instant::now(),
                "the identity provider is being looked for".to_string(),
            ));
        }
        self.discover().await?;
        self.provider
            .load_full()
            .ok_or_else(|| "the identity provider was not found".to_string())
    }

    /// How the provider stands, for the identity view: found, with its
    /// issuer and what it says it does; or not, and why, its URLs masked.
    pub(crate) fn status(&self) -> serde_json::Value {
        match self.provider.load_full() {
            Some(found) => serde_json::json!({
                "found": true,
                "issuer": crate::redact::redact_url(&found.issuer),
                "sends_iss": found.sends_iss,
                "signs_out": found.end_session_endpoint.is_some(),
                "userinfo": found.userinfo_endpoint.is_some(),
            }),
            None => {
                let looked = self.looked.lock().unwrap_or_else(|e| e.into_inner());
                serde_json::json!({
                    "found": false,
                    "error": looked
                        .as_ref()
                        .map(|(_, why)| crate::redact::redact_urls(why).into_owned()),
                })
            }
        }
    }

    /// Whether the admin API takes the provider's tokens: `api_audience` is
    /// set.
    pub(crate) fn takes_api_tokens(&self) -> bool {
        self.oidc.api_audience.is_some()
    }

    /// The subject and the roles of a bearer token the provider issued for
    /// the admin API: the subject as `[identity]` names it, else `sub`; the
    /// roles `[identity]` reads, and the console role each of its scopes
    /// gives.
    pub(crate) async fn api_caller(
        &self,
        token: &str,
    ) -> Result<(String, Vec<String>), ApiRefused> {
        let provider = self.provider().await.map_err(ApiRefused::Unavailable)?;
        let Some(api) = &provider.api else {
            return Err(ApiRefused::Invalid(
                "this admin API takes no token of the identity provider's".to_string(),
            ));
        };
        let (principal, claims) = self
            .rotated(&provider, api, |v| v.verify_claims(token))
            .await
            .map_err(|e| ApiRefused::Invalid(e.to_string()))?;
        let subject = self.model.subject(&claims).unwrap_or(principal.subject);
        let mut roles = self.model.roles(&claims);
        for (scope, role) in API_SCOPES {
            if principal.scopes.iter().any(|s| s == scope) && !roles.iter().any(|r| r == role) {
                roles.push(role.to_string());
            }
        }
        Ok((subject, roles))
    }

    /// `verify` by `verifier`; when the token names a key the provider's keys
    /// do not hold, it has rotated them, and they are read again, at most
    /// once a minute, and the token tried again.
    async fn rotated<T>(
        &self,
        provider: &Provider,
        verifier: &Verifier,
        verify: impl Fn(&Verifier) -> Result<T, AuthError>,
    ) -> Result<T, AuthError> {
        match verify(verifier) {
            Err(AuthError::UnknownKey(kid)) if verifier.should_attempt_refresh() => {
                let fetching = self.fetching.load_full();
                let read = match fetching.tls.load_async().await {
                    Ok(tls) => {
                        mcpdef_transport::fetch_text(&provider.jwks_uri, &fetching.egress, &tls)
                            .await
                            .map_err(|e| e.to_string())
                    }
                    Err(e) => Err(e.to_string()),
                }
                .and_then(|json| verifier.refresh_jwks(&json).map_err(|e| e.to_string()));
                match read {
                    Ok(()) => verify(verifier),
                    Err(why) => {
                        let said = format!(
                            "the console's identity provider's keys, at {}: {why}",
                            provider.jwks_uri
                        );
                        eprintln!("mcpdef: {}", crate::redact::redact_urls(&said));
                        Err(AuthError::UnknownKey(kid))
                    }
                }
            }
            verified => verified,
        }
    }

    /// The client's secret, read from where it comes from now.
    async fn secret(&self) -> Result<Option<String>, String> {
        let Some(secret) = self.oidc.client_secret.clone() else {
            return Ok(None);
        };
        let read = tokio::task::spawn_blocking(move || SecretRef::resolve(&secret)).await;
        match read {
            Ok(Ok(value)) => Ok(Some(value.expose_secret().to_string())),
            Ok(Err(e)) => Err(format!("[gateway.admin.oidc] client_secret: {e}")),
            Err(e) => Err(format!("[gateway.admin.oidc] client_secret: {e}")),
        }
    }
}

/// The sign-in routes: for anyone, as they are how one signs in.
pub(super) fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", post(logout))
}

/// A page of plain HTML, as the content security policy allows: no script,
/// no style.
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title} · \
         MCPdef</title></head><body><h1>{title}</h1>{body}</body></html>",
        title = escape(title)
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The value of the cookie `name` among `headers`' cookies.
pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

fn unavailable(why: &str) -> Response {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-in unavailable",
        &format!("<p>{}</p>", escape(why)),
    )
}

/// Whether `path` is a page of this console, and nowhere else: a path from
/// its root, never `//host`, nor what a browser reads as that: it takes a
/// backslash for a slash, and drops a tab or a newline.
fn local_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.chars().all(|c| c.is_ascii_graphic() && c != '\\')
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    then: Option<String>,
}

/// `GET /login`: off to the provider, with a sign-in sealed in a cookie.
async fn login(State(s): State<Arc<AdminState>>, Query(q): Query<LoginQuery>) -> Response {
    let Some(signin) = s.signin.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "Not found",
            "this console signs no one in: [gateway.admin.oidc] is not set",
        );
    };
    let provider = match signin.provider().await {
        Ok(provider) => provider,
        Err(why) => return unavailable(&why),
    };
    let then = q
        .then
        .filter(|path| local_path(path))
        .unwrap_or_else(|| "/".to_string());
    let sessions = &signin.sessions;
    let started = Login {
        state: sessions.random_text(32),
        nonce: sessions.random_text(32),
        verifier: sessions.random_text(32),
        then,
        iat: now(),
    };
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(started.verifier.as_bytes()));
    let mut to = match url::Url::parse(&provider.authorization_endpoint) {
        Ok(url) => url,
        Err(e) => return unavailable(&format!("its authorization_endpoint: {e}")),
    };
    to.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &signin.oidc.client_id)
        .append_pair("redirect_uri", &signin.redirect_uri)
        .append_pair("scope", &signin.oidc.scopes().join(" "))
        .append_pair("state", &started.state)
        .append_pair("nonce", &started.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let sealed = sessions.seal_as(LOGIN_COOKIE, &started);
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, to.to_string()),
            (
                header::SET_COOKIE,
                format!(
                    "{LOGIN_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; \
                     Max-Age={LOGIN_FOR}"
                ),
            ),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

/// Why a sign-in was refused, as its record's rule says it and as the page
/// tells the person signing in.
struct Refusal {
    rule: &'static str,
    why: String,
}

fn refused(rule: &'static str, why: impl Into<String>) -> Refusal {
    Refusal {
        rule,
        why: why.into(),
    }
}

/// `GET /callback`: the provider's answer, checked, and a session begun.
async fn callback(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(signin) = s.signin.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "Not found",
            "this console signs no one in",
        );
    };
    let clear_login = format!("{LOGIN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    let peer = caller.peer.to_string();
    let outcome = finish(&signin, &headers, q).await;
    match outcome {
        Ok(Finished::Session(session, then)) => {
            let actor = format!("user:{}", session.sub);
            s.gateway
                .audit_admin(&actor, &peer, "sign-in", "(console)", None, None)
                .await;
            let sealed = signin.sessions.seal(&session);
            let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, then)]).into_response();
            let headers = response.headers_mut();
            for value in [session::cookie(&sealed, &session, now()), clear_login] {
                if let Ok(value) = value.parse() {
                    headers.append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Ok(Finished::NoRole(subject, claims)) => {
            s.gateway
                .audit_admin(
                    &format!("user:{subject}"),
                    &peer,
                    "sign-in",
                    "(console)",
                    None,
                    Some("no-console-role"),
                )
                .await;
            let listed: String = claims
                .iter()
                .map(|(name, value)| {
                    format!(
                        "<tr><th>{}</th><td><code>{}</code></td></tr>",
                        escape(name),
                        escape(&value.to_string())
                    )
                })
                .collect();
            let mut response = page(
                StatusCode::FORBIDDEN,
                "No console role",
                &format!(
                    "<p>You are <code>{}</code>, and the roles your identity provider gave you \
                     hold none of console:viewer, console:operator and console:admin. Ask for \
                     one; this is what MCPdef received of you, which only you see:</p>\
                     <table>{listed}</table>",
                    escape(&subject)
                ),
            );
            if let Ok(value) = clear_login.parse() {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        Err(refusal) => {
            if let Some(rule) = signin.record_refusal(refusal.rule, now()) {
                s.gateway
                    .audit_admin(
                        &caller.actor,
                        &peer,
                        "sign-in",
                        "(console)",
                        None,
                        Some(rule),
                    )
                    .await;
            }
            let mut response = page(
                StatusCode::BAD_REQUEST,
                "Sign-in refused",
                &format!(
                    "<p>{}</p><p><a href=\"/login\">Sign in again</a></p>",
                    escape(&refusal.why)
                ),
            );
            if let Ok(value) = clear_login.parse() {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
    }
}

enum Finished {
    Session(Session, String),
    NoRole(String, Map<String, Value>),
}

#[derive(Deserialize)]
struct Tokens {
    id_token: String,
    #[serde(default)]
    access_token: Option<String>,
}

async fn finish(
    signin: &SignIn,
    headers: &HeaderMap,
    q: CallbackQuery,
) -> Result<Finished, Refusal> {
    let started: Login = cookie(headers, LOGIN_COOKIE)
        .and_then(|sealed| signin.sessions.open_as(LOGIN_COOKIE, sealed))
        .ok_or_else(|| {
            refused(
                "sign-in-state",
                "this sign-in did not start here, or its cookie is gone: start again",
            )
        })?;
    let at = now();
    if at >= started.iat + LOGIN_FOR {
        return Err(refused(
            "sign-in-state",
            "this sign-in took over ten minutes: start again",
        ));
    }
    let state = q.state.unwrap_or_default();
    if !same(state.as_bytes(), started.state.as_bytes()) {
        return Err(refused(
            "sign-in-state",
            "the answer's state is not this sign-in's",
        ));
    }
    // One answer finishes a sign-in, whatever it holds.
    if !signin.first_finish(&started.state, started.iat + LOGIN_FOR, at) {
        return Err(refused(
            "sign-in-state",
            "this sign-in was finished already: start again",
        ));
    }
    if let Some(error) = q.error {
        return Err(refused(
            "sign-in-provider",
            format!("the identity provider refused it: {error}"),
        ));
    }
    let provider = signin
        .provider()
        .await
        .map_err(|why| refused("sign-in-provider", why))?;
    match q.iss {
        Some(iss) if iss != provider.issuer => {
            return Err(refused(
                "sign-in-issuer",
                format!("the answer came from {iss:?}, not {:?}", provider.issuer),
            ))
        }
        None if provider.sends_iss => {
            return Err(refused(
                "sign-in-issuer",
                "the answer does not say which provider sent it, as this one says it does",
            ))
        }
        _ => {}
    }
    let code = q
        .code
        .ok_or_else(|| refused("sign-in-provider", "the answer holds no code"))?;
    let secret = signin
        .secret()
        .await
        .map_err(|why| refused("sign-in-provider", why))?;
    // Built, and the encoder dropped, before anything is awaited: it is not
    // `Send`.
    let (form, authorization) = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &signin.redirect_uri)
            .append_pair("code_verifier", &started.verifier);
        let authorization = match (&secret, signin.oidc.posts_secret()) {
            // RFC 6749 §2.3.1: each of the pair form-encoded, then Basic.
            (Some(secret), false) => {
                let encode = |s: &str| {
                    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
                };
                let pair = format!("{}:{}", encode(&signin.oidc.client_id), encode(secret));
                let value = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair)
                );
                value.parse().ok()
            }
            (Some(secret), true) => {
                form.append_pair("client_id", &signin.oidc.client_id)
                    .append_pair("client_secret", secret);
                None
            }
            (None, _) => {
                form.append_pair("client_id", &signin.oidc.client_id);
                None
            }
        };
        (form.finish(), authorization)
    };
    let fetching = signin.fetching.load_full();
    let tls = fetching
        .tls
        .load_async()
        .await
        .map_err(|e| refused("sign-in-provider", e.to_string()))?;
    let answer = mcpdef_transport::post_form(
        &provider.token_endpoint,
        form,
        authorization,
        &fetching.egress,
        &tls,
    )
    .await
    .map_err(|e| refused("sign-in-provider", format!("the token endpoint: {e}")))?;
    if answer.status != 200 {
        let said: Value = serde_json::from_slice(&answer.body).unwrap_or_default();
        return Err(refused(
            "sign-in-provider",
            format!(
                "the token endpoint answered {}: {}",
                answer.status,
                said["error"].as_str().unwrap_or("(no error)")
            ),
        ));
    }
    let tokens: Tokens = serde_json::from_slice(&answer.body).map_err(|e| {
        refused(
            "sign-in-provider",
            format!("the token endpoint's answer: {e}"),
        )
    })?;
    let (_, mut claims) = signin
        .rotated(&provider, &provider.verifier, |v| {
            v.verify_id_token(&tokens.id_token, &started.nonce)
        })
        .await
        .map_err(|e| refused("sign-in-token", format!("its ID token: {e}")))?;
    if signin.oidc.userinfo {
        let endpoint = provider.userinfo_endpoint.as_deref().ok_or_else(|| {
            refused(
                "sign-in-userinfo",
                "the provider names no userinfo_endpoint",
            )
        })?;
        let token = tokens.access_token.as_deref().ok_or_else(|| {
            refused(
                "sign-in-userinfo",
                "the token endpoint sent no access token for userinfo",
            )
        })?;
        let answer = mcpdef_transport::get_bearer(endpoint, token, &fetching.egress, &tls)
            .await
            .map_err(|e| refused("sign-in-userinfo", format!("userinfo: {e}")))?;
        if answer.status != 200 {
            return Err(refused(
                "sign-in-userinfo",
                format!("userinfo answered {}", answer.status),
            ));
        }
        let more: Map<String, Value> = serde_json::from_slice(&answer.body)
            .map_err(|e| refused("sign-in-userinfo", format!("userinfo's answer: {e}")))?;
        // OpenID Connect Core §5.3.2: its `sub` is the ID token's, or it is
        // about someone else.
        if more.get("sub") != claims.get("sub") {
            return Err(refused(
                "sign-in-userinfo",
                "userinfo names another subject than the ID token",
            ));
        }
        for (name, value) in more {
            claims.entry(name).or_insert(value);
        }
    }
    let subject = signin
        .model
        .subject(&claims)
        .map_err(|why| refused("sign-in-token", format!("its claims: {why}")))?;
    // Only the console's roles are sealed in the session: it reads no other,
    // and a provider's groups can outgrow the 4 KB a browser keeps of a
    // cookie.
    let roles: Vec<String> = signin
        .model
        .roles(&claims)
        .into_iter()
        .filter(|role| ConsoleRole::parse(role).is_some())
        .collect();
    if roles.is_empty() {
        return Ok(Finished::NoRole(subject, claims));
    }
    let name = ["name", "preferred_username", "email"]
        .iter()
        .find_map(|claim| claims.get(*claim)?.as_str().map(str::to_string));
    let session = signin
        .sessions
        .begin(&provider.issuer, &subject, name, roles, now());
    Ok(Finished::Session(session, started.then))
}

/// `POST /logout`: the session signed out, and its cookie cleared:
/// `{ redirect }`, where the browser goes next: the provider's
/// `end_session_endpoint`, to sign out there too, when it has one.
async fn logout(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
) -> Response {
    let Some(signin) = s.signin.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "Not found",
            "this console signs no one in",
        );
    };
    let at = now();
    let ended =
        cookie(&headers, session::COOKIE).and_then(|sealed| signin.sessions.open(sealed, at).ok());
    if let Some(session) = &ended {
        signin.sessions.sign_out(session, at);
        let peer = caller.peer.to_string();
        s.gateway
            .audit_admin(
                &format!("user:{}", session.sub),
                &peer,
                "sign-out",
                "(console)",
                None,
                None,
            )
            .await;
    }
    let redirect = match signin
        .provider
        .load_full()
        .and_then(|p| p.end_session_endpoint.clone())
    {
        Some(endpoint) => match url::Url::parse(&endpoint) {
            Ok(mut url) => {
                url.query_pairs_mut()
                    .append_pair("client_id", &signin.oidc.client_id)
                    .append_pair(
                        "post_logout_redirect_uri",
                        &format!("{}/", signin.public_url),
                    );
                url.to_string()
            }
            Err(_) => "/".to_string(),
        },
        None => "/".to_string(),
    };
    let mut response = Json(serde_json::json!({ "redirect": redirect })).into_response();
    if let Ok(value) = session::cleared().parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sign_in_goes_back_to_this_console_alone() {
        for path in ["/", "/audit", "/servers/github?tab=tools#pins", "/a/b%2F/c"] {
            assert!(local_path(path), "{path}");
        }
        for path in [
            "",
            "audit",
            "//evil.example",
            "/\\evil.example",
            "\\/evil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "/ /evil.example",
            "https://evil.example/",
            "/caf\u{e9}",
        ] {
            assert!(!local_path(path), "{path:?}");
        }
    }

    #[test]
    fn a_reload_changes_how_the_sign_in_fetches() {
        let text = "[gateway.admin]\npublic_url = \"https://console.example\"\n\n\
                    [gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n\n\
                    [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n";
        let cfg = Config::parse(text).unwrap();
        let signin = SignIn::of(&cfg, Arc::new(Sessions::new(&[1; 32], None))).unwrap();
        assert_eq!(*signin.fetching.load_full(), Fetching::of(&cfg));
        let reloaded = Config::parse(&text.replacen(
            "[[server]]",
            "[gateway.upstream_tls]\nroots = \"system\"\n\n[[server]]",
            1,
        ))
        .unwrap();
        assert_ne!(Fetching::of(&reloaded), Fetching::of(&cfg));
        signin.reconfigure(&reloaded);
        assert_eq!(*signin.fetching.load_full(), Fetching::of(&reloaded));
    }

    #[test]
    fn so_many_refusals_a_minute_are_recorded_then_one_says_the_rest_are_not() {
        let cfg = Config::parse(
            "[gateway.admin]\npublic_url = \"https://console.example\"\n\n\
             [gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n",
        )
        .unwrap();
        let signin = SignIn::of(&cfg, Arc::new(Sessions::new(&[1; 32], None))).unwrap();
        let minute = 60 * 29_000_000;
        for n in 0..REFUSALS_RECORDED {
            let rule = signin.record_refusal("sign-in-state", minute + 1);
            assert_eq!(rule, Some("sign-in-state"), "refusal {n}");
        }
        assert_eq!(
            signin.record_refusal("sign-in-token", minute + 30),
            Some(REFUSALS_UNRECORDED)
        );
        assert_eq!(signin.record_refusal("sign-in-token", minute + 59), None);
        // The next minute, each is recorded again.
        assert_eq!(
            signin.record_refusal("sign-in-token", minute + 60),
            Some("sign-in-token")
        );
    }

    #[test]
    fn a_sign_in_finishes_once_and_the_remembered_are_bounded() {
        let cfg = Config::parse(
            "[gateway.admin]\npublic_url = \"https://console.example\"\n\n\
             [gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n",
        )
        .unwrap();
        let signin = SignIn::of(&cfg, Arc::new(Sessions::new(&[1; 32], None))).unwrap();
        assert_eq!(signin.redirect_uri, "https://console.example/callback");
        assert!(signin.first_finish("s1", 100, 10));
        assert!(!signin.first_finish("s1", 100, 50), "a replay");
        // Past its sign-in's end it is forgotten: the cookie refuses it then.
        assert!(signin.first_finish("s1", 200, 100));
        for n in 0..FINISHED_KEPT {
            assert!(signin.first_finish(&format!("n{n}"), 300, 150));
        }
        let finished = signin.finished.lock().unwrap();
        assert_eq!(finished.len(), FINISHED_KEPT);
        assert!(
            !finished.iter().any(|(state, _)| state == "s1"),
            "the oldest went first"
        );
    }

    mod properties {
        use super::*;
        use mcpdef_auth::{claim, IdentityModel, RoleMapping};
        use proptest::prelude::*;
        use serde_json::json;

        /// A cookie's name: the console's, ones that look like them, others.
        fn cookie_name() -> impl Strategy<Value = String> {
            prop_oneof![
                Just(session::COOKIE.to_string()),
                Just(LOGIN_COOKIE.to_string()),
                Just(format!("{}2", session::COOKIE)),
                Just(format!("x{}", session::COOKIE)),
                Just(session::COOKIE.to_ascii_lowercase()),
                "[A-Za-z_-]{1,12}",
            ]
        }

        /// A JSON value, nested a few levels.
        fn json_value() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<i64>().prop_map(|n| json!(n)),
                "[a-z:._-]{0,8}".prop_map(Value::String),
            ];
            leaf.prop_recursive(3, 24, 4, |inner| {
                prop_oneof![
                    proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                    proptest::collection::btree_map("[a-z.]{1,5}", inner, 0..4)
                        .prop_map(|m| Value::Object(m.into_iter().collect())),
                ]
            })
        }

        proptest! {
            /// The cookie read is the first whose name is exactly the one
            /// asked for: never one whose name holds it, nor one that differs
            /// from it in case.
            #[test]
            fn a_cookie_is_found_by_its_exact_name(
                pairs in proptest::collection::vec((cookie_name(), "[A-Za-z0-9._~+/=-]{0,24}"), 0..6),
                spaced in any::<bool>(),
            ) {
                let joined = pairs
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join(if spaced { "; " } else { ";" });
                let mut headers = HeaderMap::new();
                if !joined.is_empty() {
                    headers.insert(header::COOKIE, joined.parse().unwrap());
                }
                let first = pairs
                    .iter()
                    .find(|(name, _)| name == session::COOKIE)
                    .map(|(_, value)| value.as_str());
                prop_assert_eq!(cookie(&headers, session::COOKIE), first);
            }

            /// A page to come back to after signing in never leaves the
            /// console: wherever a browser takes it, against the console's
            /// origin, it stays there.
            #[test]
            fn a_page_to_come_back_to_stays_on_the_console(
                path in prop_oneof!["/[/\\\\a-z0-9.:@%?#&=~ \t\n-]{0,24}", "\\PC{0,24}"],
            ) {
                if local_path(&path) {
                    let console = url::Url::parse("https://console.example:7879/").unwrap();
                    let landed = console.join(&path).unwrap();
                    prop_assert_eq!(landed.origin(), console.origin(), "{:?}", path);
                }
            }

            /// A value put at a dotted path is found there; a claim named by
            /// the whole path, dots and all, comes first.
            #[test]
            fn a_value_at_a_dotted_path_is_found_there(
                segments in proptest::collection::vec("[a-z]{1,4}", 1..4),
                value in json_value(),
                noise in proptest::collection::btree_map("[a-z]{1,4}", json_value(), 0..4),
                literal in any::<bool>(),
            ) {
                let path = segments.join(".");
                let mut claims: Map<String, Value> = noise.into_iter().collect();
                let mut nested = value.clone();
                for segment in segments.iter().skip(1).rev() {
                    let mut level = Map::new();
                    level.insert(segment.clone(), nested);
                    nested = Value::Object(level);
                }
                claims.insert(segments[0].clone(), nested);
                let named = literal && segments.len() > 1;
                if named {
                    claims.insert(path.clone(), json!("the whole path"));
                }
                let expected = if named { json!("the whole path") } else { value };
                prop_assert_eq!(claim(&claims, &path), Some(&expected));
            }

            /// Any claims and any path are read without panic.
            #[test]
            fn any_claim_path_is_read(
                claims in proptest::collection::btree_map("[a-z.]{1,5}", json_value(), 0..5),
                path in "[a-z.]{0,12}",
            ) {
                let claims: Map<String, Value> = claims.into_iter().collect();
                let _ = claim(&claims, &path);
            }

            /// A mapping gives its roles exactly when its claim holds its
            /// value, as one string or among an array's, case and all; and
            /// each role is given once.
            #[test]
            fn a_mapping_gives_its_roles_when_the_claim_holds_its_value(
                held in proptest::collection::vec("[a-zA-Z-]{1,4}", 0..4),
                one in any::<bool>(),
                value in "[a-zA-Z-]{1,4}",
            ) {
                let model = IdentityModel {
                    subject_claim: "sub".into(),
                    roles_claims: vec!["roles".into()],
                    role_map: vec![RoleMapping {
                        claim: "groups".into(),
                        value: value.clone(),
                        roles: vec!["console:viewer".into(), "console:admin".into()],
                    }],
                };
                let groups = if one && held.len() == 1 { json!(held[0]) } else { json!(held) };
                let claims: Map<String, Value> = [
                    ("groups".to_string(), groups),
                    ("roles".to_string(), json!(["console:viewer"])),
                ]
                .into_iter()
                .collect();
                let roles = model.roles(&claims);
                prop_assert_eq!(roles.contains(&"console:admin".to_string()), held.contains(&value));
                let mut once = roles.clone();
                once.sort();
                once.dedup();
                prop_assert_eq!(once.len(), roles.len(), "{:?}", roles);
            }
        }
    }
}
