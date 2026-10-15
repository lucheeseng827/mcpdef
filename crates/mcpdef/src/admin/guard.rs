// SPDX-License-Identifier: Apache-2.0
//! What every request to the admin listener passes through, before any
//! route sees it, and what every answer carries.
//!
//! - **The Host it names** must be this listener's: an IP literal,
//!   `localhost`, the host `listen` or `public_url` names, or one of
//!   `[gateway.admin] hosts`. A page that rebinds its own name to this
//!   address names its own name, and is refused (DNS rebinding).
//! - **A request that changes something** (anything but GET, HEAD and
//!   OPTIONS) from a browser must come from the console's own origin:
//!   `Sec-Fetch-Site: same-origin`, or with no such header an `Origin` that
//!   is this listener's. A request with neither is not a browser's.
//! - **Who is calling** ([`Caller`]): a bearer token, where the admin API
//!   takes one (the break-glass token, or one the identity provider issued
//!   for the admin API); else the client certificate the listener asks for;
//!   else the console's session; else, when nothing signs callers in,
//!   whoever reaches it. A caller with no console role is refused every
//!   route that needs one.
//! - **Every answer** carries a content security policy and the headers that
//!   keep it out of frames and caches, and every refusal is an RFC 9457
//!   problem document.

use super::AdminState;
use crate::config::Config;
use crate::listener::{certified, Peer};
use crate::tls::TlsSlot;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use mcpdef_auth::same;
use mcpdef_policy::Rbac;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

/// What a console caller may do, each role holding the ones below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ConsoleRole {
    /// Reads every view but the redacted config and identity ones.
    #[serde(rename = "console:viewer")]
    Viewer,
    /// Also reloads the config, and restarts, tests and approves the drift
    /// of an upstream.
    #[serde(rename = "console:operator")]
    Operator,
    /// Also reads the redacted config and the identity views.
    #[serde(rename = "console:admin")]
    Admin,
}

impl ConsoleRole {
    /// Every role, lowest first.
    pub const ALL: [ConsoleRole; 3] = [
        ConsoleRole::Viewer,
        ConsoleRole::Operator,
        ConsoleRole::Admin,
    ];

    /// The role's name, as a role map names it.
    pub fn as_str(self) -> &'static str {
        match self {
            ConsoleRole::Viewer => "console:viewer",
            ConsoleRole::Operator => "console:operator",
            ConsoleRole::Admin => "console:admin",
        }
    }

    /// The role a name is, if it is one.
    pub fn parse(name: &str) -> Option<ConsoleRole> {
        ConsoleRole::ALL
            .into_iter()
            .find(|role| role.as_str() == name)
    }

    /// The highest console role among `names`, if any is one.
    pub fn highest<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<ConsoleRole> {
        names.into_iter().filter_map(ConsoleRole::parse).max()
    }
}

/// Who made a request to the admin listener, and the console role it holds.
#[derive(Clone, Debug)]
pub struct Caller {
    /// How the ledger names it: `local` (anyone on this machine, when
    /// nothing signs callers in), `anonymous` (anyone, behind a proxy that
    /// authenticates, with `allow_unauthenticated`, or anyone not signed in
    /// where the console signs people in), `cert:<identity>`,
    /// `user:<subject>` (a session's), `token:<subject>` (a bearer token the
    /// identity provider issued for the admin API) or `break-glass`.
    pub actor: String,
    /// The highest console role it holds. `None`: it may reach no route that
    /// needs one.
    pub role: Option<ConsoleRole>,
    /// Where it called from.
    pub peer: SocketAddr,
    /// Whether nothing signs callers in, so every caller holds
    /// `console:admin`: the console says so.
    pub open: bool,
    /// Whether it could sign in, at `/login`, and has not: what it may not
    /// reach is refused `401`, saying so, rather than `403`.
    pub sign_in: bool,
    /// Whether a session names it: it signs out at `/logout`.
    pub signed_in: bool,
    /// The name its session gives it, to greet it by.
    pub name: Option<String>,
}

impl Caller {
    /// The caller a session names: `user:<subject>`, with the highest
    /// console role its roles hold.
    pub(crate) fn of_session(session: &super::session::Session, peer: SocketAddr) -> Caller {
        Caller {
            actor: format!("user:{}", session.sub),
            role: ConsoleRole::highest(session.roles.iter().map(String::as_str)),
            peer,
            open: false,
            sign_in: false,
            signed_in: true,
            name: session.name.clone(),
        }
    }

    /// The caller a bearer token for the admin API names: `token:<subject>`,
    /// with the highest console role among `roles`.
    pub(crate) fn of_token(subject: &str, roles: &[String], peer: SocketAddr) -> Caller {
        Caller {
            actor: format!("token:{subject}"),
            role: ConsoleRole::highest(roles.iter().map(String::as_str)),
            peer,
            open: false,
            sign_in: false,
            signed_in: false,
            name: None,
        }
    }

    /// The caller the break-glass token names: `console:admin`.
    fn break_glass(peer: SocketAddr) -> Caller {
        Caller {
            actor: BREAK_GLASS.to_string(),
            role: Some(ConsoleRole::Admin),
            peer,
            open: false,
            sign_in: false,
            signed_in: false,
            name: None,
        }
    }

    /// A caller who could sign in and has not.
    fn signed_out(peer: SocketAddr) -> Caller {
        Caller {
            actor: "anonymous".to_string(),
            role: None,
            peer,
            open: false,
            sign_in: true,
            signed_in: false,
            name: None,
        }
    }

    /// Every role the caller holds, its highest and those below it.
    pub fn roles(&self) -> Vec<ConsoleRole> {
        ConsoleRole::ALL
            .into_iter()
            .filter(|role| self.role.is_some_and(|held| held >= *role))
            .collect()
    }
}

/// What the envelope checks against, from the config: replaced at each
/// reload, as the servers are.
#[derive(Default)]
pub struct Guard {
    /// Who a caller is when nothing signs callers in: `local` on a loopback
    /// listener, `anonymous` with `allow_unauthenticated`. `None` when the
    /// listener requires a client certificate.
    open: Option<&'static str>,
    /// `[[identity.cert_map]]`, matched as the MCP listener matches it.
    cert_map: Rbac,
    /// The host names a request may name, lowercased, besides IP literals
    /// and `localhost`.
    hosts: Vec<String>,
    /// The console's origin, from `public_url`, which an `Origin` may name
    /// besides the one its Host gives.
    origin: Option<String>,
    /// The break-glass token's SHA-256, when there is one.
    break_glass: Option<[u8; 32]>,
}

impl Guard {
    /// The guard `cfg` asks for.
    pub fn of(cfg: &Config) -> Guard {
        let admin = &cfg.gateway.admin;
        let open = match cfg.gateway.admin_signs_in() {
            true => None,
            false if admin.listens_locally() => Some("local"),
            false => Some("anonymous"),
        };
        let mut cert_map = Rbac::new();
        for entry in &cfg.identity.cert_map {
            cert_map.map_certificates(entry.identity.clone(), entry.roles.clone());
        }
        let mut hosts: Vec<String> = admin.hosts.iter().map(|h| normal_host(h)).collect();
        hosts.extend(listen_host(&admin.listen));
        let origin = admin.public_url.as_deref().and_then(origin_of);
        if let Some(url) = admin
            .public_url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
        {
            hosts.extend(url.host_str().map(normal_host));
        }
        Guard {
            open,
            cert_map,
            hosts,
            origin,
            break_glass: admin.break_glass.as_ref().and_then(|g| g.digest()),
        }
    }

    /// Whether `token` is the break-glass token: its digest compared in
    /// constant time.
    fn is_break_glass(&self, token: &str) -> bool {
        self.break_glass
            .is_some_and(|digest| same(&Sha256::digest(token.as_bytes()), &digest))
    }

    /// Whether a request naming `host` (a Host header's value, port and all)
    /// is meant for this listener.
    fn host_allowed(&self, host: &str) -> bool {
        let name = host_part(host);
        let name = normal_host(name);
        name == "localhost"
            || name
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok()
            || self.hosts.contains(&name)
    }

    /// The caller a request is, given the identity its client certificate
    /// gives, if it presented one.
    fn caller(&self, identity: Option<String>, peer: SocketAddr) -> Caller {
        match (self.open, identity) {
            // Nothing signs callers in: whoever reaches it may do anything,
            // and is named by the certificate it chose to present, if any.
            (Some(open), identity) => Caller {
                actor: identity.map_or_else(|| open.to_string(), |id| format!("cert:{id}")),
                role: Some(ConsoleRole::Admin),
                peer,
                open: true,
                sign_in: false,
                signed_in: false,
                name: None,
            },
            (None, Some(identity)) => {
                let role = ConsoleRole::highest(self.cert_map.certificate_roles(&identity));
                Caller {
                    actor: format!("cert:{identity}"),
                    role,
                    peer,
                    open: false,
                    sign_in: false,
                    signed_in: false,
                    name: None,
                }
            }
            // A listener that requires a certificate refuses one without at
            // the handshake; this is a certificate that named no identity.
            (None, None) => Caller {
                actor: "unknown".to_string(),
                role: None,
                peer,
                open: false,
                sign_in: false,
                signed_in: false,
                name: None,
            },
        }
    }
}

/// The host `listen` names, if it names one a request may use: not an
/// address that binds every interface.
fn listen_host(listen: &str) -> Option<String> {
    let host = host_part(listen);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => None,
        _ => Some(normal_host(host)),
    }
}

/// `host` of `host:port`, `[v6]` of `[v6]:port`, or the whole when it has no
/// port.
fn host_part(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .split_once(']')
            .map_or(host, |(v6, _)| &host[..v6.len() + 1]);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            name
        }
        _ => host,
    }
}

/// A host name as compared: lowercased, without a trailing dot.
fn normal_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The origin of a URL: `scheme://host[:port]`, the port left out when it
/// is the scheme's own.
fn origin_of(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    match url.origin() {
        url::Origin::Tuple(..) => Some(url.origin().ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// Whether a request that changes something comes from the console's own
/// origin, or from no browser at all. `host` is the Host it names, already
/// checked, and `scheme` the listener's.
fn same_origin(guard: &Guard, headers: &HeaderMap, host: &str, scheme: &str) -> bool {
    // A header sent, and not text a browser writes, is not taken for one not
    // sent: `None` when absent, `Some(None)` when unreadable.
    let value = |name: &str| headers.get(name).map(|v| v.to_str().ok());
    if let Some(site) = value("sec-fetch-site") {
        return matches!(site, Some("same-origin" | "none"));
    }
    let Some(origin) = value(header::ORIGIN.as_str()) else {
        // Neither header: not a browser, so not a page another site serves.
        return true;
    };
    // An origin as a browser writes it, or as the same origin reads (its
    // host in any case, its scheme's port written out).
    let Some(origin) = origin.and_then(origin_of) else {
        return false;
    };
    guard.origin.as_deref() == Some(origin.as_str())
        || origin.eq_ignore_ascii_case(&format!("{scheme}://{}", host.to_ascii_lowercase()))
        || origin.eq_ignore_ascii_case(&format!("{scheme}://{}", default_port(host, scheme)))
}

/// Whether a request's body, if it says what it is, is JSON.
fn json_or_nothing(headers: &HeaderMap) -> bool {
    let Some(kind) = headers.get(header::CONTENT_TYPE) else {
        return true;
    };
    kind.to_str()
        .ok()
        .and_then(|kind| kind.split(';').next())
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
}

/// `host` without the port its scheme defaults to, as an origin writes it.
fn default_port<'a>(host: &'a str, scheme: &str) -> &'a str {
    let port = match scheme {
        "https" => ":443",
        _ => ":80",
    };
    host.strip_suffix(port).unwrap_or(host)
}

/// A refusal, as an RFC 9457 problem document.
pub fn problem(status: StatusCode, title: &str, detail: impl Into<String>) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail.into(),
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
}

/// The content security policy every answer carries: the console's own
/// scripts, styles, fonts and API, and nothing from anywhere else, in no
/// frame.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
     base-uri 'none'; frame-ancestors 'none'";

/// What the envelope needs besides the admin state: the listener's TLS slot,
/// when it serves TLS.
#[derive(Clone)]
pub(crate) struct Envelope {
    pub state: Arc<AdminState>,
    pub tls: Option<TlsSlot>,
}

/// Every request's envelope: its Host, its origin when it changes
/// something, and who it is; then the answer's headers.
pub(crate) async fn envelope(
    State(envelope): State<Envelope>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    mut request: Request,
    next: Next,
) -> Response {
    let guard = envelope.state.guard.load_full();
    let host = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        });
    let Some(host) = host else {
        return secured(problem(
            StatusCode::BAD_REQUEST,
            "No host",
            "the request names no host",
        ));
    };
    if !guard.host_allowed(&host) {
        return secured(problem(
            StatusCode::MISDIRECTED_REQUEST,
            "Not this listener's host",
            format!(
                "{host} is not a name this admin listener answers to: add it to \
                 [gateway.admin] hosts, or name it in public_url"
            ),
        ));
    }
    let scheme = match envelope.tls {
        Some(_) => "https",
        None => "http",
    };
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if !safe && !same_origin(&guard, request.headers(), &host, scheme) {
        return secured(problem(
            StatusCode::FORBIDDEN,
            "Cross-origin request refused",
            "a request that changes something must come from the console's own origin",
        ));
    }
    // A form a page posts, from whatever origin an old browser says, is no
    // JSON: what changes something sends JSON, or nothing.
    if !safe && !json_or_nothing(request.headers()) {
        return secured(problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Not JSON",
            "a request that changes something sends application/json, or no body",
        ));
    }
    let identity = match certified(
        envelope.tls.as_ref(),
        &peer,
        request.headers(),
        SystemTime::now(),
    ) {
        Ok(identity) => identity,
        Err(why) => {
            return secured(problem(
                StatusCode::FORBIDDEN,
                "Client certificate refused",
                why,
            ))
        }
    };
    // A bearer token, where the admin API takes one, names the caller
    // whatever else the request carries: the break-glass token, or one the
    // identity provider issued for the admin API. Each request the
    // break-glass token makes is recorded before it is served.
    let signin = envelope.state.signin.as_ref();
    let takes_tokens = guard.break_glass.is_some() || signin.is_some_and(|s| s.takes_api_tokens());
    if let Some(token) = bearer(request.headers()).filter(|_| takes_tokens) {
        let caller = if guard.is_break_glass(&token) {
            let asked = format!("{} {}", request.method(), request.uri().path());
            envelope
                .state
                .gateway
                .audit_break_glass(&peer.addr().to_string(), &asked)
                .await;
            Caller::break_glass(peer.addr())
        } else {
            let Some(signin) = signin.filter(|s| s.takes_api_tokens()) else {
                return secured(bearer_refused(
                    "it is not the break-glass token, and this admin API takes no other",
                ));
            };
            match signin.api_caller(&token).await {
                Ok((subject, roles)) => Caller::of_token(&subject, &roles, peer.addr()),
                Err(super::signin::ApiRefused::Unavailable(why)) => {
                    return secured(problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Identity provider unavailable",
                        format!("no token of its can be verified now: {why}"),
                    ))
                }
                Err(super::signin::ApiRefused::Invalid(why)) => {
                    return secured(bearer_refused(&why))
                }
            }
        };
        request.extensions_mut().insert(caller);
        return secured(next.run(request).await);
    }
    // With no certificate, where the console signs people in, its session
    // cookie names the caller, and is sealed again as it is used.
    let mut renewed = None;
    let caller = match (identity, &envelope.state.signin) {
        (None, Some(signin)) => {
            let at = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            match super::signin::cookie(request.headers(), super::session::COOKIE)
                .map(|sealed| signin.sessions.open(sealed, at))
            {
                Some(Ok(session)) => {
                    renewed = signin
                        .sessions
                        .renewed(&session, at)
                        .map(|(fresh, sealed)| super::session::cookie(&sealed, &fresh, at));
                    Caller::of_session(&session, peer.addr())
                }
                _ => Caller::signed_out(peer.addr()),
            }
        }
        (identity, _) => guard.caller(identity, peer.addr()),
    };
    request.extensions_mut().insert(caller);
    let mut response = next.run(request).await;
    if let Some(value) = renewed.and_then(|value| HeaderValue::from_str(&value).ok()) {
        if renewal_rides(response.headers()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    secured(response)
}

/// Whether the session cookie, sealed again, goes out with an answer that
/// has `headers`. Not when the route set that cookie itself: signing out
/// clears it and signing in sets another, and a browser keeps the last one
/// set. Nor on an answer a shared cache may keep and hand to someone else:
/// one whose `Cache-Control` says neither `no-store` nor `private` (one with
/// none goes out `no-store`, [`secured`]).
fn renewal_rides(headers: &HeaderMap) -> bool {
    let named = format!("{}=", super::session::COOKIE);
    let set_here = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&named));
    let caching: Vec<&HeaderValue> = headers.get_all(header::CACHE_CONTROL).iter().collect();
    let browser_only = caching.is_empty()
        || caching.iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value.split(',').map(str::trim).any(|directive| {
                    directive.eq_ignore_ascii_case("no-store")
                        || directive.eq_ignore_ascii_case("private")
                })
            })
        });
    !set_here && browser_only
}

/// How the ledger names the caller the break-glass token names.
pub const BREAK_GLASS: &str = "break-glass";

/// The bearer token a request's `Authorization` header carries, if it
/// carries one.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_string())
}

/// The refusal of a bearer token: `401`, saying why, as RFC 6750 has it.
fn bearer_refused(why: &str) -> Response {
    let mut response = problem(
        StatusCode::UNAUTHORIZED,
        "Bearer token refused",
        format!("the bearer token is refused: {why}"),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

/// `response`, with the headers every answer of the admin listener carries.
fn secured(mut response: Response) -> Response {
    let headers = response.headers_mut();
    let mut set = |name: &'static str, value: &'static str| {
        headers
            .entry(name)
            .or_insert_with(|| HeaderValue::from_static(value));
    };
    set("content-security-policy", CONTENT_SECURITY_POLICY);
    set("x-content-type-options", "nosniff");
    set("x-frame-options", "DENY");
    set("referrer-policy", "no-referrer");
    set("cross-origin-opener-policy", "same-origin");
    set("cross-origin-resource-policy", "same-origin");
    set("cache-control", "no-store");
    response
}

/// A route that needs `need`: refused `403` to a caller that holds less.
async fn gate(need: ConsoleRole, caller: &Caller, request: Request, next: Next) -> Response {
    if caller.role.is_some_and(|held| held >= need) {
        return next.run(request).await;
    }
    if caller.sign_in {
        return signed_out();
    }
    let detail = match caller.role {
        None => format!(
            "{} holds no console role: give it one of console:viewer, console:operator or \
             console:admin",
            caller.actor
        ),
        Some(held) => format!(
            "{} holds {}, and this needs {}",
            caller.actor,
            held.as_str(),
            need.as_str()
        ),
    };
    problem(StatusCode::FORBIDDEN, "Forbidden", detail)
}

/// The refusal of a caller who has not signed in: `401`, saying where to.
pub(crate) fn signed_out() -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "Not signed in",
        "sign in to the console first, at /login",
    )
}

/// A route a viewer may reach.
pub async fn viewer(
    Extension(caller): Extension<Caller>,
    request: Request,
    next: Next,
) -> Response {
    gate(ConsoleRole::Viewer, &caller, request, next).await
}

/// A route an operator may reach.
pub async fn operator(
    Extension(caller): Extension<Caller>,
    request: Request,
    next: Next,
) -> Response {
    gate(ConsoleRole::Operator, &caller, request, next).await
}

/// A route an admin may reach.
pub async fn admin(Extension(caller): Extension<Caller>, request: Request, next: Next) -> Response {
    gate(ConsoleRole::Admin, &caller, request, next).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(hosts: &[&str], public_url: Option<&str>) -> Guard {
        Guard {
            open: Some("local"),
            cert_map: Rbac::new(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            origin: public_url.and_then(origin_of),
            break_glass: None,
        }
    }

    #[test]
    fn a_bearer_token_is_read_as_rfc_6750_writes_it_and_break_glass_by_its_digest() {
        let headers = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            headers
        };
        assert_eq!(bearer(&headers("Bearer abc")).as_deref(), Some("abc"));
        assert_eq!(bearer(&headers("bearer  abc ")).as_deref(), Some("abc"));
        for not in ["Basic YWJj", "Bearer", "Bearer ", "Bearerabc"] {
            assert_eq!(bearer(&headers(not)), None, "{not:?}");
        }
        assert_eq!(bearer(&HeaderMap::new()), None);
        let token = "mcpdef_bg_secret";
        let glass = Guard {
            break_glass: Some(Sha256::digest(token.as_bytes()).into()),
            ..guard(&[], None)
        };
        assert!(glass.is_break_glass(token));
        assert!(!glass.is_break_glass("mcpdef_bg_secreT"));
        assert!(!glass.is_break_glass(""));
        assert!(!guard(&[], None).is_break_glass(token), "none is set");
    }

    #[test]
    fn a_host_is_an_ip_literal_localhost_or_a_name_it_was_given() {
        let g = guard(&["mcpdef.internal"], None);
        for host in [
            "127.0.0.1:7879",
            "10.1.2.3:7879",
            "[::1]:7879",
            "[fe80::1]",
            "localhost:7879",
            "LOCALHOST",
            "mcpdef.internal:7879",
            "MCPdef.Internal.",
        ] {
            assert!(g.host_allowed(host), "{host}");
        }
        for host in [
            "evil.example:7879",
            "mcpdef.internal.evil.example",
            "localhost.evil",
            "",
        ] {
            assert!(!g.host_allowed(host), "{host}");
        }
    }

    #[test]
    fn the_listen_and_public_url_hosts_are_allowed_but_not_an_unspecified_address() {
        assert_eq!(listen_host("console.lan:7879"), Some("console.lan".into()));
        assert_eq!(listen_host("0.0.0.0:7879"), None);
        assert_eq!(listen_host("[::]:7879"), None);
        assert_eq!(
            origin_of("https://Console.Lan:8443/x"),
            Some("https://console.lan:8443".into())
        );
        assert_eq!(
            origin_of("https://console.lan:443/"),
            Some("https://console.lan".into())
        );
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn an_origin_is_compared_as_an_origin_and_one_unreadable_is_refused() {
        let g = guard(&[], Some("https://console.lan"));
        let host = "127.0.0.1:7879";
        for same in [
            "https://console.lan",
            "https://CONSOLE.LAN",
            "https://console.lan:443",
        ] {
            assert!(
                same_origin(&g, &headers(&[("origin", same)]), host, "http"),
                "{same}"
            );
        }
        // Sent, and not text: not taken for a header not sent.
        let unreadable = |name: &'static str| {
            let mut map = HeaderMap::new();
            map.insert(
                name,
                HeaderValue::from_bytes(b"https://console.lan\xe0").unwrap(),
            );
            map
        };
        assert!(!same_origin(&g, &unreadable("origin"), host, "http"));
        assert!(!same_origin(
            &g,
            &unreadable("sec-fetch-site"),
            host,
            "http"
        ));
    }

    #[test]
    fn a_change_must_come_from_the_consoles_own_origin_or_no_browser() {
        let g = guard(&[], Some("https://console.lan"));
        let host = "127.0.0.1:7879";
        // No browser headers at all: curl, a script.
        assert!(same_origin(&g, &headers(&[]), host, "http"));
        assert!(same_origin(
            &g,
            &headers(&[("sec-fetch-site", "same-origin")]),
            host,
            "http"
        ));
        assert!(!same_origin(
            &g,
            &headers(&[("sec-fetch-site", "cross-site")]),
            host,
            "http"
        ));
        assert!(!same_origin(
            &g,
            &headers(&[("sec-fetch-site", "same-site")]),
            host,
            "http"
        ));
        // Sec-Fetch-Site decides when it is there, whatever Origin says.
        assert!(!same_origin(
            &g,
            &headers(&[
                ("sec-fetch-site", "cross-site"),
                ("origin", "http://127.0.0.1:7879")
            ]),
            host,
            "http"
        ));
        // No Sec-Fetch-Site: an older browser's Origin.
        assert!(same_origin(
            &g,
            &headers(&[("origin", "http://127.0.0.1:7879")]),
            host,
            "http"
        ));
        assert!(same_origin(
            &g,
            &headers(&[("origin", "https://console.lan")]),
            host,
            "http"
        ));
        assert!(!same_origin(
            &g,
            &headers(&[("origin", "https://127.0.0.1:7879")]),
            host,
            "http"
        ));
        assert!(!same_origin(
            &g,
            &headers(&[("origin", "http://evil.example")]),
            host,
            "http"
        ));
        assert!(!same_origin(
            &g,
            &headers(&[("origin", "null")]),
            host,
            "http"
        ));
        // A default port, written or not.
        assert!(same_origin(
            &g,
            &headers(&[("origin", "https://console.lan")]),
            "console.lan:443",
            "https"
        ));
    }

    #[test]
    fn what_changes_something_sends_json_or_nothing() {
        assert!(json_or_nothing(&headers(&[])));
        assert!(json_or_nothing(&headers(&[(
            "content-type",
            "application/json"
        )])));
        assert!(json_or_nothing(&headers(&[(
            "content-type",
            "Application/JSON; charset=utf-8"
        )])));
        for form in [
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "text/plain",
            "application/json-patch+json",
        ] {
            assert!(
                !json_or_nothing(&headers(&[("content-type", form)])),
                "{form}"
            );
        }
    }

    #[test]
    fn an_open_listener_gives_every_caller_admin_and_a_closed_one_what_its_certificate_maps_to() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let open = guard(&[], None);
        let local = open.caller(None, peer);
        assert_eq!(
            (local.actor.as_str(), local.role),
            ("local", Some(ConsoleRole::Admin))
        );
        let named = open.caller(Some("spiffe://x/bot".into()), peer);
        assert_eq!(named.actor, "cert:spiffe://x/bot");
        assert!(named.open);

        let mut cert_map = Rbac::new();
        cert_map.map_certificates("spiffe://x/ops/*", vec!["console:operator".into()]);
        cert_map.map_certificates(
            "spiffe://x/ops/lead",
            vec!["console:admin".into(), "ci".into()],
        );
        cert_map.map_certificates("spiffe://x/bot", vec!["ci".into()]);
        let closed = Guard {
            open: None,
            cert_map,
            ..Guard::default()
        };
        let role = |id: &str| closed.caller(Some(id.into()), peer).role;
        assert_eq!(role("spiffe://x/ops/alice"), Some(ConsoleRole::Operator));
        assert_eq!(role("spiffe://x/ops/lead"), Some(ConsoleRole::Admin));
        assert_eq!(role("spiffe://x/bot"), None);
        assert_eq!(role("spiffe://x/stranger"), None);
        assert_eq!(closed.caller(None, peer).role, None);
    }

    #[test]
    fn a_role_holds_the_ones_below_it() {
        let caller = |role| Caller {
            actor: "x".into(),
            role,
            peer: "127.0.0.1:1".parse().unwrap(),
            open: false,
            sign_in: false,
            signed_in: false,
            name: None,
        };
        assert_eq!(
            caller(Some(ConsoleRole::Operator)).roles(),
            [ConsoleRole::Viewer, ConsoleRole::Operator]
        );
        assert!(caller(None).roles().is_empty());
        assert_eq!(
            ConsoleRole::highest(["ci", "console:viewer", "console:admin"]),
            Some(ConsoleRole::Admin)
        );
        assert_eq!(ConsoleRole::highest(["console:root"]), None);
    }

    #[test]
    fn a_renewed_session_rides_no_answer_a_route_set_it_on_or_a_cache_keeps() {
        let rides = |pairs: &[(&'static str, &str)]| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.append(*name, HeaderValue::from_str(value).unwrap());
            }
            renewal_rides(&headers)
        };
        assert!(rides(&[]));
        assert!(rides(&[("cache-control", "no-store")]));
        assert!(rides(&[("cache-control", "private, max-age=60")]));
        assert!(rides(&[("cache-control", "max-age=0, No-Store")]));
        assert!(rides(&[("set-cookie", "__Host-mcpdef-login=; Max-Age=0")]));
        // Signed out, or in again: the route's cookie is the last one set.
        assert!(!rides(&[(
            "set-cookie",
            "__Host-mcpdef-session=; Path=/; Max-Age=0"
        )]));
        assert!(!rides(&[
            ("set-cookie", "__Host-mcpdef-login=; Max-Age=0"),
            ("set-cookie", "__Host-mcpdef-session=sealed; Max-Age=28800"),
        ]));
        // A file a shared cache may keep.
        assert!(!rides(&[(
            "cache-control",
            "public, max-age=31536000, immutable"
        )]));
        assert!(!rides(&[("cache-control", "no-cache")]));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// A DNS name: one to three labels of letters, digits and hyphens.
        fn name() -> impl Strategy<Value = String> {
            proptest::collection::vec("[a-z0-9][a-z0-9-]{0,8}", 1..4)
                .prop_map(|labels| labels.join("."))
        }

        proptest! {
            /// A name is let in when it is `localhost` or one the listener was
            /// given, whatever its case, its port or a trailing dot; no other
            /// name is.
            #[test]
            fn a_name_is_let_in_only_when_it_is_one_given(
                name in prop_oneof![Just("mcpdef.internal".to_string()), Just("localhost".to_string()), name()],
                port in proptest::option::of(any::<u16>()),
                upper in any::<bool>(),
                dot in any::<bool>(),
            ) {
                let g = guard(&["mcpdef.internal"], None);
                let mut host = if upper { name.to_ascii_uppercase() } else { name.clone() };
                if dot {
                    host.push('.');
                }
                if let Some(port) = port {
                    host = format!("{host}:{port}");
                }
                let given = name == "mcpdef.internal" || name == "localhost";
                prop_assert_eq!(g.host_allowed(&host), given, "{}", host);
            }

            /// A given name inside another, as its subdomain, its parent, or
            /// beside an `@` or a `:`, is not that name.
            #[test]
            fn a_given_name_inside_another_is_not_it(other in name()) {
                let g = guard(&["mcpdef.internal"], None);
                for host in [
                    format!("mcpdef.internal.{other}"),
                    format!("{other}.mcpdef.internal"),
                    format!("{other}@mcpdef.internal"),
                    format!("mcpdef.internal@{other}"),
                    format!("{other}:mcpdef.internal"),
                    format!("localhost.{other}"),
                ] {
                    prop_assert!(!g.host_allowed(&host), "{}", host);
                }
            }

            /// Whatever a Host header holds, the check answers.
            #[test]
            fn any_host_is_judged(host in "\\PC{0,64}") {
                let _ = guard(&["mcpdef.internal"], None).host_allowed(&host);
            }

            /// A browser's change passes from the listener's own origin or
            /// `public_url`'s, exactly, and from no other: another scheme,
            /// host or port is another origin.
            #[test]
            fn only_the_consoles_own_origin_may_change_something(
                scheme in prop_oneof![Just("http"), Just("https")],
                host in prop_oneof![
                    Just("127.0.0.1"),
                    Just("console.lan"),
                    Just("CONSOLE.LAN"),
                    Just("console.lan.evil.example"),
                    Just("evil.example"),
                ],
                port in prop_oneof![Just(None), Just(Some(7879u16)), Just(Some(443)), Just(Some(8443))],
            ) {
                let g = guard(&[], Some("https://console.lan"));
                let origin = match port {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                };
                let mut sent = HeaderMap::new();
                sent.insert(header::ORIGIN, origin.parse().unwrap());
                let console = host.eq_ignore_ascii_case("console.lan");
                let own = (scheme == "http" && host == "127.0.0.1" && port == Some(7879))
                    || (scheme == "https" && console && matches!(port, None | Some(443)));
                prop_assert_eq!(same_origin(&g, &sent, "127.0.0.1:7879", "http"), own, "{}", origin);
            }

            /// Where a browser says how the request stands to the page's
            /// origin, that decides, whatever `Origin` says: only
            /// `same-origin`, or `none` (an address typed in), may change
            /// something.
            #[test]
            fn sec_fetch_site_decides_where_it_is_sent(site in "[a-z-]{0,16}", origin in "\\PC{0,40}") {
                let g = guard(&[], Some("https://console.lan"));
                let mut sent = HeaderMap::new();
                sent.insert("sec-fetch-site", site.parse().unwrap());
                if let Ok(origin) = origin.parse() {
                    sent.insert(header::ORIGIN, origin);
                }
                prop_assert_eq!(
                    same_origin(&g, &sent, "127.0.0.1:7879", "http"),
                    site == "same-origin" || site == "none"
                );
            }

            /// Any `Origin` is judged, and passes only when it is the
            /// listener's or `public_url`'s.
            #[test]
            fn any_origin_is_judged(origin in "\\PC{0,64}") {
                let g = guard(&[], Some("https://console.lan"));
                let Ok(value) = origin.parse() else {
                    return Ok(());
                };
                let mut sent = HeaderMap::new();
                sent.insert(header::ORIGIN, value);
                if same_origin(&g, &sent, "127.0.0.1:7879", "http") {
                    let seen = origin_of(&origin).unwrap_or_default();
                    prop_assert!(
                        seen == "https://console.lan" || seen.eq_ignore_ascii_case("http://127.0.0.1:7879"),
                        "{}",
                        origin
                    );
                }
            }
        }
    }
}
