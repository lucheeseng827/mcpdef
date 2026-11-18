// SPDX-License-Identifier: Apache-2.0
//! Filter mode, `mcpdef filter`: MCPdef as the authorization service of a
//! proxy that routes MCP requests itself, as Envoy's `ext_authz` filter asks
//! an HTTP authorization service. The proxy keeps its routing; MCPdef keeps
//! the decisions and the record.
//!
//! The proxy sends each request it is about to route here first, with its
//! method, its path, its headers and its body. A `200` lets the request
//! through. Anything else stops it, and the proxy answers the client with
//! this answer: its status, its headers and its body.
//!
//! A check is judged in this order, and the first step that refuses answers:
//!
//! 1. **The path** the proxy routed, less the `path_prefix` it put before it,
//!    names the server: the `[[server]]` whose `filter_path` is the longest
//!    one the path is at or under. A path a proxy could read otherwise, by
//!    resolving `..`, merging `//` or decoding an escaped `/`, is refused.
//! 2. **The origin**, when the request carries one, as the gateway's
//!    listener checks it.
//! 3. **The credential**, when `[gateway.auth]` is on: a bearer token or a
//!    client key the gateway issued. A request without one gets the `401`
//!    the listener would send, with its challenge.
//! 4. **The message**: a `POST`'s body is one JSON-RPC message, and the
//!    gateway judges it as it would in the path ([`Gateway::authorize`]),
//!    recording what it decided. Other methods, such as the `GET` that opens a
//!    server's stream, pass once the steps above have.
//!
//! One `GET` is answered before all of them, for anyone: that of the
//! resource's metadata, where a `401`'s challenge sends a client to find the
//! authorization server. It passes as a check, and the proxy may route it
//! here, where it is answered with the document, as the listener serves it.
use crate::config::{normal_filter_path, path_is_ambiguous, Config};
use crate::gateway::{Authorization, Caller, Gateway};
use crate::listener::{authenticated, origin_allowed, traceparent, AuthState, MAX_BODY_BYTES};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use mcpdef_core::{Decision, Message};
use serde_json::{json, Value};
use std::cmp::Reverse;
use std::sync::Arc;

/// Who asked, as the records of filter mode's decisions name it (their
/// `hook`): the protocol of the proxy's checks.
pub const ASKER: &str = "ext_authz";

/// The JSON-RPC error code of a refusal: an implementation's own, as
/// JSON-RPC reserves -32000 to -32099 for, and the one other MCP gateways
/// give a denied request.
pub const DENIED_CODE: i64 = -32001;

/// Which server a request's path names: each `[[server]]` with a
/// `filter_path`, the longest path first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Routes {
    paths: Vec<(String, String)>,
}

impl Routes {
    /// The routes `cfg`'s servers give.
    pub fn of(cfg: &Config) -> Routes {
        let mut paths: Vec<(String, String)> = cfg
            .servers
            .iter()
            .filter_map(|s| Some((normal_filter_path(s.filter_path.as_deref()?), s.id.clone())))
            .collect();
        paths.sort_by_key(|(path, _)| Reverse(path.len()));
        Routes { paths }
    }

    /// Whether no server has a `filter_path`.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// How many servers have one.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// The server `path` names: the one with the longest `filter_path` that
    /// `path` is, or is under by whole segments. `/` takes any path.
    pub fn route(&self, path: &str) -> Option<&str> {
        self.paths
            .iter()
            .find(|(base, _)| under(path, base))
            .map(|(_, id)| id.as_str())
    }
}

/// Whether `path` is `base` or below it, by whole segments: `/github` takes
/// `/github/mcp` and not `/githubx`.
fn under(path: &str, base: &str) -> bool {
    base == "/"
        || path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `path`, as the proxy routed it, less the `prefix` the proxy put before it
/// in its check: `None` when it does not start with it, by whole segments.
fn unprefixed<'p>(path: &'p str, prefix: Option<&str>) -> Option<&'p str> {
    let Some(prefix) = prefix.map(normal_filter_path).filter(|p| p != "/") else {
        return Some(path);
    };
    match path.strip_prefix(prefix.as_str())? {
        "" => Some("/"),
        rest if rest.starts_with('/') => Some(rest),
        _ => None,
    }
}

/// What a filter needs to answer a check: the gateway that judges, the
/// routes, and what the listener checks before a message is read.
pub struct Filter {
    gw: Gateway,
    routes: Routes,
    prefix: Option<String>,
    auth: Option<AuthState>,
    allowed_origins: Vec<String>,
}

impl Filter {
    /// A filter for `cfg`, judging with `gw` and checking credentials as
    /// `auth` says.
    pub fn new(gw: Gateway, cfg: &Config, auth: Option<AuthState>) -> Filter {
        Filter {
            gw,
            routes: Routes::of(cfg),
            prefix: cfg.gateway.filter.path_prefix.clone(),
            auth,
            allowed_origins: cfg.gateway.allowed_origins.clone(),
        }
    }

    /// The resource's metadata, as the listener serves it, when a bearer
    /// token is taken and `path` is where a `401`'s challenge sends a client
    /// for it: in a check, after the `path_prefix`, or routed here by the
    /// proxy, without it.
    fn metadata(&self, path: &str) -> Option<Response> {
        let (at, document) = self.auth.as_ref()?.metadata()?;
        let asked = path == at || unprefixed(path, self.prefix.as_deref()) == Some(at);
        asked.then(|| {
            (
                [(header::CONTENT_TYPE, "application/json")],
                document.to_string(),
            )
                .into_response()
        })
    }
}

/// The service that answers `filter`'s checks: any method, any path.
pub fn router(filter: Filter) -> Router {
    Router::new()
        .fallback(check)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(Arc::new(filter))
}

/// Answer `filter`'s checks on `listener` until it fails.
pub async fn serve_filter_on(
    listener: tokio::net::TcpListener,
    filter: Filter,
) -> std::io::Result<()> {
    axum::serve(listener, router(filter)).await
}

/// One check: the request the proxy is about to route, as it sent it.
async fn check(
    State(filter): State<Arc<Filter>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The resource's metadata, for a client a `401` sent to find where it
    // gets a token, which has none yet.
    if method == Method::GET {
        if let Some(answer) = filter.metadata(uri.path()) {
            return answer;
        }
    }

    // 1. The path, and the server it names.
    let Some(path) = unprefixed(uri.path(), filter.prefix.as_deref()) else {
        let prefix = filter.prefix.as_deref().unwrap_or_default();
        return refused(
            None,
            "unknown-route",
            format!("the check's path does not start with the filter's path_prefix '{prefix}'"),
            None,
        );
    };
    if path_is_ambiguous(path) {
        return refused(
            None,
            "path-refused",
            "the request's path holds what a proxy may read otherwise: a `.` or `..` \
             segment, a `//`, a `\\`, or an escaped `/`, `\\` or `.`"
                .to_string(),
            None,
        );
    }
    let server = filter.routes.route(path);

    // 2. The origin, as the listener checks it: DNS-rebinding defense.
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !origin_allowed(origin, &filter.allowed_origins) {
        return refused(
            None,
            "origin-refused",
            format!("origin '{}' is not allowed", origin.unwrap_or_default()),
            None,
        );
    }

    // 3. The credential.
    let principal = match &filter.auth {
        Some(auth) => match authenticated(auth, &filter.gw, &headers, false).await {
            Ok(principal) => principal,
            Err(missing) => return auth.refusal(missing),
        },
        None => None,
    };

    // 4. The message.
    let unrouted = || {
        refused(
            None,
            "unknown-route",
            "the request's path is under no server's filter_path".to_string(),
            None,
        )
    };
    if method != Method::POST {
        return match server {
            Some(_) => allowed(None),
            None => unrouted(),
        };
    }
    let text = std::str::from_utf8(&body).unwrap_or_default().trim();
    if text.is_empty() {
        return refused(
            None,
            "invalid-request",
            "the check came with no body: have the proxy send the request's body with it \
             (Envoy's `with_request_body`)"
                .to_string(),
            None,
        );
    }
    let msg = match Message::from_json_line(text) {
        Ok(msg) => msg,
        Err(e) => {
            return refused(
                None,
                "invalid-request",
                format!("the body is not one JSON-RPC message: {e}"),
                None,
            )
        }
    };
    let caller = Caller {
        principal,
        certificate: None,
        // The check's peer is the proxy, not the client.
        peer: None,
        trace: traceparent(&headers),
    };
    match filter.gw.authorize(server, &msg, &caller, ASKER).await {
        Authorization::Unjudged if server.is_none() => unrouted(),
        Authorization::Unjudged => allowed(None),
        Authorization::Allowed { seq } => allowed(seq),
        Authorization::Denied {
            decision: Decision::Deny { rule, reason },
            seq,
        } => refused(msg.id.as_ref().map(|id| json!(id)), &rule, reason, seq),
        // `authorize` denies only with a deny.
        Authorization::Denied {
            decision: Decision::Allow,
            seq,
        } => allowed(seq),
    }
}

/// A `200`: the proxy lets the request through. It says so, and names the
/// record, for a proxy that hands its upstream the check's headers.
fn allowed(seq: Option<u64>) -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert("x-mcpdef-decision", HeaderValue::from_static("allow"));
    if let Some(seq) = seq {
        headers.insert("x-mcpdef-record", HeaderValue::from(seq));
    }
    response
}

/// A `403` with a JSON-RPC error the proxy hands the client: the request
/// `id`, when there is one, and why, by `rule`.
fn refused(id: Option<Value>, rule: &str, reason: String, seq: Option<u64>) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": DENIED_CODE,
            "message": format!("MCPdef denied ({rule}): {reason}"),
            "data": { "rule": rule },
        }
    });
    let mut response = (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert("x-mcpdef-decision", HeaderValue::from_static("deny"));
    if let Ok(rule) = HeaderValue::from_str(rule) {
        headers.insert("x-mcpdef-rule", rule);
    }
    if let Some(seq) = seq {
        headers.insert("x-mcpdef-record", HeaderValue::from(seq));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(paths: &[(&str, &str)]) -> Routes {
        let servers: String = paths
            .iter()
            .map(|(id, path)| {
                format!(
                    "[[server]]\nid = \"{id}\"\ntransport = \"streamable-http\"\n\
                     url = \"http://127.0.0.1:9/mcp\"\nfilter_path = \"{path}\"\n\n"
                )
            })
            .collect();
        Routes::of(&Config::parse(&format!("[gateway]\n\n{servers}")).unwrap())
    }

    #[test]
    fn a_path_names_the_server_whose_filter_path_it_is_under() {
        let routes = routes(&[("github", "/github"), ("files", "/files/")]);
        assert_eq!(routes.route("/github"), Some("github"));
        assert_eq!(routes.route("/github/mcp"), Some("github"));
        assert_eq!(routes.route("/files"), Some("files"));
        assert_eq!(routes.route("/files/mcp"), Some("files"));
        // By whole segments, not by characters.
        assert_eq!(routes.route("/githubx/mcp"), None);
        assert_eq!(routes.route("/"), None);
        assert_eq!(routes.route("/other"), None);
    }

    #[test]
    fn the_longest_filter_path_wins_and_the_root_takes_the_rest() {
        let routes = routes(&[("all", "/"), ("a", "/a"), ("ab", "/a/b")]);
        assert_eq!(routes.route("/a/b/mcp"), Some("ab"));
        assert_eq!(routes.route("/a/c"), Some("a"));
        assert_eq!(routes.route("/z"), Some("all"));
        assert_eq!(routes.len(), 3);
    }

    #[test]
    fn the_prefix_comes_off_by_whole_segments() {
        assert_eq!(
            unprefixed("/authz/github/mcp", Some("/authz")),
            Some("/github/mcp")
        );
        assert_eq!(unprefixed("/authz", Some("/authz/")), Some("/"));
        assert_eq!(unprefixed("/authzx/github", Some("/authz")), None);
        assert_eq!(unprefixed("/github", Some("/authz")), None);
        assert_eq!(unprefixed("/github", None), Some("/github"));
        assert_eq!(unprefixed("/github", Some("/")), Some("/github"));
    }

    #[test]
    fn a_path_a_proxy_could_read_otherwise_is_ambiguous() {
        for path in [
            "/github/../files",
            "/github/./mcp",
            "/github//mcp",
            "/github%2f..%2ffiles",
            "/github%2Fmcp",
            "/github\\mcp",
            "/github/%2e%2e/files",
            "/github/%5Cmcp",
            "//",
            "//github/mcp",
            "/github/.",
        ] {
            assert!(path_is_ambiguous(path), "{path}");
        }
        for path in ["/", "/github", "/github/", "/github/mcp", "/a-b_c/d.e"] {
            assert!(!path_is_ambiguous(path), "{path}");
        }
    }

    #[test]
    fn a_refusal_is_a_json_rpc_error_naming_its_rule() {
        let response = refused(
            Some(json!(7)),
            "not-on-allowlist",
            "no".to_string(),
            Some(3),
        );
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["x-mcpdef-decision"], "deny");
        assert_eq!(response.headers()["x-mcpdef-rule"], "not-on-allowlist");
        assert_eq!(response.headers()["x-mcpdef-record"], "3");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    }
}
