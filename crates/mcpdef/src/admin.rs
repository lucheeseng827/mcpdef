// SPDX-License-Identifier: Apache-2.0
//! The admin listener: the console, its JSON API, and Prometheus `/metrics`,
//! on a **separate** port from the MCP data path.
//!
//! It never touches the MCP wire: it reads the shared [`Metrics`] registry,
//! the configured servers with each one's live health, and the audit ledger
//! file. Every request passes [`guard::envelope`] first, which checks its
//! Host and, when it changes something, its origin, and names its caller;
//! each route then asks for the console role it needs. Like the ledger, it
//! shows what the gateway saw, never a secret.

mod actions;
mod audit;
#[cfg(feature = "console")]
mod console;
pub mod guard;
pub mod session;
mod signin;
mod state;
mod views;

pub use self::guard::{problem, Caller, ConsoleRole, Guard, CONTENT_SECURITY_POLICY};

use crate::config::Config;
use crate::gateway::{
    CredentialStatus, Gateway, HealthState, LastError, TlsStatus, ToolCollision, ToolCost,
    UpstreamStatus,
};
use crate::listener::Peer;
use crate::metrics::{render_upstreams, Metrics};
use crate::redact::redact_url;
use crate::reload::{Outcome, Reloads};
use crate::tls::{TlsListener, TlsSlot};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// The built-in status page (vanilla JS, no build step), which a build without
/// the console serves: its page, styles and script, each served on its own,
/// as the content security policy wants.
#[cfg(not(feature = "console"))]
const UI_HTML: &str = include_str!("admin_ui.html");
#[cfg(not(feature = "console"))]
const UI_CSS: &str = include_str!("admin_ui.css");
#[cfg(not(feature = "console"))]
const UI_JS: &str = include_str!("admin_ui.js");

/// The most a request to the admin listener may send: a config to validate,
/// at most, and well under the MCP listener's.
const BODY_LIMIT: usize = 1024 * 1024;

/// A configured upstream, as shown by `/api/v1/servers` and the UI. The effective
/// (profile-applied) allowlist/deny, not the raw `[[server]]` block.
#[derive(Clone, Serialize)]
pub struct ServerView {
    pub id: String,
    pub transport: String,
    /// Its URL, with any secret it holds masked as `***`.
    pub url: Option<String>,
    /// Effective allowlist (`None` = allow-all was not set; deny still applies).
    pub tools: Option<Vec<String>>,
    pub deny: Vec<String>,
    pub profile: Option<String>,
    /// Which resource URIs, resource templates and prompts it exposes
    /// (`resources`, `resource_templates`, `prompts`); absent where it
    /// exposes none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_templates: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Vec<String>>,
    /// Where each variable its `[server.env]` sets comes from, by name, never
    /// its value: `{ scheme, from }`, where `scheme` is `literal`, `env`, `file`
    /// or `exec`, and `from` is `(literal)`, `$NAME`, the file's path or
    /// `(exec PROGRAM)`. Built as JSON, which costs the binary half what a
    /// struct of its own does.
    pub env: serde_json::Map<String, serde_json::Value>,
    /// How it proves itself to the upstream (`[server.auth]`), if it does:
    /// `{ kind, name, token_url, <field>: { scheme, from } }`, the header's
    /// name for `kind = "header"` alone, the token endpoint for
    /// `kind = "oauth2"` alone, masked as `url` is, and never the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,
}

/// A configured upstream with its live health, as `/api/v1/servers` shows it.
#[derive(Serialize)]
struct ServerReport<'a> {
    #[serde(flatten)]
    view: &'a ServerView,
    health: HealthState,
    /// Times it was started again after going down.
    restarts: u64,
    last_error: Option<LastError>,
    /// How the credentials MCPdef sends it fare, for a server with
    /// `[server.auth]`. Absent for any other.
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<&'a CredentialStatus>,
    /// An HTTPS upstream's certificate, once it has opened. Absent for any
    /// other.
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<&'a TlsStatus>,
    /// The tool names it offers that another server offers too, each with
    /// every server that does: the first is the one listed and called.
    /// Absent when there are none.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    tool_collisions: &'a [ToolCollision],
    /// What it adds to `tools/list`: `{ offered, listed, bytes }`, the tools
    /// its connection lists, how many of them are listed, and the bytes those
    /// take up there. What every agent that lists the tools reads into its
    /// context.
    #[serde(skip_serializing_if = "Option::is_none")]
    listing: Option<&'a ToolCost>,
}

/// The configured servers as `/api/v1/servers` shows them: each one's
/// effective allowlist and denies, with its profile applied.
pub fn server_views(cfg: &Config) -> Vec<ServerView> {
    cfg.servers
        .iter()
        .map(|s| {
            let sp = cfg.resolve_server(s);
            ServerView {
                id: s.id.clone(),
                transport: s.transport.clone(),
                url: s.url.as_deref().map(|url| redact_url(url).into_owned()),
                tools: sp.allow_tools,
                deny: sp.deny,
                profile: s.profile.clone(),
                resources: s.resources.clone(),
                resource_templates: s.resource_templates.clone(),
                prompts: s.prompts.clone(),
                env: s
                    .env
                    .iter()
                    .map(|(name, value)| {
                        let from = serde_json::json!({
                            "scheme": value.scheme(),
                            "from": value.to_string(),
                        });
                        (name.clone(), from)
                    })
                    .collect(),
                auth: s.auth.as_ref().map(|auth| {
                    let mut view = serde_json::json!({ "kind": auth.kind.as_str() });
                    if let Some(name) = &auth.name {
                        view["name"] = name.clone().into();
                    }
                    if let Some(url) = &auth.token_url {
                        view["token_url"] = redact_url(url).into();
                    }
                    if let Some((field, secret)) = auth.secret() {
                        view[field] = serde_json::json!({
                            "scheme": secret.scheme(),
                            "from": secret.to_string(),
                        });
                    }
                    view
                }),
            }
        })
        .collect()
}

/// Everything the admin server reads: the configured servers and what the
/// envelope checks requests against, each replaced by every reload, and the
/// live parts, which are the shared [`Metrics`] registry and the gateway's
/// view of its upstreams.
pub struct AdminState {
    pub metrics: Arc<Metrics>,
    pub servers: ArcSwap<Vec<ServerView>>,
    pub guard: ArcSwap<Guard>,
    pub gateway: Gateway,
    pub audit_path: String,
    pub version: &'static str,
    /// Asks the running reloader for a reload, when one takes requests.
    pub reloads: Option<Reloads>,
    /// What the audit API keeps between requests.
    pub(crate) reads: audit::Reads,
    /// What the state API shows of the config, replaced by every reload.
    pub(crate) views: ArcSwap<state::Views>,
    /// Where `mcpdef run` serves: the MCP listener's address (`None` for
    /// stdio) and the admin listener's, once it has said.
    pub(crate) listening: Option<(Option<SocketAddr>, Option<SocketAddr>)>,
    /// The config in effect, replaced by every reload, for the views that
    /// read it when asked.
    pub(crate) config: ArcSwap<Config>,
    /// The file the gateway was started from, which `/api/v1/config` shows.
    pub(crate) config_path: Option<PathBuf>,
    /// How the console signs people in, when `[gateway.admin.oidc]` says.
    pub(crate) signin: Option<Arc<signin::SignIn>>,
}

impl AdminState {
    /// The admin state for `cfg`'s gateway `gateway`, counting into
    /// `metrics`, saying it is `version`.
    pub fn new(
        cfg: &Config,
        metrics: Arc<Metrics>,
        gateway: Gateway,
        version: &'static str,
    ) -> AdminState {
        AdminState {
            metrics,
            servers: ArcSwap::from_pointee(server_views(cfg)),
            guard: ArcSwap::from_pointee(Guard::of(cfg)),
            gateway,
            audit_path: cfg.gateway.audit.clone(),
            version,
            reloads: None,
            reads: audit::Reads::default(),
            views: ArcSwap::from_pointee(state::Views::of(cfg)),
            listening: None,
            config: ArcSwap::from_pointee(cfg.clone()),
            config_path: None,
            signin: None,
        }
    }

    /// Sign people in to the console as `[gateway.admin.oidc]` says, sealing
    /// their sessions with `sessions`: `None` without that table. The
    /// identity provider is looked for now, in the background; a failure is
    /// said, and it is looked for again at the next sign-in.
    pub fn with_sign_in(mut self, cfg: &Config, sessions: session::Sessions) -> AdminState {
        let Some(signin) = signin::SignIn::of(cfg, Arc::new(sessions)) else {
            return self;
        };
        let signin = Arc::new(signin);
        let finding = Arc::clone(&signin);
        tokio::spawn(async move {
            if let Err(why) = finding.discover().await {
                eprintln!(
                    "mcpdef: the console's identity provider was not found: {why}; it is \
                     looked for again at the next sign-in"
                );
            }
        });
        self.signin = Some(signin);
        self
    }

    /// Show the config file at `path`, masked, at `/api/v1/config`.
    pub fn with_config_path(mut self, path: impl Into<PathBuf>) -> AdminState {
        self.config_path = Some(path.into());
        self
    }

    /// Say where the gateway serves: the MCP listener's address, `None` for
    /// a stdio gateway, and the admin listener's.
    pub fn with_listening(
        mut self,
        mcp: Option<SocketAddr>,
        admin: Option<SocketAddr>,
    ) -> AdminState {
        self.listening = Some((mcp, admin));
        self
    }

    /// Ask `reloads` for the reloads `POST /api/v1/reload` asks for.
    pub fn with_reloads(mut self, reloads: Reloads) -> AdminState {
        self.reloads = Some(reloads);
        self
    }

    /// The refusal for `caller`, for `action` on `target`, when it does not
    /// hold `need`; `None` when it does. A refusal is recorded in the ledger
    /// as an admin action refused under `console-role`, and answered `403`.
    async fn refusal(
        &self,
        caller: &Caller,
        need: ConsoleRole,
        action: &str,
        target: &str,
    ) -> Option<Response> {
        if caller.role.is_some_and(|held| held >= need) {
            return None;
        }
        if caller.sign_in {
            return Some(guard::signed_out());
        }
        let peer = caller.peer.to_string();
        self.gateway
            .audit_admin(
                &caller.actor,
                &peer,
                action,
                target,
                None,
                Some("console-role"),
            )
            .await;
        Some(problem(
            StatusCode::FORBIDDEN,
            "Forbidden",
            format!(
                "{} holds {}, and {action} needs {}",
                caller.actor,
                caller.role.map_or("no console role", ConsoleRole::as_str),
                need.as_str()
            ),
        ))
    }

    /// Take what a reload changed: the servers, and what the envelope checks.
    pub fn reconfigure(&self, cfg: &Config) {
        self.servers.store(Arc::new(server_views(cfg)));
        self.guard.store(Arc::new(Guard::of(cfg)));
        self.views.store(Arc::new(state::Views::of(cfg)));
        self.config.store(Arc::new(cfg.clone()));
        if let Some(signin) = &self.signin {
            signin.reconfigure(cfg);
        }
    }
}

/// Serve the admin UI + API on `listen` until the process ends.
pub async fn serve_admin(state: Arc<AdminState>, listen: String) -> Result<()> {
    serve_admin_with(state, listen, None).await
}

/// [`serve_admin`], over TLS when `tls` is given: each connection is served
/// the `ServerConfig` it holds when the connection is accepted. A client
/// certificate it asks for is checked as the MCP listener checks one, at
/// each request, though no identity is taken from it here.
pub async fn serve_admin_with(
    state: Arc<AdminState>,
    listen: String,
    tls: Option<TlsSlot>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding admin listener on {listen}"))?;
    serve_admin_on(state, listener, tls).await
}

/// [`serve_admin_with`] on an already-bound listener: `mcpdef run` binds it
/// before its ready line, and a test binds `127.0.0.1:0`.
pub async fn serve_admin_on(
    state: Arc<AdminState>,
    listener: tokio::net::TcpListener,
    tls: Option<TlsSlot>,
) -> Result<()> {
    let envelope = guard::Envelope {
        state: Arc::clone(&state),
        tls: tls.clone(),
    };
    // The UI's own files, and who the caller is, for anyone: they show
    // nothing the gateway saw.
    let public = ui_routes()
        .route("/api/v1/session", get(session))
        .merge(state::public())
        .merge(signin::routes());
    let viewer = Router::new()
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(status))
        .route("/api/v1/servers", get(servers))
        .route("/api/v1/stats", get(stats))
        .merge(audit::routes())
        .merge(state::routes())
        .merge(views::routes())
        .route_layer(middleware::from_fn(guard::viewer));
    // What changes something: each checks its caller's role itself, so that a
    // refusal is recorded too.
    let actions = Router::new()
        .route("/api/v1/reload", post(reload))
        .merge(actions::routes());
    let app = public
        .merge(viewer)
        .merge(views::admin_routes())
        .merge(actions)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(envelope, guard::envelope))
        .with_state(state);
    // Served with the connection's peer, as the MCP listener is, so that both
    // listeners share one instance of the HTTP server's code.
    let app = app.into_make_service_with_connect_info::<Peer>();
    match tls {
        None => axum::serve(listener, app).await?,
        Some(tls) => axum::serve(TlsListener::new(listener, tls)?, app).await?,
    }
    Ok(())
}

/// The console: its page at `/`, and its files under `/assets/`.
#[cfg(feature = "console")]
fn ui_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", get(console::index))
        .route("/assets/{*file}", get(console::asset))
}

/// The built-in status page, its styles and its script.
#[cfg(not(feature = "console"))]
fn ui_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", get(ui))
        .route("/ui.css", get(ui_css))
        .route("/ui.js", get(ui_js))
}

#[cfg(not(feature = "console"))]
async fn ui() -> axum::response::Html<&'static str> {
    axum::response::Html(UI_HTML)
}

#[cfg(not(feature = "console"))]
async fn ui_css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], UI_CSS).into_response()
}

#[cfg(not(feature = "console"))]
async fn ui_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        UI_JS,
    )
        .into_response()
}

async fn not_found() -> Response {
    problem(StatusCode::NOT_FOUND, "Not found", "no such route")
}

/// A route there is, asked with a method it does not take: its `Allow`
/// header says which it does.
async fn method_not_allowed() -> Response {
    problem(
        StatusCode::METHOD_NOT_ALLOWED,
        "Method not allowed",
        "this route does not take that method: its Allow header says which it does",
    )
}

/// Who the caller is, and what it may do: for the console to say so, and to
/// show a caller with no role what it would need.
async fn session(Extension(caller): Extension<Caller>) -> Json<serde_json::Value> {
    let mut said = serde_json::json!({
        "actor": caller.actor,
        "role": caller.role,
        "roles": caller.roles(),
        "open": caller.open,
    });
    // Where to sign in, for one who has not; where to sign out, and the name
    // to greet them by, for one a session names.
    if caller.sign_in {
        said["sign_in"] = "/login".into();
    }
    if caller.signed_in {
        said["sign_out"] = "/logout".into();
        said["name"] = caller.name.into();
    }
    Json(said)
}

async fn metrics(State(s): State<Arc<AdminState>>) -> Response {
    let mut body = s.metrics.render_prometheus();
    body.push_str(&render_upstreams(&s.gateway.upstream_status()));
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn status(State(s): State<Arc<AdminState>>) -> Json<serde_json::Value> {
    let up = s
        .gateway
        .upstream_status()
        .iter()
        .filter(|u| matches!(u.health, HealthState::Up | HealthState::Degraded))
        .count();
    Json(serde_json::json!({
        "version": s.version,
        "upstreams": s.servers.load().len(),
        "upstreams_up": up,
        "uptime_seconds": s.metrics.uptime_secs(),
    }))
}

async fn servers(State(s): State<Arc<AdminState>>) -> Json<serde_json::Value> {
    Json(state::reports(&s))
}

/// Each configured server, with its live health and what it adds to
/// `tools/list` merged in by id.
fn servers_report(
    views: &[ServerView],
    live: &[UpstreamStatus],
    costs: &[ToolCost],
) -> serde_json::Value {
    let reports: Vec<ServerReport<'_>> = views
        .iter()
        .map(|view| {
            let status = live.iter().find(|u| u.id == view.id);
            ServerReport {
                view,
                health: status.map_or(HealthState::Starting, |u| u.health),
                restarts: status.map_or(0, |u| u.restarts),
                last_error: status.and_then(|u| u.last_error.clone()),
                credential: status.and_then(|u| u.credential.as_ref()),
                tls: status.and_then(|u| u.tls.as_ref()),
                tool_collisions: status.map_or(&[], |u| u.tool_collisions.as_slice()),
                listing: costs.iter().find(|cost| cost.id == view.id),
            }
        })
        .collect();
    serde_json::to_value(reports).unwrap_or_default()
}

async fn stats(State(s): State<Arc<AdminState>>) -> Json<serde_json::Value> {
    Json(s.metrics.snapshot_json())
}

/// `POST /api/v1/reload`: read the config again and apply it, as `SIGHUP`
/// does, for the caller, who needs `console:operator`. The reload is audited
/// as any is, with the caller as its actor. Applied: `200` and what changed.
/// Refused, the old config still serving: `409`, a problem document with the
/// rule and the reasons.
async fn reload(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Some(refused) = s
        .refusal(&caller, ConsoleRole::Operator, "reload", "(config)")
        .await
    {
        return refused;
    }
    let Some(reloads) = &s.reloads else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No reloader",
            "this gateway takes no reload from its admin API",
        );
    };
    let peer = Some(caller.peer.to_string());
    match reloads.reload(caller.actor.clone(), peer).await {
        Some(Outcome::Applied(report)) => Json(serde_json::json!({
            "outcome": "applied",
            "added": report.added,
            "removed": report.removed,
            "reconnected": report.reconnected,
            "failed": report
                .failed
                .iter()
                .map(|(server, error)| serde_json::json!({ "server": server, "error": error }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Some(Outcome::Refused { rule, reasons }) => {
            let mut response = problem(
                StatusCode::CONFLICT,
                "Reload refused",
                format!("{rule}: {}", reasons.join("; ")),
            );
            // The rule and each reason on their own, as RFC 9457 extension
            // members, beside the detail that joins them.
            let body = serde_json::json!({
                "type": "about:blank",
                "title": "Reload refused",
                "status": 409,
                "detail": format!("{rule}: {}", reasons.join("; ")),
                "outcome": "refused",
                "rule": rule,
                "reasons": reasons,
            });
            *response.body_mut() = axum::body::Body::from(body.to_string());
            response
        }
        None => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "No reloader",
            "the gateway's reloader has stopped",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: &str) -> ServerView {
        ServerView {
            id: id.into(),
            transport: "stdio".into(),
            url: None,
            tools: Some(vec!["echo".into()]),
            deny: vec![],
            profile: None,
            resources: None,
            resource_templates: None,
            prompts: None,
            env: serde_json::Map::new(),
            auth: None,
        }
    }

    #[test]
    fn each_server_carries_its_live_health() {
        let live = [UpstreamStatus {
            id: "gh".into(),
            health: HealthState::Down,
            restarts: 3,
            last_error: Some(LastError {
                message: "connection refused".into(),
                at_unix_ms: 1_758_000_000_000,
            }),
            tls: None,
            credential: None,
            auth_failures: 0,
            tool_collisions: Vec::new(),
            offers: None,
        }];
        let report = servers_report(&[view("gh"), view("fs")], &live, &[]);
        assert_eq!(report[0]["id"], "gh");
        assert_eq!(report[0]["tools"], serde_json::json!(["echo"]));
        assert_eq!(report[0]["health"], "down");
        assert_eq!(report[0]["restarts"], 3);
        assert_eq!(report[0]["last_error"]["message"], "connection refused");
        assert_eq!(report[0]["last_error"]["at_unix_ms"], 1_758_000_000_000u64);
        // A server the gateway has no place for yet is still starting.
        assert_eq!(report[1]["health"], "starting");
        assert_eq!(report[1]["last_error"], serde_json::Value::Null);
    }

    #[test]
    fn an_https_server_carries_its_certificate_and_no_other_does() {
        let tls = TlsStatus {
            verify: "pin",
            fingerprint: Some("AB:CD".into()),
            not_after: Some("2031-02-03T00:00:00Z".into()),
            not_after_unix: Some(1_927_843_200),
            client_not_after: None,
            client_not_after_unix: None,
        };
        let live = |id: &str, tls: Option<TlsStatus>| UpstreamStatus {
            id: id.into(),
            health: HealthState::Up,
            restarts: 0,
            last_error: None,
            tls,
            credential: None,
            auth_failures: 0,
            tool_collisions: Vec::new(),
            offers: None,
        };
        let report = servers_report(
            &[view("secure"), view("plain")],
            &[live("secure", Some(tls)), live("plain", None)],
            &[],
        );
        assert_eq!(
            report[0]["tls"],
            serde_json::json!({
                "verify": "pin",
                "fingerprint": "AB:CD",
                "not_after": "2031-02-03T00:00:00Z",
            })
        );
        let plain = report[1].as_object().unwrap();
        assert!(!plain.contains_key("tls"), "{plain:?}");
    }

    #[test]
    fn env_shows_where_each_value_comes_from_never_the_value() {
        let cfg = Config::parse(
            "[gateway]\n\n[[server]]\nid = \"gh\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n\
             [server.env]\nPLAIN = \"s3cret-literal\"\nFROM_ENV = { env = \"GH_TOKEN\" }\n\
             FROM_FILE = { file = \"/run/secrets/gh\" }\n\
             FROM_EXEC = { exec = [\"op\", \"read\", \"op://infra/gh/s3cret-field\"] }\n",
        )
        .unwrap();
        let report = servers_report(&server_views(&cfg), &[], &[]);
        assert_eq!(
            report[0]["env"],
            serde_json::json!({
                "FROM_ENV": { "scheme": "env", "from": "$GH_TOKEN" },
                "FROM_EXEC": { "scheme": "exec", "from": "(exec op)" },
                "FROM_FILE": { "scheme": "file", "from": "/run/secrets/gh" },
                "PLAIN": { "scheme": "literal", "from": "(literal)" },
            })
        );
        let text = report.to_string();
        assert!(!text.contains("s3cret"), "{text}");
    }

    #[test]
    fn auth_shows_its_kind_and_where_its_secret_comes_from_never_the_secret() {
        let cfg = Config::parse(
            "[gateway]\n\n[[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcp.test/mcp\"\n[server.auth]\nkind = \"header\"\n\
             name = \"X-Api-Key\"\nvalue = \"s3cret-key\"\n\n\
             [[server]]\nid = \"plain\"\ntransport = \"streamable-http\"\n\
             url = \"https://other.test/mcp\"\n",
        )
        .unwrap();
        let report = servers_report(&server_views(&cfg), &[], &[]);
        assert_eq!(
            report[0]["auth"],
            serde_json::json!({
                "kind": "header",
                "name": "X-Api-Key",
                "value": { "scheme": "literal", "from": "(literal)" },
            })
        );
        assert!(!report[1].as_object().unwrap().contains_key("auth"));
        assert!(!report.to_string().contains("s3cret"), "{report}");
    }

    #[test]
    fn oauth2_auth_shows_where_tokens_and_the_client_secret_come_from() {
        let cfg = Config::parse(
            "[gateway]\n\n[[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcp.test/mcp\"\n[server.auth]\nkind = \"oauth2\"\n\
             token_url = \"https://idp.test/token\"\nclient_id = \"s3cret-id\"\n\
             client_secret = { file = \"/run/secrets/client\" }\nscopes = [\"mcp:tools\"]\n",
        )
        .unwrap();
        let report = servers_report(&server_views(&cfg), &[], &[]);
        assert_eq!(
            report[0]["auth"],
            serde_json::json!({
                "kind": "oauth2",
                "token_url": "https://idp.test/token",
                "client_secret": { "scheme": "file", "from": "/run/secrets/client" },
            })
        );
        assert!(!report.to_string().contains("s3cret"), "{report}");
    }

    #[test]
    fn a_server_sent_credentials_shows_how_they_fare_and_no_other_does() {
        use crate::gateway::LastOk;
        let credential = CredentialStatus {
            last_ok: Some(LastOk {
                at_unix_ms: 1_758_000_000_000,
            }),
            last_error: Some(LastError {
                message: "http://mcp.test/mcp answered 401 Unauthorized".into(),
                at_unix_ms: 1_758_000_001_000,
            }),
            expires_at: Some("2026-09-26T13:00:00Z".into()),
            expires_at_unix: Some(1_790_427_600),
        };
        let live = |id: &str, credential: Option<CredentialStatus>| UpstreamStatus {
            id: id.into(),
            health: HealthState::Up,
            restarts: 0,
            last_error: None,
            tls: None,
            credential,
            auth_failures: 1,
            tool_collisions: Vec::new(),
            offers: None,
        };
        let report = servers_report(
            &[view("remote"), view("local")],
            &[live("remote", Some(credential)), live("local", None)],
            &[],
        );
        assert_eq!(
            report[0]["credential"],
            serde_json::json!({
                "last_ok": { "at_unix_ms": 1_758_000_000_000u64 },
                "last_error": {
                    "message": "http://mcp.test/mcp answered 401 Unauthorized",
                    "at_unix_ms": 1_758_000_001_000u64,
                },
                "expires_at": "2026-09-26T13:00:00Z",
            })
        );
        let local = report[1].as_object().unwrap();
        assert!(!local.contains_key("credential"), "{local:?}");
    }

    #[test]
    fn a_url_and_a_token_endpoint_show_none_of_the_secrets_they_hold() {
        let cfg = Config::parse(
            "[gateway]\n\n[[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcpdef:s3cret-pass@mcp.test/mcp?api_key=s3cret-key&v=2\"\n\
             [server.auth]\nkind = \"oauth2\"\n\
             token_url = \"https://idp.test/token?client_secret=s3cret-client\"\n\
             client_id = \"mcpdef\"\nclient_secret = { file = \"/run/secrets/client\" }\n",
        )
        .unwrap();
        let report = servers_report(&server_views(&cfg), &[], &[]);
        assert_eq!(
            report[0]["url"],
            "https://***:***@mcp.test/mcp?api_key=***&v=2"
        );
        assert_eq!(
            report[0]["auth"]["token_url"],
            "https://idp.test/token?client_secret=***"
        );
        assert!(!report.to_string().contains("s3cret"), "{report}");
    }
}
