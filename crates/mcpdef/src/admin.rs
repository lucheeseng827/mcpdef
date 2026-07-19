// SPDX-License-Identifier: Apache-2.0
//! The OSS admin / observability server: a read-only, self-served view of a
//! running gateway. Serves Prometheus `/metrics`, a small JSON API, and an
//! embedded status UI, on a **separate** port from the MCP data path.
//!
//! It never mutates state and never touches the MCP wire — it reads the shared
//! [`Metrics`] registry, a static snapshot of the configured servers, and the
//! audit ledger file. Bind it to loopback or keep it behind your own network
//! policy: like the ledger, it exposes what the gateway saw, not secrets, but it
//! carries no auth of its own (that is the EE control plane's job).

use crate::metrics::Metrics;
use anyhow::{Context, Result};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The single-file built-in UI (vanilla JS, no build step).
const UI_HTML: &str = include_str!("admin_ui.html");

/// A configured upstream, as shown by `/api/v1/servers` and the UI. The effective
/// (profile-applied) allowlist/deny, not the raw `[[server]]` block.
#[derive(Clone, Serialize)]
pub struct ServerView {
    pub id: String,
    pub transport: String,
    pub url: Option<String>,
    /// Effective allowlist (`None` = allow-all was not set; deny still applies).
    pub tools: Option<Vec<String>>,
    pub deny: Vec<String>,
    pub profile: Option<String>,
}

/// Everything the admin server reads. Cheap to build once at startup; the only
/// live-updating piece is the shared [`Metrics`] registry.
pub struct AdminState {
    pub metrics: Arc<Metrics>,
    pub servers: Vec<ServerView>,
    pub audit_path: String,
    pub version: &'static str,
}

/// Serve the admin UI + API on `listen` until the process ends.
pub async fn serve_admin(state: Arc<AdminState>, listen: String) -> Result<()> {
    let app = Router::new()
        .route("/", get(ui))
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(status))
        .route("/api/v1/servers", get(servers))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/audit", get(audit))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding admin listener on {listen}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn metrics(State(s): State<Arc<AdminState>>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        s.metrics.render_prometheus(),
    )
        .into_response()
}

async fn status(State(s): State<Arc<AdminState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": s.version,
        "upstreams": s.servers.len(),
        "uptime_seconds": s.metrics.uptime_secs(),
    }))
}

async fn servers(State(s): State<Arc<AdminState>>) -> Json<Vec<ServerView>> {
    Json(s.servers.clone())
}

async fn stats(State(s): State<Arc<AdminState>>) -> Json<serde_json::Value> {
    Json(s.metrics.snapshot_json())
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

async fn audit(State(s): State<Arc<AdminState>>, Query(q): Query<AuditQuery>) -> Response {
    let n = q.limit.unwrap_or(100).min(1000);
    match mcpdef_audit::tail(&s.audit_path, n) {
        Ok(mut records) => {
            // Newest first for the UI's live tail.
            records.reverse();
            Json(records).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit read failed: {e}"),
        )
            .into_response(),
    }
}
