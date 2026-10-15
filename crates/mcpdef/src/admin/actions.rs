// SPDX-License-Identifier: Apache-2.0
//! The operator's actions on an upstream: open it again, test it, and take
//! its drifted tools' definitions as their pins. Each needs
//! `console:operator`, checked in the handler so that a refusal is recorded,
//! and each one taken is recorded with its caller.

use super::{problem, AdminState, Caller, ConsoleRole};
use crate::gateway::Refused;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Extension, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// How long a test waits for the upstream's answer, unless
/// `[gateway] upstream_timeout_ms` says.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The most of a server's id a record keeps: one asked for need not be one
/// the config has.
const TARGET_KEPT: usize = 128;

pub(super) fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/servers/{id}/restart", post(restart))
        .route("/api/v1/servers/{id}/test", post(test))
        .route("/api/v1/servers/{id}/pins", post(pins))
}

/// `id`, as a record names it.
fn target(id: &str) -> &str {
    match id.char_indices().nth(TARGET_KEPT) {
        Some((end, _)) => &id[..end],
        None => id,
    }
}

fn refused(id: &str, refused: Refused, title: &str) -> Response {
    match refused {
        Refused::Unknown => problem(
            StatusCode::NOT_FOUND,
            "Not found",
            format!("no server is configured with the id {:?}", target(id)),
        ),
        Refused::Not(why) => problem(StatusCode::CONFLICT, title, why),
    }
}

/// `POST /api/v1/servers/{id}/restart`: its keeper opens it again now, its
/// backoff reset; the connection it holds serves until the new one opens.
/// Answered `202` once asked: `/api/v1/servers` shows how it went.
async fn restart(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<String>,
) -> Response {
    if let Some(refusal) = s
        .refusal(&caller, ConsoleRole::Operator, "restart", target(&id))
        .await
    {
        return refusal;
    }
    match s.gateway.restart_upstream(&id) {
        Ok(()) => {
            let peer = caller.peer.to_string();
            s.gateway
                .audit_admin(&caller.actor, &peer, "restart", &id, None, None)
                .await;
            (StatusCode::ACCEPTED, Json(json!({ "restarting": id }))).into_response()
        }
        Err(why) => refused(&id, why, "Not restarted"),
    }
}

/// `POST /api/v1/servers/{id}/test`: a `ping` over its live connection:
/// `{ ok, latency_ms, error }`.
async fn test(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<String>,
) -> Response {
    if let Some(refusal) = s
        .refusal(&caller, ConsoleRole::Operator, "test", target(&id))
        .await
    {
        return refusal;
    }
    let timeout = s
        .config
        .load()
        .gateway
        .upstream_timeout_ms
        .map_or(TEST_TIMEOUT, Duration::from_millis);
    match s.gateway.ping_upstream(&id, timeout).await {
        Ok(answer) => {
            let peer = caller.peer.to_string();
            s.gateway
                .audit_admin(&caller.actor, &peer, "test", &id, None, None)
                .await;
            Json(match answer {
                Ok(took) => {
                    json!({ "ok": true, "latency_ms": took.as_millis() as u64, "error": null })
                }
                Err(error) => json!({ "ok": false, "latency_ms": null, "error": error }),
            })
            .into_response()
        }
        Err(why) => refused(&id, why, "Not tested"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approve {
    /// Each tool approved, and the hash of the definition its approver
    /// looked at, as `GET /api/v1/servers/{id}/tools` gives it.
    tools: BTreeMap<String, String>,
}

/// `POST /api/v1/servers/{id}/pins`: the definitions its drifted tools named
/// in `{ tools: { name: hash } }` have now, taken as their pins, saved, and
/// the tools served again: `{ approved }`. Refused when one offers another
/// definition now than the hash names. One record per tool.
async fn pins(
    State(s): State<Arc<AdminState>>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if let Some(refusal) = s
        .refusal(&caller, ConsoleRole::Operator, "approve-drift", target(&id))
        .await
    {
        return refusal;
    }
    let tools = match serde_json::from_slice::<Approve>(&body) {
        Ok(approve) if !approve.tools.is_empty() => approve.tools,
        Ok(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Bad request",
                "name each tool approved, with the hash of its definition looked at",
            )
        }
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "Bad request",
                format!(
                    "the body is {{ \"tools\": {{ name: hash }} }}, each tool with the hash of \
                     the definition looked at, as /api/v1/servers/{{id}}/tools gives it: {e}"
                ),
            )
        }
    };
    match s.gateway.approve_drift(&id, &tools) {
        Ok(approved) => {
            let peer = caller.peer.to_string();
            for tool in &approved {
                s.gateway
                    .audit_admin(&caller.actor, &peer, "approve-drift", &id, Some(tool), None)
                    .await;
            }
            Json(json!({ "approved": approved })).into_response()
        }
        Err(why) => refused(&id, why, "Not approved"),
    }
}
