// SPDX-License-Identifier: Apache-2.0
//! The state API: whether the listener is up, what this gateway is and how
//! it is set up, its calls in figures, each server's tools and what became of
//! them, the policy it judges by, and what inspect found. What comes from the
//! config is put together once per config, and the rest is read live. None
//! of it holds a secret: the config's are never read here, and a finding
//! keeps no text but an injection's own words.

use super::{problem, servers_report, AdminState};
use crate::config::{ArgMatchConfig, Config, ListenerTlsConfig, PolicyRuleConfig};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use mcpdef_core::wire::WireMode;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

/// What the state API shows of a config, put together when the config is
/// read, and again by each reload.
pub(crate) struct Views {
    info: Value,
    rules: Value,
    rbac: Value,
    profiles: Value,
    inspect: Value,
}

impl Views {
    pub(crate) fn of(cfg: &Config) -> Views {
        let g = &cfg.gateway;
        let auth = &g.auth;
        let tls = |tls: Option<&ListenerTlsConfig>| {
            json!({
                "tls": tls.map_or("off", |t| t.mode.as_str()),
                "client_auth": tls.map_or("off", |t| t.client_auth.mode.as_str()),
            })
        };
        let info = json!({
            "wire": match g.wire {
                WireMode::Legacy => "legacy",
                WireMode::Dual => "dual",
                WireMode::Modern => "modern",
            },
            "revisions": g.wire.served(),
            "listen": g.listen,
            "mcp": tls(Some(&g.tls)),
            // The admin listener serves `[gateway.tls]` unless it has its own.
            "admin": tls(Some(g.admin_tls())),
            "auth": {
                "enabled": auth.enabled,
                "methods": auth
                    .methods
                    .as_deref()
                    .map_or(vec!["bearer"], |m| m.iter().map(|m| m.as_str()).collect()),
                "issuer": auth.issuer.as_deref().map(|u| crate::redact::redact_url(u).into_owned()),
                "resource": auth.resource.as_deref().map(|u| crate::redact::redact_url(u).into_owned()),
                // Where the keys come from, never the keys.
                "keys": match (&auth.jwks, &auth.jwks_uri, auth.discovery) {
                    (Some(_), _, _) => Some("jwks"),
                    (None, Some(_), _) => Some("jwks_uri"),
                    (None, None, true) => Some("discovery"),
                    (None, None, false) => None,
                },
                "audiences": auth.audiences.iter().map(|u| crate::redact::redact_url(u).into_owned()).collect::<Vec<_>>(),
            },
            "inspect": inspect_mode(cfg),
            "pins": g.pins.is_some(),
            "strict": g.strict,
        });
        let rule = |r: &PolicyRuleConfig| {
            json!({
                "name": r.name,
                "effect": r.effect.to_ascii_lowercase(),
                "agents": r.agents,
                "servers": r.servers,
                "tools": r.tools,
                "uris": r.uris,
                "prompts": r.prompts,
                "args": r.args.iter().map(predicate).collect::<Vec<_>>(),
                // What each edit does and where, never a value it puts there.
                "set_args": r.set_args.iter().map(|e| {
                    let op = match (&e.set, &e.default, &e.clamp) {
                        (Some(_), _, _) => "set",
                        (None, Some(_), _) => "default",
                        (None, None, Some(_)) => "clamp",
                        (None, None, None) => "remove",
                    };
                    let mut edit = json!({ "path": e.path, "op": op });
                    if let Some(clamp) = &e.clamp {
                        edit["min"] = json!(clamp.min);
                        edit["max"] = json!(clamp.max);
                    }
                    edit
                }).collect::<Vec<_>>(),
                "on_error": r.on_error,
                "result": r.result.iter().map(|e| {
                    let (op, arg) = match (&e.redact, &e.mask, &e.remove, e.truncate) {
                        (Some(what), ..) => ("redact", json!(what)),
                        (None, Some(path), ..) => ("mask", json!(path)),
                        (None, None, Some(path), _) => ("remove", json!(path)),
                        (None, None, None, bytes) => ("truncate", json!(bytes)),
                    };
                    json!({ "op": op, "arg": arg })
                }).collect::<Vec<_>>(),
            })
        };
        let (transforms, admission): (Vec<_>, Vec<_>) = cfg
            .policy
            .iter()
            .partition(|r| r.effect.eq_ignore_ascii_case("transform"));
        let rules = json!({
            "transform": transforms.into_iter().map(rule).collect::<Vec<_>>(),
            "admission": admission.into_iter().map(rule).collect::<Vec<_>>(),
        });
        let rbac = json!({
            "roles": cfg.roles.iter().map(|r| json!({
                "name": r.name,
                "grants": r.grants,
                "resource_grants": r.resource_grants,
                "prompt_grants": r.prompt_grants,
            })).collect::<Vec<_>>(),
            "cert_map": cfg.identity.cert_map.iter().map(|m| json!({
                "identity": m.identity,
                "roles": m.roles,
            })).collect::<Vec<_>>(),
        });
        let mut names: Vec<&String> = cfg.profiles.keys().collect();
        names.sort();
        let profiles = json!({
            "active": g.profile,
            "profiles": names.into_iter().map(|name| {
                let p = &cfg.profiles[name];
                json!({ "name": name, "tools": p.tools, "deny": p.deny })
            }).collect::<Vec<_>>(),
        });
        let inspect = json!({
            "mode": inspect_mode(cfg),
            "injection_phrases": g.inspect.injection_phrases,
            // How many, never what: one may be a secret's own prefix.
            "secret_substrings": g.inspect.secret_substrings.len(),
        });
        Views {
            info,
            rules,
            rbac,
            profiles,
            inspect,
        }
    }
}

fn inspect_mode(cfg: &Config) -> String {
    cfg.gateway
        .inspect
        .mode
        .as_deref()
        .map_or("off".to_string(), |m| m.trim().to_ascii_lowercase())
}

/// An argument predicate, by its operator.
fn predicate(m: &ArgMatchConfig) -> Value {
    let (op, value) = match (&m.equals, &m.glob, &m.contains) {
        (Some(v), ..) => ("equals", Some(v)),
        (None, Some(v), _) => ("glob", Some(v)),
        (None, None, Some(v)) => ("contains", Some(v)),
        (None, None, None) => ("exists", None),
    };
    json!({ "path": m.path, "op": op, "value": value })
}

/// The state API's routes: `/health` for anyone, the rest for a viewer.
pub(super) fn public() -> Router<Arc<AdminState>> {
    Router::new().route("/health", get(health))
}

pub(super) fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/info", get(info))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/servers/{id}", get(server))
        .route("/api/v1/servers/{id}/tools", get(tools))
        .route("/api/v1/policy/rules", get(rules))
        .route("/api/v1/policy/rbac", get(rbac))
        .route("/api/v1/policy/profiles", get(profiles))
        .route("/api/v1/inspect/config", get(inspect))
        .route("/api/v1/inspect/findings", get(findings))
}

/// `GET /health`: the listener answers. For a probe, so for anyone, and it
/// says nothing else.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/v1/info`: what this gateway is and how it is set up, and its
/// ledger's length and head.
async fn info(State(s): State<Arc<AdminState>>) -> Json<Value> {
    let mut info = s.views.load().info.clone();
    let (records, head) = s.gateway.audit_written();
    let upstreams = s.gateway.upstream_status();
    info["version"] = json!(s.version);
    info["audit"] = json!({ "records": records, "head": head });
    info["upstreams"] = json!(upstreams.len());
    info["upstreams_up"] = json!(upstreams
        .iter()
        .filter(|u| matches!(
            u.health,
            crate::gateway::HealthState::Up | crate::gateway::HealthState::Degraded
        ))
        .count());
    info["uptime_seconds"] = json!(s.metrics.uptime_secs());
    if let Some((mcp, admin)) = &s.listening {
        info["serving"] = json!({
            "mcp": mcp.map_or("stdio".to_string(), |a: SocketAddr| a.to_string()),
            "admin": admin.map(|a| a.to_string()),
        });
    }
    Json(info)
}

/// `GET /api/v1/metrics`: the calls since the gateway started, in figures.
async fn metrics(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(s.metrics.console_json())
}

/// Each server's report, as `/api/v1/servers` gives them, with how many of
/// its tools are hidden for drifting from their pins and for tripping the
/// scanner.
pub(super) fn reports(s: &AdminState) -> Value {
    let mut report = servers_report(
        &s.servers.load(),
        &s.gateway.upstream_status(),
        &s.gateway.tool_costs(),
    );
    for server in report.as_array_mut().into_iter().flatten() {
        let id = server["id"].as_str().unwrap_or_default().to_string();
        let tools = s.gateway.server_tools(&id).unwrap_or_default();
        let hidden = |why: &str| tools.iter().filter(|t| t.hidden == Some(why)).count();
        server["drifted"] = json!(hidden("drift"));
        server["poisoned"] = json!(hidden("inspect"));
    }
    report
}

fn no_server(id: &str) -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "Not found",
        format!("no server is configured with the id {id:?}"),
    )
}

/// `GET /api/v1/servers/{id}`: one server's report.
async fn server(State(s): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    let reports = reports(&s);
    match reports
        .as_array()
        .and_then(|all| all.iter().find(|r| r["id"] == id.as_str()))
    {
        Some(report) => Json(report.clone()).into_response(),
        None => no_server(&id),
    }
}

/// `GET /api/v1/servers/{id}/tools`: each tool its connection offers, and
/// what became of it.
async fn tools(State(s): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    match s.gateway.server_tools(&id) {
        Some(tools) => Json(tools).into_response(),
        None => no_server(&id),
    }
}

/// `GET /api/v1/policy/rules`: the `[[policy]]` rules, in the order they
/// run: the transform rules, which rewrite a call's arguments before the
/// others judge it and its result after, then the allow and deny rules,
/// the first that matches deciding.
async fn rules(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(s.views.load().rules.clone())
}

/// `GET /api/v1/policy/rbac`: the `[[role]]`s, and the roles each client
/// certificate identity holds.
async fn rbac(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(s.views.load().rbac.clone())
}

/// `GET /api/v1/policy/profiles`: the profiles, and which is active.
async fn profiles(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(s.views.load().profiles.clone())
}

/// `GET /api/v1/inspect/config`: how inspect is set up.
async fn inspect(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(s.views.load().inspect.clone())
}

/// `GET /api/v1/inspect/findings`: what inspect found lately, newest first.
async fn findings(State(s): State<Arc<AdminState>>) -> Json<Value> {
    Json(json!(s.gateway.inspect_findings()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_listener_is_said_to_serve_the_tls_it_inherits_or_its_own() {
        let config = |admin_tls: &str| {
            Config::parse(&format!(
                "[gateway]\nlisten = \"127.0.0.1:7878\"\n\n\
                 [gateway.tls]\nmode = \"self-signed\"\n\
                 client_auth = {{ mode = \"optional\", ca = [\"/etc/mcpdef/ca.pem\"] }}\n\n\
                 {admin_tls}\n\n\
                 [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"a\"]\n"
            ))
            .unwrap()
        };
        let inherited = Views::of(&config("")).info;
        assert_eq!(
            inherited["mcp"],
            json!({ "tls": "self-signed", "client_auth": "optional" })
        );
        assert_eq!(inherited["admin"], inherited["mcp"], "{inherited}");
        let own = Views::of(&config("[gateway.admin.tls]\nmode = \"off\"")).info;
        assert_eq!(
            own["admin"],
            json!({ "tls": "off", "client_auth": "off" }),
            "{own}"
        );
    }
}
