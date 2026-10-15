// SPDX-License-Identifier: Apache-2.0
//! The config and connection views: the config file with every secret it
//! holds masked, a config checked without being applied, each listener's
//! TLS, each upstream's credentials, a client's entry for the gateway, the
//! local CA's certificate, and who the gateway takes its callers to be.
//! None of them shows a secret: the file's are masked by where they sit and
//! by their shape, and the rest never reads one.

use super::{guard, problem, AdminState};
use crate::clients::{self, Ask, Client, Target};
use crate::config::{Config, ListenerTlsConfig, ListenerTlsMode, CONSOLE_ROLES};
use crate::redact::{redact_url, redact_urls};
use crate::tls::local_ca;
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use mcpdef_inspect::{Category, Mode, Scanner};
use mcpdef_transport::{rfc3339, CertificateNames, PeerCertificate};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use toml_edit::{DocumentMut, Item, TableLike};

/// What a masked secret reads as.
const MASK: &str = "***";

/// The views for a viewer, and those for an admin: the config and who the
/// gateway takes its callers to be.
pub(super) fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/tls", get(tls))
        .route("/api/v1/credentials", get(credentials))
        .route("/api/v1/clients/{client}/snippet", get(snippet))
        .route("/api/v1/ca.pem", get(ca_pem))
}

pub(super) fn admin_routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/config", get(config_file))
        .route("/api/v1/config/validate", post(validate))
        .route("/api/v1/identity", get(identity))
        .route_layer(middleware::from_fn(guard::admin))
}

/// `text`, a config, with every secret it holds masked, and where each was:
/// the secrets in their places (keys, `[server.auth]` secrets, `[server.env]`
/// values written in the file, a transform's values, the inspect secret
/// substrings), the credentials in its URLs, and then anything anywhere in
/// the text, comments too, that has a credential's shape. A value that
/// names where a secret comes from (`{ env = … }`, `{ file = … }`,
/// `{ exec = … }`) is kept: it is not the secret.
pub(crate) fn masked(text: &str) -> Result<(String, Vec<String>), String> {
    let mut doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
        let at = e.span().map_or(0, |span| span.start);
        let line = text[..at.min(text.len())].lines().count().max(1);
        format!("the config file does not parse as TOML, at line {line}")
    })?;
    let mut paths = Vec::new();
    let root = doc.as_table_mut();
    if let Some(gateway) = table(root, "gateway") {
        for (path, key) in [
            ("tls", "key"),
            ("upstream_tls", "client_key"),
            ("admin.tls", "key"),
            ("admin.session", "key"),
            ("admin.session", "previous_key"),
            ("admin.oidc", "client_secret"),
            ("admin.break_glass", "token_sha256"),
        ] {
            if let Some(t) = nested(gateway, path) {
                secret(
                    t,
                    key,
                    &format!("/gateway/{}/{key}", path.replace('.', "/")),
                    &mut paths,
                );
            }
        }
        for (path, key) in [
            ("auth", "issuer"),
            ("auth", "resource"),
            ("auth", "jwks_uri"),
            ("admin", "public_url"),
            ("admin.oidc", "issuer"),
        ] {
            if let Some(t) = nested(gateway, path) {
                url(
                    t,
                    key,
                    &format!("/gateway/{}/{key}", path.replace('.', "/")),
                    &mut paths,
                );
            }
        }
        if let Some(inspect) = table(gateway, "inspect") {
            if let Some(list) = inspect
                .get_mut("secret_substrings")
                .and_then(Item::as_array_mut)
            {
                for (i, value) in list.iter_mut().enumerate() {
                    mask(value);
                    paths.push(format!("/gateway/inspect/secret_substrings/{i}"));
                }
            }
        }
    }
    each(root, "server", |i, server| {
        let at = format!("/server/{i}");
        url(server, "url", &format!("{at}/url"), &mut paths);
        if let Some(tls) = table(server, "tls") {
            secret(
                tls,
                "client_key",
                &format!("{at}/tls/client_key"),
                &mut paths,
            );
        }
        if let Some(auth) = table(server, "auth") {
            for key in ["token", "value", "password", "client_secret"] {
                secret(auth, key, &format!("{at}/auth/{key}"), &mut paths);
            }
            url(
                auth,
                "token_url",
                &format!("{at}/auth/token_url"),
                &mut paths,
            );
        }
        if let Some(env) = table(server, "env") {
            let names: Vec<String> = env.iter().map(|(name, _)| name.to_string()).collect();
            for name in names {
                secret(env, &name, &format!("{at}/env/{name}"), &mut paths);
            }
        }
    });
    // A transform's values, `set_args = [...]` or `[[policy.set_args]]`,
    // whatever they are: one written as a table of its own goes too.
    each(root, "policy", |i, rule| {
        each(rule, "set_args", |j, edit| {
            for key in ["set", "default"] {
                if let Some(item) = edit.get_mut(key) {
                    match item.as_value_mut() {
                        Some(value) => mask(value),
                        None => *item = Item::Value(MASK.into()),
                    }
                    paths.push(format!("/policy/{i}/set_args/{j}/{key}"));
                }
            }
        });
    });
    Ok((by_shape(&redact_urls(&doc.to_string())), paths))
}

/// `name`'s table in `parent`, written as a table or inline.
fn table<'a>(parent: &'a mut dyn TableLike, name: &str) -> Option<&'a mut dyn TableLike> {
    parent.get_mut(name)?.as_table_like_mut()
}

/// The table at the dotted `path` under `parent`.
fn nested<'a>(parent: &'a mut dyn TableLike, path: &str) -> Option<&'a mut dyn TableLike> {
    path.split('.').try_fold(parent, |at, name| table(at, name))
}

/// Each table of the array `name` in `parent`, `[[name]]` or inline.
fn each(parent: &mut dyn TableLike, name: &str, mut f: impl FnMut(usize, &mut dyn TableLike)) {
    match parent.get_mut(name) {
        Some(Item::ArrayOfTables(tables)) => {
            for (i, t) in tables.iter_mut().enumerate() {
                f(i, t);
            }
        }
        Some(Item::Value(toml_edit::Value::Array(values))) => {
            for (i, value) in values.iter_mut().enumerate() {
                if let Some(t) = value.as_inline_table_mut() {
                    f(i, t);
                }
            }
        }
        _ => {}
    }
}

/// `value`, whatever it was, read as the mask, its comments kept.
fn mask(value: &mut toml_edit::Value) {
    let decor = value.decor().clone();
    *value = MASK.into();
    *value.decor_mut() = decor;
}

/// Masks `key` of `t` when it is written in the file: a string. A table
/// says where the secret comes from, and is kept.
fn secret(t: &mut dyn TableLike, key: &str, path: &str, paths: &mut Vec<String>) {
    if let Some(value) = t.get_mut(key).and_then(Item::as_value_mut) {
        if value.is_str() {
            mask(value);
            paths.push(path.to_string());
        }
    }
}

/// Masks the credentials in the URL at `key` of `t`, if it holds any.
fn url(t: &mut dyn TableLike, key: &str, path: &str, paths: &mut Vec<String>) {
    let Some(value) = t.get_mut(key).and_then(Item::as_value_mut) else {
        return;
    };
    let Some(text) = value.as_str() else {
        return;
    };
    let redacted = redact_url(text);
    if redacted != text {
        let redacted = redacted.into_owned();
        let decor = value.decor().clone();
        *value = redacted.into();
        *value.decor_mut() = decor;
        paths.push(path.to_string());
    }
}

/// `text` with whatever has a credential's shape masked, wherever it is.
fn by_shape(text: &str) -> String {
    let Some(scanner) = Scanner::new(Mode::Enforce) else {
        return text.to_string();
    };
    let mut out = text.to_string();
    let mut found: Vec<_> = scanner
        .find_all(text)
        .into_iter()
        .filter(|m| m.category == Category::Secret)
        .collect();
    found.sort_by_key(|m| std::cmp::Reverse(m.range.start));
    for m in found {
        out.replace_range(m.range, MASK);
    }
    out
}

/// `GET /api/v1/config` (admin): the config file the gateway was started
/// from, as it is on disk now, masked. A change in it that no reload has
/// applied yet shows here before it runs.
async fn config_file(State(s): State<Arc<AdminState>>) -> Response {
    let Some(path) = s.config_path.clone() else {
        return problem(
            StatusCode::NOT_FOUND,
            "Not found",
            "this gateway was not started from a config file",
        );
    };
    let shown = path.display().to_string();
    let read = tokio::task::spawn_blocking(move || std::fs::read_to_string(path)).await;
    let text = match read {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Config unreadable",
                format!("reading {shown}: {e}"),
            )
        }
        Err(e) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Config unreadable",
                e.to_string(),
            )
        }
    };
    match masked(&text) {
        Ok((text, redacted)) => {
            Json(json!({ "path": shown, "text": text, "redacted": redacted })).into_response()
        }
        Err(why) => problem(StatusCode::INTERNAL_SERVER_ERROR, "Config unreadable", why),
    }
}

#[derive(Deserialize)]
struct Posted {
    text: String,
}

/// `POST /api/v1/config/validate` (admin): `{ valid, problems }` for a
/// config's text, parsed and checked as `mcpdef validate` checks one, and
/// never applied. Nothing it names is read or run: no file, no command.
async fn validate(body: Result<Json<Posted>, JsonRejection>) -> Response {
    let posted = match body {
        Ok(Json(posted)) => posted,
        Err(e) => return problem(StatusCode::BAD_REQUEST, "Bad request", e.body_text()),
    };
    let problems = match Config::parse(&posted.text) {
        Ok(cfg) => cfg.validate(),
        Err(e) => vec![format!("{e:#}")],
    };
    Json(json!({ "valid": problems.is_empty(), "problems": problems })).into_response()
}

/// `GET /api/v1/tls`: each listener's TLS as the config sets it and the
/// certificates it names, the local CA's, and each upstream's certificate,
/// once its connection has opened.
async fn tls(State(s): State<Arc<AdminState>>) -> Json<Value> {
    let cfg = s.config.load_full();
    let mut view = tokio::task::spawn_blocking(move || tls_view(&cfg))
        .await
        .unwrap_or_default();
    view["upstreams"] = s
        .gateway
        .upstream_status()
        .into_iter()
        .filter_map(|u| Some(json!({ "server": u.id, "tls": u.tls? })))
        .collect();
    Json(view)
}

fn tls_view(cfg: &Config) -> Value {
    let g = &cfg.gateway;
    let paths = local_ca::Paths::under(&g.state_dir);
    let ca = paths.ca_cert();
    json!({
        "mcp": listener(&g.tls, &paths),
        "admin": g.admin.enabled.then(|| listener(g.admin_tls(), &paths)),
        "local_ca": ca.exists().then(|| certificate(ca)),
    })
}

fn listener(tls: &ListenerTlsConfig, paths: &local_ca::Paths) -> Value {
    let cert = match tls.mode {
        ListenerTlsMode::Off => None,
        ListenerTlsMode::Files => tls.cert.as_deref().map(PathBuf::from),
        ListenerTlsMode::SelfSigned => Some(paths.cert()),
    };
    let client_auth = &tls.client_auth;
    json!({
        "mode": tls.mode.as_str(),
        "hostnames": tls.hostnames,
        "certificate": cert.map(certificate),
        "client_auth": {
            "mode": client_auth.mode.as_str(),
            "identity": client_auth.identity.map(|i| i.as_str()),
            "trust_domains": client_auth.trust_domains,
            "ca": client_auth.ca.iter().map(|path| certificate(PathBuf::from(path))).collect::<Vec<_>>(),
            "crl": client_auth.crl,
        },
    })
}

/// The first certificate in the PEM file at `path`: whom it is for, who
/// issued it, when it expires and its fingerprint; or why it does not read.
fn certificate(path: PathBuf) -> Value {
    let shown = path.display().to_string();
    match CertificateDer::pem_file_iter(&path).map(|mut certs| certs.next()) {
        Ok(Some(Ok(der))) => {
            let names = CertificateNames::read(&der);
            let read = PeerCertificate::read(&der);
            json!({
                "path": shown,
                "subject": names.subject,
                "names": names.alt_names,
                "issuer": names.issuer,
                "not_after": read.not_after.map(rfc3339),
                "sha256": read.fingerprint,
            })
        }
        Ok(Some(Err(e))) | Err(e) => json!({ "path": shown, "error": e.to_string() }),
        Ok(None) => json!({ "path": shown, "error": "it holds no certificate" }),
    }
}

/// `GET /api/v1/credentials`: how the credentials MCPdef sends each upstream
/// that takes some fare: their kind, the last time they were taken and
/// refused, when they expire, and how often they failed. Never the secret.
async fn credentials(State(s): State<Arc<AdminState>>) -> Json<Value> {
    let views = s.servers.load();
    let live = s.gateway.upstream_status();
    let credentials: Vec<Value> = views
        .iter()
        .filter_map(|view| {
            let kind = view.auth.as_ref()?.get("kind")?.clone();
            let status = live.iter().find(|u| u.id == view.id);
            Some(json!({
                "server": view.id,
                "kind": kind,
                "credential": status.and_then(|u| u.credential.as_ref()),
                "auth_failures": status.map_or(0, |u| u.auth_failures),
            }))
        })
        .collect();
    Json(json!(credentials))
}

#[derive(Deserialize)]
struct SnippetQuery {
    name: Option<String>,
    token_env: Option<String>,
}

/// `GET /api/v1/clients/{client}/snippet`: what `mcpdef connect <client>`
/// prints, for this gateway: `?name=` names the entry (`mcpdef`), and
/// `?token_env=` the variable a client that sends its own bearer token reads
/// it from.
async fn snippet(
    State(s): State<Arc<AdminState>>,
    Path(client): Path<String>,
    Query(q): Query<SnippetQuery>,
) -> Response {
    let client: Client = match client.parse() {
        Ok(client) => client,
        Err(e) => return problem(StatusCode::NOT_FOUND, "Not found", e.to_string()),
    };
    let cfg = s.config.load_full();
    let mut target = Target::of(&cfg);
    if let Some((Some(mcp), _)) = s.listening {
        target.url = clients::listener_url(&mcp.to_string(), cfg.gateway.tls.mode.is_on());
    }
    let ask = Ask {
        name: q.name.unwrap_or_else(|| "mcpdef".to_string()),
        token_env: q.token_env,
        token_file: None,
        cert: None,
        key: None,
        mcpdef: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mcpdef")),
    };
    match clients::entry(client, &target, &ask, None) {
        Ok(entry) => Json(json!({
            "client": client.name(),
            "name": entry.name,
            "url": entry.url,
            "text": entry.render(),
            "report": entry.report(),
        }))
        .into_response(),
        Err(e) => problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "No entry",
            format!("{e:#}"),
        ),
    }
}

/// `GET /api/v1/ca.pem`: the local CA's certificate, for a client to trust.
/// Each certificate the file holds is written out again from its DER, so
/// whatever else the file might hold, a key above all, never goes out.
async fn ca_pem(State(s): State<Arc<AdminState>>) -> Response {
    let path = local_ca::Paths::under(&s.config.load().gateway.state_dir).ca_cert();
    let certs: Vec<CertificateDer<'static>> = match CertificateDer::pem_file_iter(&path) {
        Ok(certs) => certs.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    };
    if certs.is_empty() {
        return problem(
            StatusCode::NOT_FOUND,
            "Not found",
            "this gateway has no local CA: `mcpdef tls init` makes one",
        );
    }
    let pem: String = certs.iter().map(|der| pem_certificate(der)).collect();
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"mcpdef-ca.crt\"",
            ),
        ],
        pem,
    )
        .into_response()
}

/// `der` as a PEM `CERTIFICATE` block.
fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// `GET /api/v1/identity` (admin): who the gateway takes its callers to be:
/// how the MCP listener authenticates them, how the console signs them in,
/// and the roles a certificate's identity holds.
async fn identity(State(s): State<Arc<AdminState>>) -> Json<Value> {
    let cfg = s.config.load_full();
    let g = &cfg.gateway;
    let auth = &g.auth;
    let masked = |url: &Option<String>| url.as_deref().map(|u| redact_url(u).into_owned());
    // How the console signs people in: at an identity provider, by a client
    // certificate, both, or neither.
    let signs_in: Vec<&str> = [
        ("oidc", g.admin.oidc.is_some()),
        ("certificate", g.admin_requires_certificates()),
    ]
    .into_iter()
    .filter_map(|(how, on)| on.then_some(how))
    .collect();
    // The client's secret is said to be set, or not; never shown.
    let oidc = g.admin.oidc.as_ref().map(|o| {
        json!({
            "issuer": redact_url(&o.issuer),
            "client_id": o.client_id,
            "client_secret": o.client_secret.is_some(),
            "client_auth": o.client_auth.as_deref().unwrap_or("client_secret_basic"),
            "scopes": o.scopes(),
            "userinfo": o.userinfo,
            "api_audience": o.api_audience.as_deref().map(redact_url),
            "redirect_uri": g.admin.public_url.as_deref().map(|u| format!("{}/callback", redact_url(u.trim_end_matches('/')))),
        })
    });
    let model = cfg.identity.model();
    Json(json!({
        "mcp": {
            "bearer": {
                "enabled": auth.enabled,
                "methods": auth.methods.as_deref().map_or(vec!["bearer"], |m| m.iter().map(|m| m.as_str()).collect()),
                "issuer": masked(&auth.issuer),
                "resource": masked(&auth.resource),
                "audiences": auth.audiences.iter().map(|u| redact_url(u).into_owned()).collect::<Vec<_>>(),
                "discovery": auth.discovery,
            },
            "client_certificates": g.tls.client_auth.mode.as_str(),
            "identity": g.tls.client_auth.identity.map(|i| i.as_str()),
        },
        "console": {
            "signs_in": signs_in,
            "oidc": oidc,
            "break_glass": g.admin.break_glass.is_some(),
            // Whether the identity provider was found, as the gateway last
            // looked for it.
            "provider": s.signin.as_ref().map(|signin| signin.status()),
            "allow_unauthenticated": g.admin.allow_unauthenticated,
            "public_url": masked(&g.admin.public_url),
            "hosts": g.admin.hosts,
            "roles": CONSOLE_ROLES,
        },
        "model": {
            "subject_claim": model.subject_claim,
            "roles_claims": model.roles_claims,
            "role_map": model.role_map.iter().map(|m| json!({ "claim": m.claim, "value": m.value, "roles": m.roles })).collect::<Vec<_>>(),
        },
        "cert_map": cfg.identity.cert_map.iter().map(|m| json!({ "identity": m.identity, "roles": m.roles })).collect::<Vec<_>>(),
        // The client keys the gateway issued: whom each names, never its digest.
        "keys": cfg.keys.iter().map(|k| json!({ "name": k.name, "roles": k.roles })).collect::<Vec<_>>(),
        "roles": cfg.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_is_masked_by_where_its_secrets_sit_and_by_their_shape() {
        let key = ["AK", "IA", "PLANTEDKEY000042"].concat();
        let text = format!(
            "# deploy key, for now: {key}\n\
             [gateway]\nlisten = \"127.0.0.1:7878\"\n\n\
             [gateway.tls]\nmode = \"files\"\ncert = \"/etc/mcpdef/tls.crt\"\nkey = \"lItErAl-kEy\"\n\n\
             [gateway.auth]\nenabled = true\nissuer = \"https://usr:iSsUeR-pAsS@idp.example/\"\n\n\
             [gateway.inspect]\nsecret_substrings = [\"aCmE_sK_\", \"oThEr_\"]\n\n\
             [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"a\"]\n\n\
             [server.env]\nAPI_KEY = \"eNv-SeCrEt\" # rotated monthly\nFROM_VAR = {{ env = \"A_KEY\" }}\n\n\
             [server.auth]\nkind = \"header\"\nname = \"x-key\"\nvalue = \"hEaDeR-sEcReT\"\n\n\
             [[server]]\nid = \"b\"\ntransport = \"streamable-http\"\nurl = \"https://mcp.example/mcp?token=uRl-SeCrEt\"\n\
             auth = {{ kind = \"oauth2\", token_url = \"https://idp.example/token\", client_id = \"c\", client_secret = {{ file = \"/run/s\" }} }}\n\n\
             [[policy]]\nname = \"stamp\"\neffect = \"transform\"\nset_args = [{{ path = \"t\", set = \"sEt-SeCrEt\" }}, {{ path = \"n\", clamp = {{ max = 5 }} }}]\n\n\
             [[policy]]\nname = \"stamp-tables\"\neffect = \"transform\"\n\n\
             [[policy.set_args]]\npath = \"headers.authorization\"\nset = \"tAbLe-SeCrEt\"\n\n\
             [[policy.set_args]]\npath = \"region\"\ndefault = \"dEfAuLt-SeCrEt\"\n\n\
             [[policy.set_args]]\npath = \"options\"\n[policy.set_args.set]\ntoken = \"sUbTaBlE-SeCrEt\"\n"
        );
        let (out, paths) = masked(&text).unwrap();
        for secret in [
            key.as_str(),
            "lItErAl-kEy",
            "iSsUeR-pAsS",
            "aCmE_sK_",
            "oThEr_",
            "eNv-SeCrEt",
            "hEaDeR-sEcReT",
            "uRl-SeCrEt",
            "sEt-SeCrEt",
            "tAbLe-SeCrEt",
            "dEfAuLt-SeCrEt",
            "sUbTaBlE-SeCrEt",
        ] {
            assert!(!out.contains(secret), "{secret} in\n{out}");
        }
        // What names a secret's source, and the rest, are kept; so are comments.
        for kept in [
            "FROM_VAR = { env = \"A_KEY\" }",
            "client_secret = { file = \"/run/s\" }",
            "# rotated monthly",
            "clamp = { max = 5 }",
            "cert = \"/etc/mcpdef/tls.crt\"",
            "https://idp.example/token",
        ] {
            assert!(out.contains(kept), "{kept} not in\n{out}");
        }
        assert_eq!(
            paths,
            [
                "/gateway/tls/key",
                "/gateway/auth/issuer",
                "/gateway/inspect/secret_substrings/0",
                "/gateway/inspect/secret_substrings/1",
                "/server/0/auth/value",
                "/server/0/env/API_KEY",
                "/server/1/url",
                "/policy/0/set_args/0/set",
                "/policy/1/set_args/0/set",
                "/policy/1/set_args/1/default",
                "/policy/1/set_args/2/set",
            ]
        );
        // What does not parse says where, and nothing of the line.
        assert_eq!(
            masked("[gateway]\nkey = \"sEcReT\n").unwrap_err(),
            "the config file does not parse as TOML, at line 2"
        );
    }

    #[test]
    fn a_certificate_is_written_as_pem() {
        let pem = pem_certificate(&[7u8; 100]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let back: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(back[0].as_ref(), &[7u8; 100][..]);
    }
}
