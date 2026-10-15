// SPDX-License-Identifier: Apache-2.0
//! The `mcpdef.toml` config model + structural validation, and the mapping from
//! per-server `tools`/`deny` to the Phase-1 [`Policy`].

use crate::tls::forwarded::Cidr;
use anyhow::Context;
use mcpdef_core::wire::{SpecSetting, WireMode};
use mcpdef_policy::glob::{self, UriGlob};
use mcpdef_policy::{
    ArgEdit, ArgMatch, ArgOp, Detected, EditOp, Effect, OnError, Policy, PolicyRules, Rbac,
    ResourcePolicy, ResultEdit, Rule, ServerPolicy, Transform,
};
use mcpdef_sandbox::{EgressAllow, SandboxLimits};
use mcpdef_secrets::{ExposeSecret, SecretRef};
use mcpdef_transport::{
    ClientAuth, ClientCredentials, Credential, EgressPolicy, IdentityFiles, MinVersion, Roots,
    TlsSettings, TransportError,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Transports the config grammar accepts — all of them are served as of Phase
/// 1.5 (stdio, Streamable HTTP, and the legacy HTTP+SSE bridge).
pub const SUPPORTED_TRANSPORTS: &[&str] =
    &["stdio", "streamable-http", "sse", "wasm", "wasm-component"];

/// One rate-limit scope as `(refill_per_sec, burst_capacity)`.
pub type RateScope = (f64, f64);

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub gateway: GatewayConfig,
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerConfig>,
    /// Named, reusable allow/deny profiles (`[profile.<name>]`).
    #[serde(default, rename = "profile")]
    pub profiles: HashMap<String, ProfileConfig>,
    /// RBAC roles (`[[role]]`) — each grants tools to authenticated callers.
    #[serde(default, rename = "role")]
    pub roles: Vec<RoleConfig>,
    /// Client keys the gateway issued (`[[key]]`), made by `mcpdef keys
    /// create`: a caller that presents one as its bearer token is
    /// `key:<name>`, holding its roles, where `[gateway.auth] methods` names
    /// `key`. A reload takes them, and one removed opens nothing from then on.
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyConfig>,
    /// Policy-as-code rules (`[[policy]]`) — per-agent / per-argument allow/deny
    /// evaluated after the allowlist, first-match-wins, and the `transform`
    /// rules that rewrite a tool call's arguments before them and a result
    /// after the upstream answers.
    #[serde(default, rename = "policy")]
    pub policy: Vec<PolicyRuleConfig>,
    /// Who a caller is, beyond what its credential says (`[identity]`): the
    /// roles a client certificate's identity holds.
    #[serde(default)]
    pub identity: IdentityConfig,
}

/// `[identity]`: who a caller is, beyond what its credential says.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// `[[identity.cert_map]]`: the roles a client certificate's identity
    /// holds. A certificate no entry maps holds no role.
    #[serde(default)]
    pub cert_map: Vec<CertMapConfig>,
    /// The claim a token names its subject by (`sub`): a dotted path, as
    /// `roles_claims` are.
    #[serde(default)]
    pub subject_claim: Option<String>,
    /// The claims a token holds roles in (`["roles"]`): dotted paths, such
    /// as Keycloak's `realm_access.roles`; each a string or an array of
    /// strings.
    #[serde(default)]
    pub roles_claims: Option<Vec<String>>,
    /// `[[identity.role_map]]`: roles given to a caller whose claim holds a
    /// value, such as an Okta group or a Google hosted domain.
    #[serde(default)]
    pub role_map: Vec<RoleMapConfig>,
}

impl IdentityConfig {
    /// How a token's claims name its caller, as this table says.
    pub fn model(&self) -> mcpdef_auth::IdentityModel {
        let default = mcpdef_auth::IdentityModel::default();
        mcpdef_auth::IdentityModel {
            subject_claim: self.subject_claim.clone().unwrap_or(default.subject_claim),
            roles_claims: self.roles_claims.clone().unwrap_or(default.roles_claims),
            role_map: self
                .role_map
                .iter()
                .map(|m| mcpdef_auth::RoleMapping {
                    claim: m.claim.clone(),
                    value: m.value.clone(),
                    roles: m.roles.clone(),
                })
                .collect(),
        }
    }
}

/// One `[[identity.role_map]]` entry.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoleMapConfig {
    /// The claim, by a dotted path.
    pub claim: String,
    /// The value it holds, or one of the values an array of strings holds.
    pub value: String,
    /// The `[[role]]`s, and console roles, a caller whose claim holds it
    /// holds.
    pub roles: Vec<String>,
}

/// One `[[identity.cert_map]]` entry.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertMapConfig {
    /// The identity a certificate gives, as `[gateway.tls.client_auth]
    /// identity` reads it: exactly, or as a glob whose `*` matches any run of
    /// characters, `/` included.
    pub identity: String,
    /// The `[[role]]`s a certificate whose identity matches holds, with those
    /// of every other entry that matches.
    pub roles: Vec<String>,
}

/// `[[policy]]` — one policy-as-code rule. Match conditions (`agents` / `servers`
/// / `tools` globs and `args` predicates) are AND-ed. **Omit** a condition to
/// match anything for that dimension; an explicit empty list (`servers = []`) is
/// rejected by `validate()` — it would otherwise silently match nothing (a
/// fail-open for a `deny`).
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct PolicyRuleConfig {
    pub name: String,
    /// `"allow"`, `"deny"` or `"transform"` (case-insensitive). A transform
    /// rule rewrites a tool call's arguments (`set_args`), before the allow and
    /// deny rules judge them, and a result (`result`), a tool call's or a
    /// read's, before inspect sees it.
    pub effect: String,
    #[serde(default)]
    pub agents: Option<Vec<String>>,
    #[serde(default)]
    pub servers: Option<Vec<String>>,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// URI patterns: the rule judges a `resources/read` of a URI one of them
    /// matches. A rule with `uris` judges reads only, one with `tools` tool
    /// calls only, one with `prompts` prompt gets only, and one with none of
    /// them all three. A read has no arguments, so a rule with `args` judges
    /// no read.
    #[serde(default)]
    pub uris: Option<Vec<String>>,
    /// Prompt-name globs: the rule judges a `prompts/get` of a prompt one of
    /// them matches, and its `args` the prompt's arguments.
    #[serde(default)]
    pub prompts: Option<Vec<String>>,
    /// Argument predicates: `{ path = "name", glob = "prod-*" }` etc.
    #[serde(default)]
    pub args: Vec<ArgMatchConfig>,
    /// A transform rule's edits of the arguments, in order:
    /// `{ path = "per_page", clamp = { max = 100 } }` etc.
    #[serde(default)]
    pub set_args: Vec<ArgEditConfig>,
    /// A transform rule's answer to an edit that cannot apply: `"deny"` (the
    /// default) or `"skip"`.
    #[serde(default)]
    pub on_error: Option<String>,
    /// A transform rule's edits of a result, a tool call's or a read's, in
    /// order: `{ redact = "secrets" }`, `{ mask = "user.email" }`,
    /// `{ remove = "debug" }`, `{ truncate = 65536 }`.
    #[serde(default)]
    pub result: Vec<ResultEditConfig>,
}

impl PolicyRuleConfig {
    fn is_transform(&self) -> bool {
        self.effect.eq_ignore_ascii_case("transform")
    }

    /// What becomes of a call when this transform rule cannot apply.
    fn on_error(&self) -> Result<OnError, String> {
        match self.on_error.as_deref() {
            None => Ok(OnError::Deny),
            Some(s) if s.eq_ignore_ascii_case("deny") => Ok(OnError::Deny),
            Some(s) if s.eq_ignore_ascii_case("skip") => Ok(OnError::Skip),
            Some(other) => Err(format!("has `on_error` '{other}' (must be deny/skip)")),
        }
    }
}

/// One edit in a transform rule's `set_args`: a dotted `path` into the
/// arguments and **exactly one** of `set`, `default`, `remove` and `clamp`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArgEditConfig {
    pub path: String,
    /// The value to put at `path`, whatever is there.
    #[serde(default)]
    pub set: Option<toml::Value>,
    /// The value to put at `path` when nothing (or null) is there.
    #[serde(default)]
    pub default: Option<toml::Value>,
    /// `true` takes `path` out.
    #[serde(default)]
    pub remove: Option<bool>,
    /// Bounds for the number at `path`.
    #[serde(default)]
    pub clamp: Option<ClampConfig>,
}

/// `clamp = { min = …, max = … }`: at least one of them, and `min` no higher
/// than `max`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClampConfig {
    #[serde(default)]
    pub min: Option<toml::Value>,
    #[serde(default)]
    pub max: Option<toml::Value>,
}

impl ArgEditConfig {
    /// The edit this entry makes, or what is wrong with it.
    fn to_arg_edit(&self) -> Result<ArgEdit, String> {
        if self.path.split('.').any(str::is_empty) {
            return Err("needs a path of keys joined by single dots".into());
        }
        let ops = [
            self.set.is_some(),
            self.default.is_some(),
            self.remove == Some(true),
            self.clamp.is_some(),
        ]
        .iter()
        .filter(|op| **op)
        .count();
        if ops != 1 {
            return Err(format!(
                "must name exactly one of set/default/remove/clamp (found {ops})"
            ));
        }
        let op = if let Some(value) = &self.set {
            EditOp::Set(json_value(value).map_err(|why| format!("`set` {why}"))?)
        } else if let Some(value) = &self.default {
            EditOp::Default(json_value(value).map_err(|why| format!("`default` {why}"))?)
        } else if let Some(clamp) = &self.clamp {
            clamp.to_op()?
        } else {
            EditOp::Remove
        };
        Ok(ArgEdit {
            path: self.path.clone(),
            op,
        })
    }
}

/// One edit in a transform rule's `result`: **exactly one** of `redact`,
/// `mask`, `remove` and `truncate`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResultEditConfig {
    /// `"secrets"`: every secret the inspect pack's secret rules, and
    /// `[gateway.inspect] secret_substrings`, find in a string of the result.
    #[serde(default)]
    pub redact: Option<String>,
    /// A dotted path, in the JSON the result carries, to a string to mask;
    /// `*` takes every element or value.
    #[serde(default)]
    pub mask: Option<String>,
    /// A dotted path, in the JSON the result carries, to a key to take out.
    #[serde(default)]
    pub remove: Option<String>,
    /// The most bytes each text block of the result keeps.
    #[serde(default)]
    pub truncate: Option<i64>,
}

impl ResultEditConfig {
    /// The edit this entry makes, or what is wrong with it.
    fn to_result_edit(&self) -> Result<ResultEdit, String> {
        let ops = [
            self.redact.is_some(),
            self.mask.is_some(),
            self.remove.is_some(),
            self.truncate.is_some(),
        ]
        .iter()
        .filter(|op| **op)
        .count();
        if ops != 1 {
            return Err(format!(
                "must name exactly one of redact/mask/remove/truncate (found {ops})"
            ));
        }
        let path = |key: &str, path: &str, ends_any: bool| {
            let steps: Vec<&str> = path.split('.').collect();
            if steps.iter().any(|step| step.is_empty()) {
                return Err(format!(
                    "`{key}` needs a path of keys joined by single dots"
                ));
            }
            if !ends_any && steps.last() == Some(&"*") {
                return Err(format!("`{key}` must end in a key, not `*`"));
            }
            Ok(path.to_string())
        };
        if let Some(what) = &self.redact {
            match what.eq_ignore_ascii_case("secrets") {
                true => Ok(ResultEdit::Redact),
                false => Err(format!("`redact` is '{what}' (must be \"secrets\")")),
            }
        } else if let Some(mask) = &self.mask {
            path("mask", mask, true).map(ResultEdit::Mask)
        } else if let Some(remove) = &self.remove {
            path("remove", remove, false).map(ResultEdit::Remove)
        } else {
            let bytes = self.truncate.unwrap_or_default();
            usize::try_from(bytes)
                .ok()
                .filter(|bytes| *bytes > 0)
                .map(ResultEdit::Truncate)
                .ok_or_else(|| {
                    format!("`truncate` is {bytes} (must be a number of bytes, 1 or more)")
                })
        }
    }
}

impl ClampConfig {
    fn to_op(&self) -> Result<EditOp, String> {
        if self.min.is_none() && self.max.is_none() {
            return Err("`clamp` names neither `min` nor `max`".into());
        }
        let bound = |name: &str, value: &Option<toml::Value>| {
            value
                .as_ref()
                .map(|v| json_number(v).map_err(|why| format!("`clamp` {name} {why}")))
                .transpose()
        };
        let min = bound("min", &self.min)?;
        let max = bound("max", &self.max)?;
        if let (Some(min), Some(max)) = (&min, &max) {
            let above = match (min.as_i64(), max.as_i64()) {
                (Some(min), Some(max)) => min > max,
                _ => min.as_f64() > max.as_f64(),
            };
            if above {
                return Err("`clamp` has its `min` above its `max`".into());
            }
        }
        Ok(EditOp::Clamp { min, max })
    }
}

/// A TOML value as the JSON value an edit writes. A date has no JSON form,
/// and JSON has no number that is not finite.
fn json_value(value: &toml::Value) -> Result<serde_json::Value, String> {
    Ok(match value {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::from(*i),
        toml::Value::Float(_) => serde_json::Value::Number(json_number(value)?),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(_) => {
            return Err("holds a date, which JSON has no form for: quote it".into())
        }
        toml::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(json_value).collect::<Result<_, _>>()?)
        }
        toml::Value::Table(table) => serde_json::Value::Object(
            table
                .iter()
                .map(|(key, v)| Ok((key.clone(), json_value(v)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn json_number(value: &toml::Value) -> Result<serde_json::Number, String> {
    match value {
        toml::Value::Integer(i) => Ok((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .ok_or_else(|| "holds a number that is not finite".to_string()),
        _ => Err("is not a number".into()),
    }
}

/// One argument predicate in a `[[policy]]` rule. Exactly one of `equals` /
/// `glob` / `contains` / `exists` selects the operator.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ArgMatchConfig {
    pub path: String,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub exists: Option<bool>,
}

impl ArgMatchConfig {
    /// Resolve the configured operator (precedence equals → glob → contains →
    /// exists). `None` if the predicate names no operator (rejected by `validate`).
    fn to_arg_match(&self) -> Option<ArgMatch> {
        let op = if let Some(v) = &self.equals {
            ArgOp::Equals(v.clone())
        } else if let Some(v) = &self.glob {
            ArgOp::Glob(v.clone())
        } else if let Some(v) = &self.contains {
            ArgOp::Contains(v.clone())
        } else if self.exists == Some(true) {
            ArgOp::Exists
        } else {
            return None;
        };
        Some(ArgMatch {
            path: self.path.clone(),
            op,
        })
    }
}

/// `[[key]]`: a client key the gateway issued, by its SHA-256; the config
/// never holds the key.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Its caller's name: the ledger records `key:<name>`.
    pub name: String,
    /// The key's SHA-256, in hex, as `mcpdef keys create` prints it.
    pub sha256: String,
    /// The `[[role]]`s its caller holds.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl KeyConfig {
    /// The digest `sha256` writes, if it writes one.
    pub fn digest(&self) -> Option<[u8; 32]> {
        hex::decode(self.sha256.trim()).ok()?.try_into().ok()
    }
}

impl Config {
    /// The client keys `[[key]]` lists, as the gateway takes them.
    pub fn issued_keys(&self) -> Vec<crate::gateway::IssuedKey> {
        self.keys
            .iter()
            .filter_map(|key| {
                Some(crate::gateway::IssuedKey {
                    name: key.name.clone(),
                    digest: key.digest()?,
                    roles: key.roles.clone(),
                })
            })
            .collect()
    }
}

/// `[[role]]` — an RBAC role: a set of `"server:tool"` glob grants. A caller
/// holds the role when its `name` appears among the token's scopes or `roles`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RoleConfig {
    pub name: String,
    /// Grants as `"server-glob:tool-glob"` (a bare `"tool"` means any server).
    #[serde(default)]
    pub grants: Vec<String>,
    /// Resource-read grants as `"server-glob:uri-pattern"`, such as
    /// `"fs:file:///srv/docs/**"`. The server part is required: a URI holds a
    /// `:` itself, so the grant splits at its first.
    #[serde(default)]
    pub resource_grants: Vec<String>,
    /// Prompt grants as `"server-glob:prompt-glob"`; a bare `"prompt-glob"`
    /// grants it on any server, as in `grants`.
    #[serde(default)]
    pub prompt_grants: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct GatewayConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_audit")]
    pub audit: String,
    /// Reserved for the Phase-3 policy directory; unused in Phase 1.
    #[serde(default)]
    pub policy: Option<String>,
    /// Tool-def pin store path. When set, MCPdef pins each upstream tool's
    /// definition (trust-on-first-use) and denies + audits a `rug-pull` if a
    /// later definition drifts. Unset = pinning off.
    #[serde(default)]
    pub pins: Option<String>,
    /// The active named profile (`[profile.<name>]`) layered over every server,
    /// scoping the whole tool surface an agent sees. `None` = no extra filter.
    /// Overridable at launch with `mcpdef run --profile <name>`.
    #[serde(default)]
    pub profile: Option<String>,
    /// The SSRF/egress guard applied to HTTP upstreams (`[gateway.egress]`).
    #[serde(default)]
    pub egress: EgressConfig,
    /// Token-bucket rate limits for `tools/call` (`[gateway.rate_limit]`).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Per-call upstream response timeout (ms). A wedged upstream that does not
    /// reply within this bound is failed (and audited) instead of hanging the
    /// gateway. `0` / unset = no timeout.
    #[serde(default)]
    pub upstream_timeout_ms: Option<u64>,
    /// Extra Origins allowed on the downstream HTTP listener (`mcpdef run --http`)
    /// beyond loopback (`localhost` / `127.0.0.1` / `::1`, any port — always
    /// allowed). A browser cross-site `Origin` not in this set is rejected with
    /// `403` (DNS-rebinding defense).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Max concurrent in-flight HTTP requests on the listener; excess is shed with
    /// `503` + `Retry-After` (load-shedding, ARCHITECTURE §5b). Unset = unlimited.
    #[serde(default)]
    pub max_inflight: Option<usize>,
    /// What the HTTP listener requires of every request (`[gateway.auth]`),
    /// when `enabled`: a valid bearer token (OAuth 2.1, as a Resource Server),
    /// a client certificate, or both.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Inline injection / secret-exfil scanning of tool descriptions + results
    /// (`[gateway.inspect]`).
    #[serde(default)]
    pub inspect: InspectConfig,
    /// OSS read-only admin / observability server (`[gateway.admin]`).
    #[serde(default)]
    pub admin: AdminConfig,
    /// Which MCP wire models the downstream listener serves: `legacy`
    /// (2025-11-25, the default), `modern` (the stateless 2026-07-28), or
    /// `dual`. Defaulting to `legacy` means upgrading MCPdef never changes what
    /// an existing deployment accepts — for an in-path enforcer, a surprise in
    /// what the wire takes is a surprise in what gets governed.
    #[serde(default)]
    pub wire: WireMode,
    /// Reload when the config, or a file it names, changes: its content is
    /// hashed every 30 s. A reload is also a `SIGHUP` away, with or without
    /// this. Off by default.
    #[serde(default)]
    pub watch_config: bool,
    /// The TLS profile of every HTTPS connection to an upstream, and of the
    /// gateway's own fetches, a `jwks_uri` among them
    /// (`[gateway.upstream_tls]`). A server's `[server.tls]` goes over it.
    #[serde(default)]
    pub upstream_tls: TlsConfig,
    /// Every warning is an error ([`Config::warnings`]): a secret written in
    /// the config, a secret file others can read, a certificate not checked,
    /// or credentials sent in the clear. `mcpdef validate` refuses such a
    /// config, the gateway does not start with it, and a reload to it is
    /// refused. And an upstream that does not open at startup fails the
    /// start, where it would be retried in the background. Off by default.
    #[serde(default)]
    pub strict: bool,
    /// How `tools/list` names each tool: `off` (the default) as its server
    /// names it, each name once, or `prefix` as `<prefix>__<name>`.
    #[serde(default)]
    pub tool_namespace: ToolNamespace,
    /// TLS on the MCP listener (`[gateway.tls]`): `off` (the default), a
    /// certificate from `files`, or one a local CA of MCPdef's own issues
    /// (`self-signed`). The admin listener serves the same, unless
    /// `[gateway.admin.tls]` says otherwise.
    #[serde(default)]
    pub tls: ListenerTlsConfig,
    /// The proxy in front of the MCP listener that terminates its clients'
    /// TLS and forwards their certificates (`[gateway.trusted_proxy]`), as
    /// Envoy or Istio does. Unset: no proxy is trusted, and no forwarded
    /// certificate is read.
    #[serde(default)]
    pub trusted_proxy: Option<TrustedProxyConfig>,
    /// Where MCPdef keeps what it makes for itself: under `tls/`, the local
    /// CA and the certificate it issues the listeners, the keys readable by
    /// MCPdef's own user alone.
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
}

/// `[gateway.tls]`, or `[gateway.admin.tls]`: TLS on one of MCPdef's own
/// listeners.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsConfig {
    /// `off` (the default): plain HTTP. `files`: the certificate and key
    /// `cert` and `key` name, as cert-manager or certbot writes them.
    /// `self-signed`: a certificate a local CA of MCPdef's own issues, the CA
    /// made once and kept under `[gateway] state_dir`.
    #[serde(default)]
    pub mode: ListenerTlsMode,
    /// `self-signed`: what the certificate is for besides `localhost`,
    /// `127.0.0.1`, `::1` and the address the listener binds to, each a DNS
    /// name or an IP address. The local CA vouches for the names it was made
    /// with and no others, so a name added after it needs a new CA.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// `files`: the certificate, then any intermediates it needs, as PEM.
    #[serde(default)]
    pub cert: Option<String>,
    /// `files`: its key, unencrypted, as PEM: `{ file = "/path/to/key.pem" }`,
    /// `{ env = "NAME" }`, `{ exec = ["command", …] }`, or a string that is the
    /// key itself.
    #[serde(default)]
    pub key: Option<SecretRef>,
    /// mTLS (`[gateway.tls.client_auth]`): what the listener asks of a
    /// client's certificate. Nothing, by default.
    #[serde(default)]
    pub client_auth: ClientAuthConfig,
}

/// `[gateway.tls.client_auth]`, or `[gateway.admin.tls.client_auth]`: a
/// client's certificate, checked at the handshake, and read as who the
/// client is.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    /// `off` (the default): no certificate asked for. `optional`: one asked
    /// for, and checked when the client presents it. `required`: a client
    /// that presents none is refused at the handshake.
    #[serde(default)]
    pub mode: ClientAuthMode,
    /// Files of the CA certificates a client's certificate has to chain to,
    /// as PEM. With `identity = "spiffe"`, the trust bundle, as spiffe-helper
    /// writes it.
    #[serde(default)]
    pub ca: Vec<String>,
    /// Files of CRLs, as PEM. A certificate they revoke is refused, and so is
    /// one whose status none of them tells: every CA in a client's chain
    /// needs its CRL here.
    #[serde(default)]
    pub crl: Vec<String>,
    /// Which of a certificate's names is its client's identity: `spiffe` (its
    /// one SPIFFE ID), `san-dns` (its first DNS name), `san-email` (its first
    /// email address) or `subject-cn` (its subject's common name).
    #[serde(default)]
    pub identity: Option<CertIdentity>,
    /// `spiffe` only: the trust domains a SPIFFE ID may name.
    #[serde(default)]
    pub trust_domains: Vec<String>,
}

/// `[gateway.tls.client_auth] mode`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuthMode {
    /// No certificate asked for.
    #[default]
    Off,
    /// A certificate asked for, and checked when one is presented.
    Optional,
    /// A certificate asked for, and the handshake refused without one.
    Required,
}

impl ClientAuthMode {
    /// As the config spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthMode::Off => "off",
            ClientAuthMode::Optional => "optional",
            ClientAuthMode::Required => "required",
        }
    }

    /// Whether the listener asks for a certificate.
    pub fn is_on(self) -> bool {
        self != ClientAuthMode::Off
    }
}

/// `[gateway.tls.client_auth] identity`: which of a certificate's names is
/// its client's identity.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CertIdentity {
    /// Its one SPIFFE ID, a `spiffe://` URI, under the X509-SVID rules.
    Spiffe,
    /// Its first DNS name.
    SanDns,
    /// Its first email address.
    SanEmail,
    /// Its subject's common name.
    SubjectCn,
}

impl CertIdentity {
    /// As the config spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            CertIdentity::Spiffe => "spiffe",
            CertIdentity::SanDns => "san-dns",
            CertIdentity::SanEmail => "san-email",
            CertIdentity::SubjectCn => "subject-cn",
        }
    }
}

impl ClientAuthConfig {
    /// Every file this table names.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.ca.iter().chain(&self.crl).map(String::as_str)
    }

    /// What is wrong with this table, `table` naming it in each message: a
    /// key its mode does not take, what `optional` and `required` need and
    /// lack, and a CA or CRL file that does not read. `listener` names its
    /// listener's table, whose mode is `tls`; a listener that is `proxied`,
    /// behind a `[gateway.trusted_proxy]` that forwards its clients'
    /// certificates, needs no TLS of its own.
    fn problems(
        &self,
        table: &str,
        listener: &str,
        tls: ListenerTlsMode,
        proxied: bool,
    ) -> Vec<String> {
        let mut problems = Vec::new();
        let mode = self.mode.as_str();
        if !self.mode.is_on() {
            for (key, set) in [
                ("ca", !self.ca.is_empty()),
                ("crl", !self.crl.is_empty()),
                ("identity", self.identity.is_some()),
                ("trust_domains", !self.trust_domains.is_empty()),
            ] {
                if set {
                    problems.push(format!(
                        "{table} has `{key}`, which only mode = \"optional\" or \"required\" \
                         takes, and its mode is \"off\""
                    ));
                }
            }
            return problems;
        }
        if !tls.is_on() && !proxied {
            problems.push(format!(
                "{table} mode = \"{mode}\" needs TLS on its listener, and {listener} mode is \
                 \"off\""
            ));
        }
        if self.ca.is_empty() {
            problems.push(format!(
                "{table} mode = \"{mode}\" needs `ca`: the CA certificates a client's \
                 certificate has to chain to"
            ));
        }
        match self.identity {
            None => problems.push(format!(
                "{table} mode = \"{mode}\" needs `identity`: which of a certificate's names is \
                 its client's, \"spiffe\", \"san-dns\", \"san-email\" or \"subject-cn\""
            )),
            Some(CertIdentity::Spiffe) => {
                if self.trust_domains.is_empty() {
                    problems.push(format!(
                        "{table} identity = \"spiffe\" needs `trust_domains`: the trust \
                         domains a SPIFFE ID may name"
                    ));
                }
                for domain in &self.trust_domains {
                    if let Some(why) = crate::tls::client_auth::trust_domain_problem(domain) {
                        problems.push(format!("{table} trust_domains entry {domain:?} {why}"));
                    }
                }
            }
            Some(identity) => {
                if !self.trust_domains.is_empty() {
                    problems.push(format!(
                        "{table} has `trust_domains`, which only identity = \"spiffe\" takes, \
                         and its identity is \"{}\"",
                        identity.as_str()
                    ));
                }
            }
        }
        if !self.ca.is_empty() {
            let paths = |files: &[String]| files.iter().map(PathBuf::from).collect::<Vec<_>>();
            if let Err(e) = mcpdef_transport::read_client_trust(&paths(&self.ca), &paths(&self.crl))
            {
                let e = match e {
                    TransportError::Tls(e) => e,
                    e => e.to_string(),
                };
                problems.push(format!("{table} {e}"));
            }
        }
        problems
    }
}

/// `[gateway.trusted_proxy]`: a proxy in front of the MCP listener that
/// terminates its clients' TLS, as Envoy or Istio does, and forwards
/// each client's certificate in a header. The header is read on a connection
/// from the proxy's addresses alone, and the certificate checked and read as
/// `[gateway.tls.client_auth]` says.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxyConfig {
    /// The proxy's addresses: ranges such as `10.0.0.0/8`, or addresses
    /// alone. From any other, the header is not read.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// The header the proxy forwards the client's certificate in:
    /// `client-cert`, RFC 9440's, its chain in `client-cert-chain` (the
    /// default); or `x-forwarded-client-cert`, the XFCC of Envoy and Istio.
    #[serde(default)]
    pub client_cert_header: ClientCertHeader,
}

/// `[gateway.trusted_proxy] client_cert_header`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClientCertHeader {
    /// RFC 9440's `Client-Cert`, with `Client-Cert-Chain`.
    #[default]
    ClientCert,
    /// Envoy's and Istio's `x-forwarded-client-cert`.
    XForwardedClientCert,
}

impl ClientCertHeader {
    /// As the config spells it, which is the header's name.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientCertHeader::ClientCert => "client-cert",
            ClientCertHeader::XForwardedClientCert => "x-forwarded-client-cert",
        }
    }
}

impl TrustedProxyConfig {
    /// What is wrong with this table: no `cidrs`, an entry that is not a
    /// range, and no `[gateway.tls.client_auth]` to check what the proxy
    /// forwards.
    fn problems(&self, client_auth: &ClientAuthConfig) -> Vec<String> {
        let mut problems = Vec::new();
        if self.cidrs.is_empty() {
            problems.push(
                "[gateway.trusted_proxy] needs `cidrs`: the addresses of the proxy in front of \
                 the listener"
                    .to_string(),
            );
        }
        for cidr in &self.cidrs {
            if let Err(why) = Cidr::parse(cidr) {
                problems.push(format!(
                    "[gateway.trusted_proxy] cidrs entry {cidr:?} {why}"
                ));
            }
        }
        if !client_auth.mode.is_on() {
            problems.push(
                "[gateway.trusted_proxy] reads the client certificates the proxy forwards, and \
                 [gateway.tls.client_auth] mode is \"off\": set it, to say how they are \
                 checked and read"
                    .to_string(),
            );
        }
        problems
    }
}

/// `[gateway.tls] mode`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerTlsMode {
    /// Plain HTTP.
    #[default]
    Off,
    /// A certificate and key from files.
    Files,
    /// A certificate the local CA issues.
    SelfSigned,
}

impl ListenerTlsMode {
    /// As the config spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ListenerTlsMode::Off => "off",
            ListenerTlsMode::Files => "files",
            ListenerTlsMode::SelfSigned => "self-signed",
        }
    }

    /// Whether the listener speaks TLS.
    pub fn is_on(self) -> bool {
        self != ListenerTlsMode::Off
    }
}

impl ListenerTlsConfig {
    /// The certificate and key `files` mode serves, when both are set.
    pub fn served_files(&self) -> Option<IdentityFiles> {
        Some(IdentityFiles {
            cert: self.cert.as_ref()?.into(),
            key: self.key.clone()?,
        })
    }

    /// Every file this table names.
    pub fn files(&self) -> Vec<&str> {
        let key = self
            .key
            .iter()
            .filter_map(|k| k.path().and_then(Path::to_str));
        self.cert
            .as_deref()
            .into_iter()
            .chain(key)
            .chain(self.client_auth.files())
            .collect()
    }

    /// What is wrong with this table, `table` naming it in each message:
    /// a key its mode does not take, a hostname no certificate can carry,
    /// for `files`, a certificate or key that is missing, or that does not
    /// read as the transport reads a client's, and what is wrong with its
    /// `client_auth`, on a listener `proxied` or not (see
    /// [`ClientAuthConfig::problems`]).
    fn problems(&self, table: &str, proxied: bool) -> Vec<String> {
        let mut problems = Vec::new();
        let mode = self.mode.as_str();
        let files = self.mode == ListenerTlsMode::Files;
        for (key, set) in [("cert", self.cert.is_some()), ("key", self.key.is_some())] {
            if set && !files {
                problems.push(format!(
                    "{table} has `{key}`, which only mode = \"files\" takes, and its mode is \
                     \"{mode}\""
                ));
            }
        }
        if !self.hostnames.is_empty() && self.mode != ListenerTlsMode::SelfSigned {
            problems.push(format!(
                "{table} has `hostnames`, which only mode = \"self-signed\" takes, and its mode \
                 is \"{mode}\": a certificate from files is for the names it was issued for"
            ));
        }
        if self.mode == ListenerTlsMode::SelfSigned {
            for name in &self.hostnames {
                if let Some(why) = hostname_problem(name) {
                    problems.push(format!("{table} hostnames entry {name:?} {why}"));
                }
            }
        }
        if files {
            match self.served_files() {
                None => problems.push(format!(
                    "{table} mode = \"files\" needs `cert` and `key`: the certificate to serve, \
                     and its key"
                )),
                Some(files) => {
                    if let Err(e) = mcpdef_transport::read_served(&files) {
                        let e = match e {
                            TransportError::Tls(e) => e,
                            e => e.to_string(),
                        };
                        problems.push(format!("{table} {e}"));
                    }
                }
            }
        }
        let client_auth = format!("{}.client_auth]", table.trim_end_matches(']'));
        problems.extend(
            self.client_auth
                .problems(&client_auth, table, self.mode, proxied),
        );
        problems
    }
}

/// Why `name` cannot be a certificate's name, if it cannot: a `hostnames`
/// entry is a DNS name or an IP address.
fn hostname_problem(name: &str) -> Option<String> {
    if name.parse::<IpAddr>().is_ok() {
        return None;
    }
    if name.contains('*') {
        return Some("is a wildcard: name each host".to_string());
    }
    match rustls::pki_types::DnsName::try_from(name) {
        Ok(_) if !name.ends_with('.') => None,
        _ => Some("is neither a DNS name nor an IP address".to_string()),
    }
}

/// `[gateway] tool_namespace`: how `tools/list` names each tool.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolNamespace {
    /// As its server names it. A name two servers offer is listed once, from
    /// the first, and called there; a warning says so, an error under
    /// `strict`.
    #[default]
    Off,
    /// `<prefix>__<name>`, with each server's `prefix`, its id by default.
    Prefix,
}

/// `[gateway.admin]` — the admin listener: the console, its API, and
/// Prometheus `/metrics`. Off by default; a separate port from the MCP data
/// path. With nothing to sign its callers in, a loopback listener is open to
/// this machine, and any other is refused unless `allow_unauthenticated`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// TLS on the admin listener (`[gateway.admin.tls]`), when it is not
    /// `[gateway.tls]`'s: `mode = "off"` for plain HTTP beside an MCP listener
    /// on TLS, say.
    #[serde(default)]
    pub tls: Option<ListenerTlsConfig>,
    /// The console's URL as its users reach it, `https://host[:port]`: the
    /// origin a browser's request must come from, and a host name a request
    /// may name.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Host names a request may name besides an IP literal, `localhost`,
    /// `listen`'s host and `public_url`'s: a Service's name a scraper uses,
    /// say. Any other is refused, so that a page cannot rebind its own name
    /// to this listener.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Serve a listener other machines can reach with nothing to sign its
    /// callers in: for a proxy in front that authenticates them. Every
    /// caller may then do anything.
    #[serde(default)]
    pub allow_unauthenticated: bool,
    /// `[gateway.admin.session]`: the key the console's sessions are sealed
    /// with.
    #[serde(default)]
    pub session: Option<SessionConfig>,
    /// `[gateway.admin.oidc]`: the identity provider the console signs people
    /// in at.
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// `[gateway.admin.break_glass]`: a token for when the provider cannot
    /// sign anyone in.
    #[serde(default)]
    pub break_glass: Option<BreakGlassConfig>,
}

/// `[gateway.admin.oidc]`: the console signs people in at an OpenID Connect
/// provider, as a confidential client using the authorization code flow
/// with PKCE.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The provider's issuer: the `iss` its tokens carry, exactly, and where
    /// its discovery document is (`<issuer>/.well-known/openid-configuration`).
    pub issuer: String,
    pub client_id: String,
    /// The client's secret, as a secret reference: `{ env = … }`, say.
    #[serde(default)]
    pub client_secret: Option<SecretRef>,
    /// The scopes asked for besides `openid`: `["profile", "email"]` unless
    /// set.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Read the userinfo endpoint too, adding its claims to the ID token's:
    /// for a provider that puts groups there alone. Its failure fails the
    /// sign-in.
    #[serde(default)]
    pub userinfo: bool,
    /// How the client proves itself at the token endpoint:
    /// `client_secret_basic` (the default) or `client_secret_post`.
    #[serde(default)]
    pub client_auth: Option<String>,
    /// The audience of the tokens the provider issues for the admin API, as
    /// automation calls it with a bearer token: never the MCP listener's
    /// `resource`, nor the client's ID tokens'. Unset, the admin API takes
    /// no token of the provider's.
    #[serde(default)]
    pub api_audience: Option<String>,
}

/// `[gateway.admin.break_glass]`: one token that holds `console:admin`, for
/// when the identity provider signs no one in. Every request made with it is
/// recorded.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassConfig {
    /// The token's SHA-256, in hex, as `mcpdef admin token` prints it: the
    /// config never holds the token.
    pub token_sha256: String,
}

impl BreakGlassConfig {
    /// The digest `token_sha256` writes, if it writes one.
    pub fn digest(&self) -> Option<[u8; 32]> {
        hex::decode(self.token_sha256.trim()).ok()?.try_into().ok()
    }
}

impl OidcConfig {
    /// The scopes asked for: `openid`, then the rest, each once.
    pub fn scopes(&self) -> Vec<String> {
        let rest = self
            .scopes
            .clone()
            .unwrap_or_else(|| vec!["profile".into(), "email".into()]);
        let mut all = vec!["openid".to_string()];
        for scope in rest {
            if !all.contains(&scope) {
                all.push(scope);
            }
        }
        all
    }

    /// Whether the client sends its secret in the body rather than as basic
    /// auth.
    pub fn posts_secret(&self) -> bool {
        self.client_auth.as_deref() == Some("client_secret_post")
    }
}

/// `[gateway.admin.session]`.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// 32 bytes, in base64 or hex (`openssl rand -base64 32`). Without it,
    /// the key in `<state_dir>/session.key`, made the first time.
    #[serde(default)]
    pub key: Option<SecretRef>,
    /// The key before `key`, which opens sessions it sealed: a rotation
    /// signs no one out.
    #[serde(default)]
    pub previous_key: Option<SecretRef>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        AdminConfig {
            enabled: false,
            listen: default_admin_listen(),
            tls: None,
            public_url: None,
            hosts: Vec::new(),
            allow_unauthenticated: false,
            session: None,
            oidc: None,
            break_glass: None,
        }
    }
}

impl AdminConfig {
    /// Whether the admin listener takes connections from this machine alone:
    /// `listen` binds to a loopback address, or to `localhost`.
    pub fn listens_locally(&self) -> bool {
        binds_locally(&self.listen)
    }
}

/// The roles the console knows, which a role map may give besides the
/// `[[role]]`s the MCP listener judges.
pub const CONSOLE_ROLES: [&str; 3] = ["console:viewer", "console:operator", "console:admin"];

fn default_admin_listen() -> String {
    "127.0.0.1:7879".to_string()
}

/// `[gateway.inspect]` — inline injection / secret-exfil scanning. `mode` is
/// `off` (default), `warn` (log findings only), or `enforce` (hide poisoned tools
/// and refuse results that leak a secret / carry injected instructions).
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct InspectConfig {
    #[serde(default)]
    pub mode: Option<String>,
    /// Operator-defined prompt-injection phrases, matched case-insensitively on
    /// top of the built-in pack (e.g. org-specific instruction-override wording).
    #[serde(default)]
    pub injection_phrases: Vec<String>,
    /// Operator-defined secret substrings, matched case-sensitively (e.g. an
    /// internal credential prefix like `acme_sk_` the built-in pack won't know).
    #[serde(default)]
    pub secret_substrings: Vec<String>,
}

/// `[gateway.auth]` — the OAuth 2.1 Resource Server config. When `enabled`, the
/// listener validates a bearer JWT per request against the JWKS (inline `jwks` or
/// fetched `jwks_uri`), checking `aud == resource` and `iss == issuer`.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The authorization server's `iss`.
    #[serde(default)]
    pub issuer: Option<String>,
    /// This gateway's canonical URI — the audience tokens must carry (RFC 8707).
    #[serde(default)]
    pub resource: Option<String>,
    /// The offline / pinned-keys path: either inline JWKS JSON (a value starting
    /// with `{`) or a path to a JWKS JSON file. Preferred over `jwks_uri` for a
    /// hardened deploy — no startup network dependency, keys are pinned.
    #[serde(default)]
    pub jwks: Option<String>,
    /// A `jwks_uri` to fetch the JWKS from at startup (egress-guarded).
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Find `jwks_uri` from the issuer's metadata, as it starts: OpenID
    /// Connect Discovery's document, then RFC 8414's.
    #[serde(default)]
    pub discovery: bool,
    /// Audiences a token may carry besides `resource`: an API the identity
    /// provider names its own way, as Entra's `api://<app id>`.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// How a caller proves who it is: `bearer`, an access token (the
    /// default); `mtls`, a client certificate, as `[gateway.tls.client_auth]`
    /// checks it; or both.
    #[serde(default)]
    pub methods: Option<Vec<AuthMethod>>,
    /// With both methods: `any` (the default), either credential will do;
    /// `all`, a request needs both.
    #[serde(default)]
    pub require: Option<AuthRequire>,
}

/// One of `[gateway.auth] methods`.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// An OAuth 2.1 access token, in `Authorization: Bearer`.
    Bearer,
    /// A client certificate.
    Mtls,
    /// A client key the gateway issued (`[[key]]`), in `Authorization:
    /// Bearer`.
    Key,
}

impl AuthMethod {
    /// As the config spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Bearer => "bearer",
            AuthMethod::Mtls => "mtls",
            AuthMethod::Key => "key",
        }
    }
}

/// `[gateway.auth] require`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthRequire {
    /// A credential of any of the methods.
    #[default]
    Any,
    /// A credential of each of them.
    All,
}

impl AuthConfig {
    /// The methods a caller may prove itself by: `methods`, or `bearer`
    /// alone when it is unset.
    pub fn methods(&self) -> &[AuthMethod] {
        self.methods.as_deref().unwrap_or(&[AuthMethod::Bearer])
    }

    /// Whether `method` is one of them.
    pub fn takes(&self, method: AuthMethod) -> bool {
        self.methods().contains(&method)
    }

    /// The JWKS file `jwks` names, unless it holds the JWKS inline.
    pub fn jwks_file(&self) -> Option<&str> {
        self.jwks
            .as_deref()
            .filter(|jwks| !jwks.trim_start().starts_with('{'))
    }
}

impl GatewayConfig {
    /// The effective egress policy for HTTP upstreams.
    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy {
            allow_private_network: self.egress.allow_private,
            require_https_public: self.egress.require_https,
        }
    }

    /// Build the inline-inspection scanner from `[gateway.inspect] mode`, or `None`
    /// when off (the default). An unrecognized mode is rejected by `validate()`, so
    /// here it falls back to off.
    pub fn inspect_scanner(&self) -> Option<mcpdef_inspect::Scanner> {
        let mode = self.inspect.mode.as_deref().unwrap_or("off");
        mcpdef_inspect::Mode::parse(mode)
            .and_then(mcpdef_inspect::Scanner::new)
            .map(|s| {
                s.with_extra_injection(self.inspect.injection_phrases.clone())
                    .with_extra_secrets(self.inspect.secret_substrings.clone())
            })
    }

    /// `(per_tool, global)` rate-limit settings as `(refill_per_sec, burst)`
    /// tuples for the limiter; either is `None` when that scope is unset.
    pub fn rate_limit_settings(&self) -> (Option<RateScope>, Option<RateScope>) {
        let per_tool = self
            .rate_limit
            .per_tool_per_sec
            .map(|r| (r, self.rate_limit.per_tool_burst.unwrap_or(r)));
        let global = self
            .rate_limit
            .global_per_sec
            .map(|r| (r, self.rate_limit.global_burst.unwrap_or(r)));
        (per_tool, global)
    }

    /// The per-call upstream timeout, if configured (> 0).
    pub fn upstream_timeout(&self) -> Option<std::time::Duration> {
        self.upstream_timeout_ms
            .filter(|&ms| ms > 0)
            .map(std::time::Duration::from_millis)
    }

    /// The TLS settings of the gateway's own fetches, such as a `jwks_uri`:
    /// `[gateway.upstream_tls]`.
    pub fn fetch_tls(&self) -> TlsSettings {
        self.upstream_tls.settings()
    }

    /// The admin listener's TLS: `[gateway.admin.tls]`, or `[gateway.tls]`
    /// when it sets none.
    pub fn admin_tls(&self) -> &ListenerTlsConfig {
        self.admin.tls.as_ref().unwrap_or(&self.tls)
    }

    /// Whether something signs the admin listener's callers in: a client
    /// certificate it requires. With nothing, a loopback listener is open to
    /// this machine, and any other is refused unless `allow_unauthenticated`
    /// says a proxy in front authenticates.
    pub fn admin_signs_in(&self) -> bool {
        self.admin_requires_certificates()
            || self.admin.oidc.is_some()
            || self.admin.break_glass.is_some()
    }

    /// Whether the admin listener requires a client certificate of each
    /// caller.
    pub fn admin_requires_certificates(&self) -> bool {
        let tls = self.admin_tls();
        tls.mode.is_on() && tls.client_auth.mode == ClientAuthMode::Required
    }

    /// What is wrong with `[gateway.admin]`: a `public_url` that is no
    /// origin, or one in the clear off this machine; an empty or malformed
    /// `hosts` entry; and a listener other machines reach with nothing to
    /// sign its callers in.
    fn admin_problems(&self) -> Vec<String> {
        let admin = &self.admin;
        let mut problems = Vec::new();
        if let Some(public) = &admin.public_url {
            if let Some(why) = public_url_problem(public) {
                problems.push(format!("[gateway.admin] public_url = {public:?} {why}"));
            }
        }
        for host in &admin.hosts {
            let bad = host.trim().is_empty()
                || host.contains(|c: char| c.is_whitespace() || matches!(c, '/' | ':' | '@'));
            if bad {
                problems.push(format!(
                    "[gateway.admin] hosts has {host:?}: name a host alone, with no scheme or port"
                ));
            }
        }
        if admin.enabled
            && !admin.listens_locally()
            && !self.admin_signs_in()
            && !admin.allow_unauthenticated
        {
            problems.push(format!(
                "[gateway.admin] listen = {:?} takes connections from other machines, and \
                 nothing signs its callers in: sign people in with [gateway.admin.oidc], \
                 require client certificates in {}, or set allow_unauthenticated = true for a \
                 proxy in front that authenticates them",
                admin.listen,
                self.admin_tls_table(),
            ));
        }
        if let Some(oidc) = &admin.oidc {
            if admin.public_url.is_none() {
                problems.push(
                    "[gateway.admin.oidc] needs [gateway.admin] public_url: the console's origin, \
                     which the provider sends people back to (`<public_url>/callback`)"
                        .to_string(),
                );
            }
            if let Some(why) = issuer_problem(&oidc.issuer) {
                problems.push(format!(
                    "[gateway.admin.oidc] issuer = {:?} {why}",
                    oidc.issuer
                ));
            }
            if oidc.client_id.trim().is_empty() {
                problems.push("[gateway.admin.oidc] has an empty client_id".to_string());
            }
            if let Some(how) = &oidc.client_auth {
                if how != "client_secret_basic" && how != "client_secret_post" {
                    problems.push(format!(
                        "[gateway.admin.oidc] client_auth = {how:?}: client_secret_basic or \
                         client_secret_post"
                    ));
                }
            }
            if oidc
                .scopes
                .iter()
                .flatten()
                .any(|s| s.trim().is_empty() || s.contains(' '))
            {
                problems.push(
                    "[gateway.admin.oidc] scopes holds an empty scope, or one with a space"
                        .to_string(),
                );
            }
            if let Some(audience) = &oidc.api_audience {
                if audience.trim().is_empty() {
                    problems.push("[gateway.admin.oidc] has an empty api_audience".to_string());
                } else if self.auth.resource.as_deref() == Some(audience.as_str()) {
                    problems.push(format!(
                        "[gateway.admin.oidc] api_audience = {audience:?} is [gateway.auth] \
                         resource: a token for the MCP listener would open the admin API; give \
                         the admin API an audience of its own"
                    ));
                } else if *audience == oidc.client_id {
                    problems.push(format!(
                        "[gateway.admin.oidc] api_audience = {audience:?} is its client_id: an \
                         ID token would open the admin API; give the admin API an audience of \
                         its own"
                    ));
                }
            }
        }
        if let Some(glass) = &admin.break_glass {
            if glass.digest().is_none() {
                problems.push(
                    "[gateway.admin.break_glass] token_sha256 is no SHA-256 in hex: make a \
                     token, and its digest, with `mcpdef admin token`"
                        .to_string(),
                );
            }
        }
        problems
    }

    /// The table that says the admin listener's TLS, as messages name it.
    pub fn admin_tls_table(&self) -> &'static str {
        match self.admin.tls {
            Some(_) => "[gateway.admin.tls]",
            None => "[gateway.tls]",
        }
    }

    /// Whether the MCP listener takes connections from this machine alone:
    /// `[gateway] listen` binds to a loopback address, or to `localhost`.
    pub fn listens_locally(&self) -> bool {
        binds_locally(&self.listen)
    }
}

/// Why `issuer` is no OpenID Connect issuer: not an `https` URL with a host
/// (`http` to this machine alone), or one with credentials, a query or a
/// fragment.
fn issuer_problem(issuer: &str) -> Option<&'static str> {
    let Ok(url) = url::Url::parse(issuer) else {
        return Some("is no URL");
    };
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.host_str().is_none() || !(url.scheme() == "https" || url.scheme() == "http" && local) {
        return Some("is no https URL with a host (http only to this machine)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("holds credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Some("has a query or a fragment, which no issuer has");
    }
    None
}

/// Why `url` is no console origin: not an `http` or `https` URL with a host,
/// one with credentials, a path, a query or a fragment, or `http` to a host
/// other than this machine.
fn public_url_problem(url: &str) -> Option<&'static str> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Some("is not a URL");
    };
    let Some(host) = parsed.host_str() else {
        return Some("names no host");
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Some("is not an http or https URL");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("holds credentials");
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Some("names a path, a query or a fragment: name the console's origin alone");
    }
    if parsed.scheme() == "http" && !binds_locally(&format!("{host}:0")) {
        return Some("is http to another machine: a sign-in's cookies need https there");
    }
    None
}

/// Whether `host:port` binds to a loopback address, or to `localhost`.
fn binds_locally(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map_or(listen, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `[gateway.rate_limit]` — token-bucket caps on `tools/call`. A scope is active
/// only if its `*_per_sec` is set; `*_burst` defaults to the per-sec rate.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct RateLimitConfig {
    /// Refill rate (tokens/sec) for each tool's own bucket.
    #[serde(default)]
    pub per_tool_per_sec: Option<f64>,
    /// Per-tool bucket capacity (max burst). Defaults to `per_tool_per_sec`.
    #[serde(default)]
    pub per_tool_burst: Option<f64>,
    /// Refill rate (tokens/sec) for the gateway-wide bucket.
    #[serde(default)]
    pub global_per_sec: Option<f64>,
    /// Gateway-wide bucket capacity (max burst). Defaults to `global_per_sec`.
    #[serde(default)]
    pub global_burst: Option<f64>,
}

/// `[gateway.egress]` — the SSRF guard knobs. Cloud-metadata / link-local
/// (`169.254/16`, `fe80::/10`) is **always** blocked and has no knob.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct EgressConfig {
    /// Allow private / loopback / unique-local upstreams. Default `true` — MCPdef
    /// commonly fronts internal or localhost MCP servers. Set `false` to only
    /// reach public upstreams.
    #[serde(default = "default_true")]
    pub allow_private: bool,
    /// Require HTTPS for public destinations (private/loopback may be plain
    /// HTTP). Default `true`.
    #[serde(default = "default_true")]
    pub require_https: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        EgressConfig {
            allow_private: true,
            require_https: true,
        }
    }
}

/// How MCPdef proves itself to an HTTP upstream (`[server.auth]`): a header
/// it adds to every request it sends there. Each secret is a reference: a
/// string is the secret itself, and `{ file }`, `{ env }` and `{ exec }` say
/// where to read it. A static kind's is read when the upstream is opened and
/// again once when it answers `401`; an `oauth2` client secret at each fetch
/// of a token.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerAuth {
    /// `bearer`, `header`, `basic` or `oauth2`.
    pub kind: ServerAuthKind,
    /// `bearer`: the token, sent as `Authorization: Bearer <token>`.
    pub token: Option<SecretRef>,
    /// `header`: the header's name.
    pub name: Option<String>,
    /// `header`: the header's value.
    pub value: Option<SecretRef>,
    /// `basic`: the user name, sent with the password as
    /// `Authorization: Basic <base64>`.
    pub username: Option<String>,
    /// `basic`: the password.
    pub password: Option<SecretRef>,
    /// `oauth2`: the authorization server's token endpoint.
    pub token_url: Option<String>,
    /// `oauth2`: the client's id there.
    pub client_id: Option<String>,
    /// `oauth2`: the client's secret there.
    pub client_secret: Option<SecretRef>,
    /// `oauth2`: how the client proves itself there: `client_secret_basic`,
    /// the default, or `client_secret_post`.
    pub client_auth: Option<String>,
    /// `oauth2`: the scopes to ask for.
    pub scopes: Option<Vec<String>>,
    /// `oauth2`: RFC 8707's `resource`, the upstream a token is for. The
    /// server's `url` when unset, and none when `""`
    /// ([`ServerConfig::credentials`]).
    pub resource: Option<String>,
}

/// Read field by field, each as a secret reference, which a string is too,
/// but `scopes`, a list; then checked. A secret reference's code, and a
/// list's, the binary holds already. A struct serde reads for itself would
/// cost it 20 KB.
impl<'de> Deserialize<'de> for ServerAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(AuthFields)
    }
}

/// The fields a `[server.auth]` table may have.
const AUTH_FIELDS: &[&str] = &[
    "kind",
    "token",
    "name",
    "value",
    "username",
    "password",
    "token_url",
    "client_id",
    "client_secret",
    "client_auth",
    "scopes",
    "resource",
];

struct AuthFields;

impl<'de> serde::de::Visitor<'de> for AuthFields {
    type Value = ServerAuth;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a table")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<ServerAuth, A::Error> {
        let (mut table, mut scopes) = (BTreeMap::new(), None);
        while let Some(field) = map.next_key::<String>()? {
            // Before its value is read: `scope = […]` is a field misspelled,
            // not a secret written wrong.
            if !AUTH_FIELDS.contains(&field.as_str()) {
                return Err(serde::de::Error::unknown_field(&field, AUTH_FIELDS));
            }
            if field == "scopes" {
                scopes = Some(map.next_value::<Vec<String>>()?);
            } else {
                table.insert(field, map.next_value::<SecretRef>()?);
            }
        }
        ServerAuth::from_table(table, scopes).map_err(serde::de::Error::custom)
    }
}

/// What a [`ServerAuth`] sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAuthKind {
    Bearer,
    Header,
    Basic,
    /// A token fetched by the client credentials grant.
    OAuth2,
}

impl ServerAuthKind {
    /// As the config writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            ServerAuthKind::Bearer => "bearer",
            ServerAuthKind::Header => "header",
            ServerAuthKind::Basic => "basic",
            ServerAuthKind::OAuth2 => "oauth2",
        }
    }
}

/// What a [`ServerAuth`] has MCPdef send, checked.
#[derive(Debug, Clone)]
pub enum UpstreamAuth {
    /// The same header on every request: `bearer`, `header` or `basic`.
    Static(Credential),
    /// A token fetched by the client credentials grant: `oauth2`.
    OAuth2(ClientCredentials),
}

impl ServerAuth {
    /// The table as `[server.auth]` writes it, its fields known: a known
    /// `kind`, and strings where a string goes.
    fn from_table(
        mut table: BTreeMap<String, SecretRef>,
        scopes: Option<Vec<String>>,
    ) -> Result<Self, String> {
        fn string(
            table: &mut BTreeMap<String, SecretRef>,
            field: &str,
        ) -> Result<Option<String>, String> {
            match table.remove(field) {
                None => Ok(None),
                Some(SecretRef::Literal(value)) => Ok(Some(value.expose_secret().to_string())),
                Some(_) => Err(format!("`{field}` is a string, not a place to read one")),
            }
        }
        let kind = match string(&mut table, "kind")?.as_deref() {
            Some("bearer") => ServerAuthKind::Bearer,
            Some("header") => ServerAuthKind::Header,
            Some("basic") => ServerAuthKind::Basic,
            Some("oauth2") => ServerAuthKind::OAuth2,
            Some(other) => {
                return Err(format!(
                    "unknown kind `{other}`, expected one of `bearer`, `header`, `basic`, \
                     `oauth2`"
                ))
            }
            None => return Err("missing field `kind`".to_string()),
        };
        let (name, username) = (string(&mut table, "name")?, string(&mut table, "username")?);
        let token_url = string(&mut table, "token_url")?;
        let client_id = string(&mut table, "client_id")?;
        let client_auth = string(&mut table, "client_auth")?;
        let resource = string(&mut table, "resource")?;
        let token = table.remove("token");
        let value = table.remove("value");
        let password = table.remove("password");
        let client_secret = table.remove("client_secret");
        Ok(ServerAuth {
            kind,
            token,
            name,
            value,
            username,
            password,
            token_url,
            client_id,
            client_secret,
            client_auth,
            scopes,
            resource,
        })
    }

    /// What this table has MCPdef send, or what is wrong with it: a field its
    /// kind needs and lacks, one it does not take, a header or user name no
    /// request can carry, or an `oauth2` field that is not what it should be.
    /// An `oauth2` token's `resource` is as the table gives it:
    /// [`ServerConfig::credentials`] fills in the server's.
    pub fn credential(&self) -> Result<UpstreamAuth, String> {
        let kind = self.kind.as_str();
        let (needs, takes): (&[&str], &[&str]) = match self.kind {
            ServerAuthKind::Bearer => (&["token"], &[]),
            ServerAuthKind::Header => (&["name", "value"], &[]),
            ServerAuthKind::Basic => (&["username", "password"], &[]),
            ServerAuthKind::OAuth2 => (
                &["token_url", "client_id", "client_secret"],
                &["client_auth", "scopes", "resource"],
            ),
        };
        let given = [
            ("token", self.token.is_some()),
            ("name", self.name.is_some()),
            ("value", self.value.is_some()),
            ("username", self.username.is_some()),
            ("password", self.password.is_some()),
            ("token_url", self.token_url.is_some()),
            ("client_id", self.client_id.is_some()),
            ("client_secret", self.client_secret.is_some()),
            ("client_auth", self.client_auth.is_some()),
            ("scopes", self.scopes.is_some()),
            ("resource", self.resource.is_some()),
        ];
        for (field, set) in given {
            match (needs.contains(&field), set) {
                (true, false) => return Err(format!("kind = \"{kind}\" needs `{field}`")),
                (false, true) if !takes.contains(&field) => {
                    return Err(format!("`{field}` is not for kind = \"{kind}\""))
                }
                _ => {}
            }
        }
        let missing = || format!("kind = \"{kind}\" is incomplete");
        let credential = match self.kind {
            ServerAuthKind::Bearer => Credential::Bearer(self.token.clone().ok_or_else(missing)?),
            ServerAuthKind::Header => Credential::header(
                self.name.as_deref().ok_or_else(missing)?,
                self.value.clone().ok_or_else(missing)?,
            )?,
            ServerAuthKind::Basic => Credential::basic(
                self.username.as_deref().ok_or_else(missing)?,
                self.password.clone().ok_or_else(missing)?,
            )?,
            ServerAuthKind::OAuth2 => return self.grant().map(UpstreamAuth::OAuth2),
        };
        Ok(UpstreamAuth::Static(credential))
    }

    /// The client credentials grant an `oauth2` table describes, its fields
    /// checked: a token endpoint's URL, a client id, a known `client_auth`,
    /// scopes as RFC 6749 writes them, and a `resource` as RFC 8707 does.
    fn grant(&self) -> Result<ClientCredentials, String> {
        let missing = || "kind = \"oauth2\" is incomplete".to_string();
        let token_url = self.token_url.clone().ok_or_else(missing)?;
        // Not repeated until it is known to hold no password.
        let url =
            url::Url::parse(&token_url).map_err(|e| format!("token_url is not a URL: {e}"))?;
        if !url.username().is_empty() || url.password().is_some() {
            let why = "token_url holds a user name or password: give the client's as \
                       `client_id` and `client_secret`";
            return Err(why.to_string());
        }
        if !matches!(url.scheme(), "https" | "http") {
            return Err(format!(
                "token_url {token_url:?} is not an https:// or http:// URL"
            ));
        }
        if url.fragment().is_some() {
            return Err(format!(
                "token_url {token_url:?} has a fragment, which a token endpoint's URL cannot"
            ));
        }
        let client_id = self.client_id.clone().ok_or_else(missing)?;
        if client_id.is_empty() {
            return Err("client_id is empty".to_string());
        }
        let client_auth = match self.client_auth.as_deref() {
            None | Some("client_secret_basic") => ClientAuth::Basic,
            Some("client_secret_post") => ClientAuth::Post,
            Some(other) => {
                return Err(format!(
                    "unknown client_auth `{other}`, expected `client_secret_basic` or \
                     `client_secret_post`"
                ))
            }
        };
        let scopes = self.scopes.clone().unwrap_or_default();
        // RFC 6749 §3.3: printable ASCII but space, `"` and `\`.
        let scope_char = |b: u8| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e);
        if let Some(scope) = scopes
            .iter()
            .find(|s| s.is_empty() || !s.bytes().all(scope_char))
        {
            return Err(format!(
                "scope {scope:?} is not one: a scope is printable ASCII, with no space, `\"` \
                 or `\\`"
            ));
        }
        if let Some(resource) = self.resource.as_deref().filter(|r| !r.is_empty()) {
            let url = url::Url::parse(resource)
                .map_err(|e| format!("resource {resource:?} is not an absolute URI: {e}"))?;
            if url.fragment().is_some() {
                return Err(format!(
                    "resource {resource:?} has a fragment, which RFC 8707 does not allow"
                ));
            }
        }
        Ok(ClientCredentials {
            token_url,
            client_id,
            client_secret: self.client_secret.clone().ok_or_else(missing)?,
            client_auth,
            scopes,
            resource: self.resource.clone(),
        })
    }

    /// Its secret, with the name of the field it is in.
    pub fn secret(&self) -> Option<(&'static str, &SecretRef)> {
        match self.kind {
            ServerAuthKind::Bearer => Some(("token", self.token.as_ref()?)),
            ServerAuthKind::Header => Some(("value", self.value.as_ref()?)),
            ServerAuthKind::Basic => Some(("password", self.password.as_ref()?)),
            ServerAuthKind::OAuth2 => Some(("client_secret", self.client_secret.as_ref()?)),
        }
    }
}

/// A TLS profile: `[gateway.upstream_tls]`, and a server's `[server.tls]`
/// over it. It says how MCPdef checks an HTTPS upstream's certificate, and
/// which certificate it presents. A field a `[server.tls]` sets replaces the
/// gateway's, and the rest are the gateway's. Every file is PEM.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Whose roots to trust: `bundled` (Mozilla's, in the binary; the
    /// default), `system` (the host's store, which honours `SSL_CERT_FILE`
    /// and `SSL_CERT_DIR`), or `both`.
    #[serde(default)]
    pub roots: Option<RootsSetting>,
    /// More roots: files of CA certificates.
    #[serde(default)]
    pub ca: Option<Vec<String>>,
    /// Files of CRLs. A certificate they revoke is refused, and so is one
    /// whose status none of them tells: every CA in an upstream's chain needs
    /// its CRL here.
    #[serde(default)]
    pub crl: Option<Vec<String>>,
    /// The oldest TLS version to speak: `"1.2"` (the default) or `"1.3"`.
    #[serde(default)]
    pub min_version: Option<TlsVersion>,
    /// A certificate for an upstream that asks for one: the certificate,
    /// then any intermediates. Set together with `client_key`.
    #[serde(default)]
    pub client_cert: Option<String>,
    /// The certificate's key, unencrypted, as PEM: `{ file = "/path/to/key.pem" }`,
    /// `{ env = "NAME" }` for a variable of MCPdef's own that holds it,
    /// `{ exec = ["command", …] }` for what a command writes, or a string that
    /// is the key itself.
    #[serde(default)]
    pub client_key: Option<SecretRef>,
    /// `[server.tls]` only: dial this IP address in place of what the URL's
    /// host resolves to, and still check the certificate against the host's
    /// name. The address passes the egress guard as a resolved one would.
    #[serde(default)]
    pub connect_to: Option<String>,
    /// `[server.tls]` only: accept whatever certificate the upstream
    /// presents. Warned about at startup, and audited at every connection.
    #[serde(default)]
    pub insecure_skip_verify: Option<bool>,
    /// `[server.tls]` only: SPKI pins, as `mcpdef tls pin` prints them. With
    /// any, the upstream is trusted by its key alone: its certificate's
    /// issuer, names and dates are not checked, so a self-signed upstream
    /// works. A certificate renewed on the same key keeps its pin.
    #[serde(default)]
    pub pin_sha256: Option<Vec<String>>,
}

/// `roots`: whose root certificates a TLS profile trusts.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RootsSetting {
    Bundled,
    System,
    Both,
}

/// `min_version`: the oldest TLS version a profile speaks.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

impl TlsConfig {
    /// `self` over `under`: each field `self` sets, and `under`'s for the
    /// rest. The client certificate and its key go as a pair. `connect_to`,
    /// `insecure_skip_verify` and `pin_sha256` are a server's own, never
    /// inherited.
    pub fn over(&self, under: &TlsConfig) -> TlsConfig {
        let identity = match self.client_cert.is_some() || self.client_key.is_some() {
            true => self,
            false => under,
        };
        TlsConfig {
            roots: self.roots.or(under.roots),
            ca: self.ca.clone().or_else(|| under.ca.clone()),
            crl: self.crl.clone().or_else(|| under.crl.clone()),
            min_version: self.min_version.or(under.min_version),
            client_cert: identity.client_cert.clone(),
            client_key: identity.client_key.clone(),
            connect_to: self.connect_to.clone(),
            insecure_skip_verify: self.insecure_skip_verify,
            pin_sha256: self.pin_sha256.clone(),
        }
    }

    /// The settings the transport reads a profile from. A client certificate
    /// without its key, or a key without its certificate, is left out:
    /// `validate()` refuses either.
    pub fn settings(&self) -> TlsSettings {
        let paths =
            |files: &Option<Vec<String>>| files.iter().flatten().map(PathBuf::from).collect();
        TlsSettings {
            roots: match self.roots {
                None | Some(RootsSetting::Bundled) => Roots::Bundled,
                Some(RootsSetting::System) => Roots::System,
                Some(RootsSetting::Both) => Roots::Both,
            },
            ca: paths(&self.ca),
            crl: paths(&self.crl),
            min_version: match self.min_version {
                None | Some(TlsVersion::V1_2) => MinVersion::Tls12,
                Some(TlsVersion::V1_3) => MinVersion::Tls13,
            },
            identity: match (&self.client_cert, &self.client_key) {
                (Some(cert), Some(key)) => Some(IdentityFiles {
                    cert: cert.into(),
                    key: key.clone(),
                }),
                _ => None,
            },
            insecure_skip_verify: self.insecure_skip_verify.unwrap_or(false),
            pin_sha256: self.pin_sha256.clone().unwrap_or_default(),
        }
    }

    /// Every file this table names.
    pub fn files(&self) -> Vec<&str> {
        let lists = self
            .ca
            .iter()
            .chain(&self.crl)
            .flatten()
            .map(String::as_str);
        let identity = self.client_cert.as_deref().into_iter();
        let key = self
            .client_key
            .iter()
            .filter_map(|key| key.path().and_then(Path::to_str));
        lists.chain(identity).chain(key).collect()
    }

    /// What is wrong with this table on its own: a certificate without its
    /// key, and any file it names that is missing or holds the wrong thing.
    /// `table` names it in each message.
    fn problems(&self, table: &str) -> Vec<String> {
        let mut problems = Vec::new();
        if self.client_cert.is_some() != self.client_key.is_some() {
            problems.push(format!(
                "{table} client_cert and client_key go together: set both, or neither"
            ));
        }
        if let Err(e) = self.settings().check() {
            let e = match e {
                TransportError::Tls(e) => e,
                e => e.to_string(),
            };
            problems.push(format!("{table} {e}"));
        }
        problems
    }
}

/// Whether a variable named `name` that holds `value` holds a secret, as far
/// as can be told. Its name says so when its last word is `KEY`, `PASS` or
/// `PAT`, or ends in `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE` or
/// `APIKEY`: `GITHUB_TOKEN`, `PGPASSWORD` and `OPENAI_API_KEY` do, and
/// `SSH_KEY_PATH` does not. Or its value has the shape of a known credential,
/// whatever its name. An empty value holds none.
pub(crate) fn a_secret(name: &str, value: &str) -> bool {
    const ENDINGS: [&str; 6] = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASSPHRASE",
        "APIKEY",
    ];
    if value.is_empty() {
        return false;
    }
    let last = name
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let named = ["KEY", "PASS", "PAT"].contains(&last.as_str())
        || ENDINGS.iter().any(|ending| last.ends_with(ending));
    named || mcpdef_inspect::secret_pattern(value).is_some()
}

/// What [`Config::check`] found.
#[derive(Debug, Default, PartialEq)]
pub struct Checked {
    /// What stops the config from running.
    pub errors: Vec<String>,
    /// What it does that it should not have to, and that does not stop it.
    pub warnings: Vec<String>,
}

/// A `[[role]]` resource grant, `"server-glob:uri-pattern"`, split at its
/// first `:` and compiled, or what is wrong with it.
fn resource_grant(grant: &str) -> Result<(String, UriGlob), String> {
    let no_server = || {
        "names no server: write it as 'server-glob:uri-pattern', such as '*:file:///srv/**'"
            .to_string()
    };
    let (server, uri) = grant.split_once(':').ok_or_else(no_server)?;
    // `file:///x` alone would split into server `file` and `///x`.
    if server.is_empty() || uri.starts_with("//") {
        return Err(no_server());
    }
    let glob = UriGlob::new(uri).map_err(|e| format!("has a URI pattern that {e}"))?;
    Ok((server.to_string(), glob))
}

/// What secret `url` holds, if any, as a warning says it: a password, a query
/// parameter that is one by its name or its shape, or a known credential's
/// shape anywhere in it. Never the secret itself.
fn url_secret(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.password().is_some() {
        return Some("a password".to_string());
    }
    if let Some((name, _)) = parsed
        .query_pairs()
        .find(|(name, value)| a_secret(name, value))
    {
        return Some(format!("a secret, its query parameter `{name}`"));
    }
    mcpdef_inspect::secret_pattern(url).map(|shape| format!("a secret, a {shape} by its shape"))
}

/// A server's `url` as the RFC 8707 `resource` its tokens are asked for: as
/// the config writes it, less any user info, query and fragment. A resource
/// cannot have a fragment and should not have a query, and the authorization
/// server is no place for the credentials a URL can hold. The authority ends
/// where the URL parser ends it, at the first `/` or `\`, and its user info
/// at the last `@` in it.
fn resource_of(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (authority, path) = rest.split_at(rest.find(['/', '\\']).unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}{path}")
}

/// The host `url` names, if it is a plain-HTTP URL and the host is not this
/// machine: where a request sent in the clear can be read on the way.
fn cleartext_host(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let this_machine = match url.host()? {
        url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    (!this_machine).then(|| url.host_str().unwrap_or_default().to_string())
}

fn default_listen() -> String {
    "127.0.0.1:7878".to_string()
}
fn default_audit() -> String {
    "./mcpdef-audit/audit.log".to_string()
}
fn default_state_dir() -> String {
    "./mcpdef-state".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ServerConfig {
    pub id: String,
    pub transport: String,
    /// stdio: the command (argv) to spawn.
    #[serde(default)]
    pub command: Vec<String>,
    /// streamable-http / sse: the upstream endpoint (reserved in Phase 1).
    #[serde(default)]
    pub url: Option<String>,
    /// Which MCP revision this server speaks: `"2025-11-25"` (the default),
    /// `"2026-07-28"`, or `"auto"` to probe it. The newer one has no `initialize` handshake, so MCPdef
    /// opens it with `server/discover` instead and puts the protocol version,
    /// its own identity and its capabilities on every request it sends.
    ///
    /// It is a fact about the server, not a preference — set it to whatever the
    /// server actually speaks, and MCPdef translates for a client speaking the
    /// other one.
    #[serde(default)]
    pub spec: SpecSetting,
    /// Allowlist: if present, only these tools are exposed (deny-by-default).
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Glob denies (e.g. `delete_*`), applied after the allowlist.
    #[serde(default)]
    pub deny: Vec<String>,
    /// A named `[profile.<name>]` to inherit allow/deny from. Inline `tools`
    /// replaces the profile's allowlist; inline `deny` is appended to it.
    #[serde(default)]
    pub profile: Option<String>,
    /// Environment variables injected into a **stdio** upstream's child process —
    /// the OSS token-broker path: MCPdef holds the upstream's credentials and hands
    /// them to the server via env (the spec says stdio servers take creds from the
    /// environment), so the client's bearer is never passed through.
    ///
    /// Each value is a secret reference: a string is the value itself, and
    /// `{ file = … }`, `{ env = … }` and `{ exec = […] }` say where to read it.
    /// It is read at every spawn, so a restart picks up a rotated secret.
    #[serde(default)]
    pub env: BTreeMap<String, SecretRef>,
    /// Resource-URI allowlist: the URIs a `resources/read` may name, as URI
    /// globs (`file:///srv/docs/**`). Unset or empty exposes none of this
    /// server's resources.
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    /// The URI templates `resources/templates/list` may show, as name globs
    /// matched against each template as the server writes it. A URI filled in
    /// from one is read only if `resources` allows it.
    #[serde(default)]
    pub resource_templates: Option<Vec<String>>,
    /// Prompt allowlist: the prompts `prompts/list` may show and `prompts/get`
    /// may name, as name globs. Unset or empty exposes none of this server's
    /// prompts.
    #[serde(default)]
    pub prompts: Option<Vec<String>>,
    /// With `[gateway] tool_namespace = "prefix"`, what its tools' listed
    /// names start with, before `__`. Unset means the server's id.
    #[serde(default)]
    pub prefix: Option<String>,
    /// `wasm` transport: path to the `.wasm` module to run in the in-path sandbox
    /// (Phase 4). Required when `transport = "wasm"`.
    #[serde(default)]
    pub wasm: Option<String>,
    /// `wasm`: fuel granted per call (≈ one unit per instruction). Unset = default.
    #[serde(default)]
    pub wasm_fuel: Option<u64>,
    /// `wasm`: max linear memory (MiB) the module may grow to. Unset = default.
    #[serde(default)]
    pub wasm_max_memory_mb: Option<usize>,
    /// `wasm`: per-call **wall-clock** deadline (ms). A module that runs longer than
    /// this traps, even with fuel to spare — defense-in-depth on top of the fuel
    /// (CPU) bound. Unset or `0` = no wall-clock bound.
    #[serde(default)]
    pub wasm_deadline_ms: Option<u64>,
    /// `wasm-component`: outbound TCP **egress allowlist** for the sandboxed
    /// component (`["ip:port", …]`). Default empty = **deny all** network access.
    /// A connection is permitted only if its address is listed *and* passes the
    /// egress IP classification (cloud-metadata/special-use are always blocked).
    #[serde(default)]
    pub wasm_allow_egress: Vec<String>,
    /// The most calls that may wait on this upstream at once. Unset means 16, or
    /// 1 for `wasm` and `wasm-component`, whose one instance runs one call at a
    /// time. Further calls queue for a slot, and the queueing counts against
    /// `upstream_timeout_ms`.
    #[serde(default)]
    pub max_inflight: Option<usize>,
    /// This upstream's TLS profile, over `[gateway.upstream_tls]` field by
    /// field (`[server.tls]`). For an `https://` upstream only.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// How MCPdef proves itself to this upstream (`[server.auth]`). For an
    /// HTTP upstream only.
    #[serde(default)]
    pub auth: Option<ServerAuth>,
}

/// How many calls in a row to an HTTP upstream may fail or time out before it is
/// declared down and connected again.
pub const HTTP_TRIP_AFTER: u32 = 5;

impl ServerConfig {
    /// This entry with only what says how to reach the upstream: everything
    /// but its allowlist, denies, profile, resources, prompts and tool prefix.
    /// Two entries whose connections are equal reach the same upstream the
    /// same way.
    pub fn connection(&self) -> ServerConfig {
        ServerConfig {
            tools: None,
            deny: Vec::new(),
            profile: None,
            resources: None,
            resource_templates: None,
            prompts: None,
            prefix: None,
            ..self.clone()
        }
    }

    /// What it may expose of its resources, compiled. A pattern that is not a
    /// URI is left out, which exposes less, never more; `validate` refuses a
    /// config that holds one.
    pub fn resource_policy(&self) -> ResourcePolicy {
        ResourcePolicy {
            uris: self
                .resources
                .iter()
                .flatten()
                .filter_map(|pattern| UriGlob::new(pattern).ok())
                .collect(),
            templates: self.resource_templates.clone().unwrap_or_default(),
        }
    }

    /// Whether it is reached over HTTP, and so through the egress guard.
    pub fn is_http(&self) -> bool {
        matches!(self.transport.as_str(), "streamable-http" | "sse")
    }

    /// Whether it is reached over HTTPS, and so with a TLS profile.
    pub fn is_https(&self) -> bool {
        self.is_http()
            && self
                .url
                .as_deref()
                .and_then(|url| url::Url::parse(url).ok())
                .is_some_and(|url| url.scheme() == "https")
    }

    /// The host its URL names, if it is a plain-HTTP one and not this
    /// machine: where a request sent in the clear can be read on the way.
    pub fn cleartext_host(&self) -> Option<String> {
        cleartext_host(self.url.as_deref()?)
    }

    /// What its `[server.auth]` has MCPdef send, checked, if it has one
    /// ([`ServerAuth::credential`]). An `oauth2` token is asked for with this
    /// server's `url` as its RFC 8707 `resource`, as MCP's authorization
    /// spec has a client do, less any user info, query and fragment: unless
    /// the table gives another, or none with `resource = ""`.
    pub fn credentials(&self) -> Option<Result<UpstreamAuth, String>> {
        let mut auth = self.auth.as_ref()?.credential();
        if let Ok(UpstreamAuth::OAuth2(grant)) = &mut auth {
            grant.resource = match grant.resource.take() {
                None => self.url.as_deref().map(resource_of),
                Some(resource) => Some(resource).filter(|r| !r.is_empty()),
            };
        }
        Some(auth)
    }

    /// Whether its `[server.auth]` fetches tokens: `kind = "oauth2"`.
    pub fn fetches_tokens(&self) -> bool {
        self.auth
            .as_ref()
            .is_some_and(|auth| auth.kind == ServerAuthKind::OAuth2)
    }

    /// The address its `[server.tls] connect_to` names, if it names one.
    pub fn connect_to(&self) -> Result<Option<IpAddr>, String> {
        let Some(addr) = self.tls.as_ref().and_then(|tls| tls.connect_to.as_deref()) else {
            return Ok(None);
        };
        addr.parse().map(Some).map_err(|_| {
            format!(
                "server '{}': [server.tls] connect_to must be an IP address, the one to dial in \
                 place of what the url's host resolves to; '{addr}' is not one",
                self.id
            )
        })
    }

    /// How many calls in a row may fail or time out before this upstream is
    /// declared down: [`HTTP_TRIP_AFTER`] for an HTTP upstream, which has no
    /// connection whose end would say so, and never for the rest. A stdio
    /// server is down when its process or pipes go, and a sandbox never is.
    pub fn trip_after(&self) -> Option<u32> {
        self.is_http().then_some(HTTP_TRIP_AFTER)
    }

    /// The in-flight cap for this upstream: `max_inflight`, or the default for
    /// its transport.
    pub fn max_inflight(&self) -> usize {
        self.max_inflight.unwrap_or(match self.transport.as_str() {
            "wasm" | "wasm-component" => 1,
            _ => mcpdef_transport::DEFAULT_MAX_INFLIGHT,
        })
    }

    /// The configured `wasm` module/component path, treating an empty or
    /// whitespace-only string as **missing** (so a blank `wasm = ""` is rejected
    /// at `validate()` time rather than blowing up later as a confusing file-not-
    /// found during transport construction).
    pub fn wasm_path(&self) -> Option<&str> {
        self.wasm
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
    }

    /// The files its `[server.env]` reads values from.
    pub fn env_files(&self) -> impl Iterator<Item = &str> {
        self.env
            .values()
            .filter_map(|value| value.path().and_then(Path::to_str))
    }

    /// The sandbox resource caps for a `wasm` upstream — config overrides on top
    /// of [`SandboxLimits::default`].
    pub fn sandbox_limits(&self) -> SandboxLimits {
        let d = SandboxLimits::default();
        SandboxLimits {
            fuel_per_call: self.wasm_fuel.unwrap_or(d.fuel_per_call),
            max_memory_bytes: self
                .wasm_max_memory_mb
                .map(|mb| mb.saturating_mul(1024 * 1024))
                .unwrap_or(d.max_memory_bytes),
            // A `0` deadline means "no wall-clock bound", same as unset.
            deadline: self
                .wasm_deadline_ms
                .filter(|&ms| ms > 0)
                .map(std::time::Duration::from_millis)
                .or(d.deadline),
        }
    }

    /// The outbound-socket egress allowlist for a `wasm-component` upstream. Empty
    /// `wasm_allow_egress` = deny all. Errors if an entry isn't a valid `ip:port`
    /// (also surfaced by [`Config::validate`]).
    pub fn egress_allow(&self) -> Result<EgressAllow, String> {
        let mut addrs = Vec::with_capacity(self.wasm_allow_egress.len());
        for e in &self.wasm_allow_egress {
            let addr: SocketAddr = e.parse().map_err(|_| {
                format!(
                    "server '{}': wasm_allow_egress entry '{e}' is not a valid ip:port",
                    self.id
                )
            })?;
            addrs.push(addr);
        }
        // Private/loopback are allowed when explicitly listed (the allowlist is the
        // grant); only the always-blocked classes (metadata/special-use) are denied.
        Ok(EgressAllow::new(addrs, EgressPolicy::default()))
    }
}

/// A reusable, named allow/deny set (`[profile.<name>]`). Defined once and
/// referenced by one or more servers (DRY), or applied gateway-wide as the
/// active profile to scope the whole tool surface an agent sees.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
pub struct ProfileConfig {
    /// Glob allowlist (deny-by-default). `None` = allow all (subject to `deny`).
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Glob denies, applied before the allowlist.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self::load_text(path)?.0)
    }

    /// [`Config::load`], and the text the config was parsed from.
    pub fn load_text(path: impl AsRef<Path>) -> anyhow::Result<(Self, String)> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config =
            Self::parse(&text).with_context(|| format!("parsing TOML {}", path.display()))?;
        Ok((config, text))
    }

    /// A config from its TOML text.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// The files this config reads as input, besides itself: a JWKS file,
    /// each wasm module, every file a TLS profile names, every file a
    /// `[server.env]` reads a value from, and a listener's certificate and key
    /// from files. A reload notices when one of them changes. Files the
    /// gateway writes, such as the ledger, the pin store and what it keeps in
    /// `state_dir`, are not inputs.
    pub fn referenced_files(&self) -> Vec<String> {
        let jwks = self.gateway.auth.jwks_file();
        let modules = self.servers.iter().filter_map(ServerConfig::wasm_path);
        let tls = std::iter::once(&self.gateway.upstream_tls)
            .chain(self.servers.iter().filter_map(|s| s.tls.as_ref()))
            .flat_map(TlsConfig::files);
        let env = self.servers.iter().flat_map(ServerConfig::env_files);
        let listeners = std::iter::once(&self.gateway.tls)
            .chain(&self.gateway.admin.tls)
            .flat_map(ListenerTlsConfig::files);
        jwks.into_iter()
            .chain(modules)
            .chain(tls)
            .chain(env)
            .chain(listeners)
            .map(str::to_string)
            .collect()
    }

    /// The TLS settings of `s`'s connections: its `[server.tls]` over
    /// `[gateway.upstream_tls]`.
    pub fn upstream_tls(&self, s: &ServerConfig) -> TlsSettings {
        match &s.tls {
            Some(tls) => tls.over(&self.gateway.upstream_tls).settings(),
            None => self.gateway.upstream_tls.settings(),
        }
    }

    /// What a valid config does that it should not have to. Each is printed
    /// when the gateway starts or reloads, and by `mcpdef validate`. None
    /// stops either, unless the config is checked strictly ([`check`]).
    ///
    /// [`check`]: Config::check
    pub fn warnings(&self) -> Vec<String> {
        let skip_verify = self
            .servers
            .iter()
            .filter(|s| s.tls.as_ref().and_then(|tls| tls.insecure_skip_verify) == Some(true))
            .map(|s| {
                format!(
                    "server '{}': [server.tls] insecure_skip_verify = true: its certificate is \
                     not checked, so anyone on the path to it can pose as it. Give its CA in \
                     `ca` instead",
                    s.id
                )
            });
        let cleartext = self
            .servers
            .iter()
            .filter(|s| s.auth.is_some())
            .filter_map(|s| {
                let host = s.cleartext_host()?;
                Some(format!(
                    "server '{}': [server.auth] sends its credentials over plain HTTP to {host}, \
                     where anyone on the path can read them: use https://",
                    s.id
                ))
            });
        let cleartext_secret = self.servers.iter().filter_map(|s| {
            let host = cleartext_host(s.auth.as_ref()?.token_url.as_deref()?)?;
            Some(format!(
                "server '{}': [server.auth] sends its client secret over plain HTTP to {host}, \
                 where anyone on the path can read it: give token_url as https://",
                s.id
            ))
        });
        let readable = self
            .secrets()
            .filter_map(|(name, secret)| Some(format!("{name}: {}", secret.warning()?)));
        let literal = self.literal_secrets().map(|name| {
            format!(
                "{name} is a secret written in the config, so every copy of the config holds \
                 it too: read it from a file, a variable or a command instead, as \
                 {{ file = \"…\" }}, {{ env = \"…\" }} or {{ exec = [\"…\"] }}"
            )
        });
        // Where no secret reference can go: a URL, and a command's arguments.
        let in_url = self.servers.iter().filter_map(|s| {
            let what = url_secret(s.url.as_deref()?)?;
            Some(format!(
                "server '{}': url holds {what}, so every copy of the config holds it too, and \
                 so does every message that names the URL: send it with [server.auth] \
                 instead, if the upstream takes it in a header",
                s.id
            ))
        });
        let in_command = self.servers.iter().flat_map(|s| {
            s.command.iter().enumerate().filter_map(move |(i, arg)| {
                let shape = mcpdef_inspect::secret_pattern(arg)?;
                Some(format!(
                    "server '{}': command[{i}] holds a secret, a {shape} by its shape, so every \
                     copy of the config holds it too, and any user of this machine can read a \
                     process's arguments: give it to the server in [server.env] instead, read \
                     from a file, a variable or a command",
                    s.id
                ))
            })
        });
        skip_verify
            .chain(self.exposed_in_the_clear())
            .chain(self.trusts_every_address())
            .chain(cleartext)
            .chain(cleartext_secret)
            .chain(readable)
            .chain(literal)
            .chain(in_url)
            .chain(in_command)
            .chain(self.resource_overlaps())
            .chain(self.prompt_overlaps())
            .chain(self.tool_collisions())
            .chain(self.grants_to_no_server())
            .chain(self.cert_roles_undefined())
            .chain(self.keys_unread())
            .collect()
    }

    /// `[[key]]`s no listener reads, and their roles no `[[role]]` defines.
    fn keys_unread(&self) -> Vec<String> {
        let auth = &self.gateway.auth;
        let mut lines = Vec::new();
        if !self.keys.is_empty() && !(auth.enabled && auth.takes(AuthMethod::Key)) {
            lines.push(
                "[[key]] is set, and no listener takes keys: add \"key\" to [gateway.auth] \
                 methods, with enabled = true"
                    .to_string(),
            );
        }
        let defined: HashSet<&str> = self.roles.iter().map(|r| r.name.as_str()).collect();
        for key in &self.keys {
            for role in &key.roles {
                if !role.trim().is_empty() && !defined.contains(role.as_str()) {
                    lines.push(format!(
                        "[[key]] '{}' holds role '{role}', which no [[role]] defines: it grants \
                         nothing",
                        key.name
                    ));
                }
            }
        }
        lines
    }

    /// What is wrong with `[gateway.auth] methods` and `require`: a list
    /// that is empty or names a method twice, `mtls` where the MCP listener
    /// asks for no certificate, and either set where auth is off, which
    /// would make it look on.
    fn auth_method_problems(&self) -> Vec<String> {
        let auth = &self.gateway.auth;
        let mut problems = Vec::new();
        if !auth.enabled {
            for (key, set) in [
                ("methods", auth.methods.is_some()),
                ("require", auth.require.is_some()),
            ] {
                if set {
                    problems.push(format!(
                        "[gateway.auth] has `{key}`, which applies only with enabled = true"
                    ));
                }
            }
            return problems;
        }
        if auth.methods().is_empty() {
            problems.push(
                "[gateway.auth] methods is empty: name \"bearer\", \"mtls\", \"key\" or more"
                    .to_string(),
            );
        }
        for (i, method) in auth.methods().iter().enumerate() {
            if auth.methods()[..i].contains(method) {
                problems.push(format!(
                    "[gateway.auth] methods names \"{}\" twice",
                    method.as_str()
                ));
            }
        }
        if auth.takes(AuthMethod::Mtls) && !self.gateway.tls.client_auth.mode.is_on() {
            problems.push(
                "[gateway.auth] methods names \"mtls\", and the listener asks for no client \
                 certificate: set [gateway.tls.client_auth] mode = \"optional\" or \"required\""
                    .to_string(),
            );
        }
        if auth.issuer.as_deref() == Some("mcpdef") {
            problems.push(
                "[gateway.auth] issuer = \"mcpdef\" is the issuer of the gateway's own client \
                 keys: name the authorization server's"
                    .to_string(),
            );
        }
        if auth.takes(AuthMethod::Bearer)
            && auth.takes(AuthMethod::Key)
            && auth.require == Some(AuthRequire::All)
        {
            problems.push(
                "[gateway.auth] requires both \"bearer\" and \"key\", and a request carries one \
                 bearer token: require = \"any\", or name one of them"
                    .to_string(),
            );
        }
        problems
    }

    /// What is wrong with a `[[key]]`: a name that is empty, not one word of
    /// letters, digits, `.`, `_` and `-`, or another key's; a digest that is
    /// no SHA-256 in hex; no roles.
    fn key_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for (n, key) in self.keys.iter().enumerate() {
            let named = !key.name.is_empty()
                && key
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
            if !named {
                problems.push(format!(
                    "[[key]] {} has the name {:?}: one word, of letters, digits, '.', '_' and '-'",
                    n + 1,
                    key.name
                ));
            } else if self.keys[..n].iter().any(|k| k.name == key.name) {
                problems.push(format!("[[key]] '{}' is named twice", key.name));
            }
            if key.digest().is_none() {
                problems.push(format!(
                    "[[key]] '{}': sha256 is no SHA-256 in hex: make a key, and its digest, with \
                     `mcpdef keys create`",
                    key.name
                ));
            }
            if key.roles.is_empty() {
                problems.push(format!(
                    "[[key]] '{}' has no roles: it would grant nothing",
                    key.name
                ));
            }
        }
        problems
    }

    /// What is wrong with an `[[identity.cert_map]]` entry: an empty
    /// identity, and no roles.
    fn cert_map_problems(&self) -> Vec<String> {
        let mut problems = self.role_map_problems();
        for (n, entry) in self.identity.cert_map.iter().enumerate() {
            let n = n + 1;
            if entry.identity.trim().is_empty() {
                problems.push(format!(
                    "[[identity.cert_map]] entry {n} has an empty `identity`"
                ));
            }
            if entry.roles.is_empty() {
                problems.push(format!(
                    "[[identity.cert_map]] entry {n} ({:?}) maps to no role: name the `roles` \
                     it holds",
                    entry.identity
                ));
            }
            for role in &entry.roles {
                if role.trim().is_empty() {
                    problems.push(format!(
                        "[[identity.cert_map]] entry {n} ({:?}) has an empty role",
                        entry.identity
                    ));
                }
                if role.starts_with("console:") && !CONSOLE_ROLES.contains(&role.as_str()) {
                    problems.push(format!(
                        "[[identity.cert_map]] entry {n} ({:?}) maps to '{role}', which is no \
                         console role: name console:viewer, console:operator or console:admin",
                        entry.identity
                    ));
                }
            }
        }
        problems
    }

    /// What is wrong with `[identity]`'s claims and `[[identity.role_map]]`.
    fn role_map_problems(&self) -> Vec<String> {
        let identity = &self.identity;
        let mut problems = Vec::new();
        let claims = identity
            .subject_claim
            .iter()
            .chain(identity.roles_claims.iter().flatten());
        for claim in claims {
            if claim.trim().is_empty() || claim.split('.').any(str::is_empty) {
                problems.push(format!(
                    "[identity] names the claim {claim:?}: a claim's name, or a path of names \
                     joined by single dots"
                ));
            }
        }
        for (n, entry) in identity.role_map.iter().enumerate() {
            let n = n + 1;
            if entry.claim.trim().is_empty() || entry.claim.split('.').any(str::is_empty) {
                problems.push(format!(
                    "[[identity.role_map]] entry {n} names the claim {:?}: a claim's name, or a \
                     path of names joined by single dots",
                    entry.claim
                ));
            }
            if entry.value.is_empty() {
                problems.push(format!(
                    "[[identity.role_map]] entry {n} ({}) has an empty `value`",
                    entry.claim
                ));
            }
            if entry.roles.is_empty() {
                problems.push(format!(
                    "[[identity.role_map]] entry {n} ({} = {:?}) maps to no role: name the \
                     `roles` it gives",
                    entry.claim, entry.value
                ));
            }
            for role in &entry.roles {
                if role.trim().is_empty() {
                    problems.push(format!(
                        "[[identity.role_map]] entry {n} ({} = {:?}) has an empty role",
                        entry.claim, entry.value
                    ));
                }
                if role.starts_with("console:") && !CONSOLE_ROLES.contains(&role.as_str()) {
                    problems.push(format!(
                        "[[identity.role_map]] entry {n} ({} = {:?}) maps to '{role}', which is \
                         no console role: name console:viewer, console:operator or console:admin",
                        entry.claim, entry.value
                    ));
                }
            }
        }
        problems
    }

    /// A line for each role an `[[identity.cert_map]]` or
    /// `[[identity.role_map]]` entry maps to that no `[[role]]` defines: it
    /// grants nothing, and is most likely misspelled.
    fn cert_roles_undefined(&self) -> Vec<String> {
        let defined: HashSet<&str> = self.roles.iter().map(|r| r.name.as_str()).collect();
        let mut lines = Vec::new();
        for entry in &self.identity.cert_map {
            for role in &entry.roles {
                if !role.trim().is_empty()
                    && !role.starts_with("console:")
                    && !defined.contains(role.as_str())
                {
                    lines.push(format!(
                        "[[identity.cert_map]] maps {:?} to role '{role}', which no [[role]] \
                         defines: it grants nothing",
                        entry.identity
                    ));
                }
            }
        }
        for entry in &self.identity.role_map {
            for role in &entry.roles {
                if !role.trim().is_empty()
                    && !role.starts_with("console:")
                    && !defined.contains(role.as_str())
                {
                    lines.push(format!(
                        "[[identity.role_map]] maps {} = {:?} to role '{role}', which no [[role]] \
                         defines: it grants nothing",
                        entry.claim, entry.value
                    ));
                }
            }
        }
        lines
    }

    /// The line for an MCP listener that other machines can reach with
    /// neither TLS nor auth on: whoever reaches it calls the tools, and reads
    /// what passes. A trusted proxy in front terminates TLS for the clients
    /// that come through it, but does not stop one connecting directly: it
    /// counts only where client certificates are `required`, which refuses
    /// such a client.
    fn exposed_in_the_clear(&self) -> Option<String> {
        let g = &self.gateway;
        let proxied =
            g.trusted_proxy.is_some() && g.tls.client_auth.mode == ClientAuthMode::Required;
        if g.tls.mode.is_on() || proxied || g.auth.enabled || g.listens_locally() {
            return None;
        }
        let remedy = match g.trusted_proxy {
            Some(_) => {
                "[gateway.trusted_proxy] does not stop a client connecting to it directly, and \
                 one that does is served as no one unless [gateway.tls.client_auth] mode = \
                 \"required\". Set that mode, or [gateway.auth], or listen on 127.0.0.1 beside \
                 the proxy"
            }
            None => "Set [gateway.tls] and [gateway.auth], or listen on 127.0.0.1",
        };
        Some(format!(
            "[gateway] listen = \"{}\" takes connections from other machines, and neither TLS \
             nor auth is on: whoever can reach it can call every tool it allows, and read what \
             passes. {remedy}",
            g.listen
        ))
    }

    /// The line for a `[gateway.trusted_proxy]` range that holds every
    /// address: a client's certificate is no secret, so whoever reaches the
    /// listener could forward one, and be taken for that client.
    fn trusts_every_address(&self) -> Option<String> {
        let proxy = self.gateway.trusted_proxy.as_ref()?;
        let every = proxy
            .cidrs
            .iter()
            .find(|cidr| Cidr::parse(cidr).is_ok_and(|cidr| cidr.prefix() == 0))?;
        Some(format!(
            "[gateway.trusted_proxy] cidrs entry {every:?} trusts every address: a client's \
             certificate is no secret, so whoever reaches the listener can forward one, and be \
             taken for that client. Name the proxy's own addresses"
        ))
    }

    /// A line for each resource grant whose server part matches no
    /// `[[server]]`: most likely a URI written with no server in front, such
    /// as `urn:isbn:1`, read as server `urn`.
    fn grants_to_no_server(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for role in &self.roles {
            for grant in &role.resource_grants {
                let Ok((server, _)) = resource_grant(grant) else {
                    continue;
                };
                if !self.servers.iter().any(|s| glob::names(&server, &s.id)) {
                    lines.push(format!(
                        "[[role]] '{}': resource grant '{grant}' is for server '{server}', which \
                         no [[server]] is: a grant is 'server-glob:uri-pattern'",
                        role.name
                    ));
                }
            }
        }
        lines
    }

    /// A line for each two servers whose resource allowlists overlap, naming
    /// the first two patterns that do. A read of a URI both take goes to the
    /// one that listed or linked it, and otherwise to the first in config
    /// order: deterministic, but not what the config says.
    fn resource_overlaps(&self) -> Vec<String> {
        let allowlists: Vec<(&str, Vec<UriGlob>)> = self
            .servers
            .iter()
            .map(|s| (s.id.as_str(), s.resource_policy().uris))
            .collect();
        let mut lines = Vec::new();
        for (i, (a, a_globs)) in allowlists.iter().enumerate() {
            for (b, b_globs) in &allowlists[i + 1..] {
                let both = a_globs
                    .iter()
                    .find_map(|x| b_globs.iter().find(|y| x.overlaps(y)).map(|y| (x, y)));
                if let Some((x, y)) = both {
                    lines.push(format!(
                        "servers '{a}' and '{b}' can both serve one resource: '{x}' and '{y}' \
                         overlap. A read goes to the server that listed or linked its URI, and \
                         otherwise to '{a}', the first"
                    ));
                }
            }
        }
        lines
    }

    /// A line for each tool name more than one server's allowlist gives
    /// outright, as it would be listed, worded as the gateway reports it once
    /// it finds the servers offer it; with prefixes, each name so listed that
    /// is too long for some clients, and each prefix two servers share; and
    /// each `prefix` nothing uses. A pattern names no one tool, and what a
    /// server offers is known only once it runs: the gateway reports what it
    /// finds then, at startup.
    fn tool_collisions(&self) -> Vec<String> {
        use crate::gateway::{listed_tool_name, long_name, ToolCollision, LISTED_NAME_WARN};
        let prefixes = self.tool_prefixes();
        let policy = self.to_policy();
        let mut offered: Vec<ToolCollision> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        let mut prefixed: HashMap<&str, &str> = HashMap::new();
        let mut lines = Vec::new();
        for s in &self.servers {
            if prefixes.is_none() && s.prefix.is_some() {
                lines.push(format!(
                    "[[server]] '{}' sets `prefix`, which only `[gateway] tool_namespace = \
                     \"prefix\"` uses",
                    s.id
                ));
            }
            let prefix = prefixes.as_ref().map(|_| self.tool_prefix(s));
            if let Some(prefix) = prefix {
                match prefixed.get(prefix) {
                    Some(earlier) if *earlier != s.id => lines.push(format!(
                        "servers '{earlier}' and '{}' share the tool prefix '{prefix}': a tool \
                         both offer is listed once, from '{earlier}', and a call to it goes there",
                        s.id
                    )),
                    Some(_) => {}
                    None => {
                        prefixed.insert(prefix, &s.id);
                    }
                }
            }
            let Some(allow) = self.resolve_server(s).allow_tools else {
                continue;
            };
            let mut named = HashSet::new();
            for tool in &allow {
                if tool.contains('*')
                    || !policy.tool_is_exposed(&s.id, tool)
                    || !named.insert(tool.as_str())
                {
                    continue;
                }
                let listed = listed_tool_name(prefix, tool);
                if prefix.is_some() && listed.chars().count() > LISTED_NAME_WARN {
                    lines.push(long_name(&s.id, tool, &listed));
                }
                match at.get(&listed) {
                    Some(&i) if !offered[i].servers.contains(&s.id) => {
                        offered[i].servers.push(s.id.clone());
                    }
                    Some(_) => {}
                    None => {
                        at.insert(listed.clone(), offered.len());
                        offered.push(ToolCollision {
                            tool: listed,
                            servers: vec![s.id.clone()],
                        });
                    }
                }
            }
        }
        let collisions = offered.iter().filter(|c| c.servers.len() > 1);
        lines.extend(collisions.map(ToString::to_string));
        lines
    }

    /// A line for each two servers whose prompt allowlists overlap, naming the
    /// first two patterns that do. A prompt both list is shown and got from
    /// the first in config order; one only the second lists goes to it.
    fn prompt_overlaps(&self) -> Vec<String> {
        let allowlists: Vec<(&str, &[String])> = self
            .servers
            .iter()
            .filter_map(|s| Some((s.id.as_str(), s.prompts.as_deref()?)))
            .collect();
        let mut lines = Vec::new();
        for (i, (a, a_globs)) in allowlists.iter().enumerate() {
            for (b, b_globs) in &allowlists[i + 1..] {
                let both = a_globs.iter().find_map(|x| {
                    b_globs
                        .iter()
                        .find(|y| glob::names_overlap(x, y))
                        .map(|y| (x, y))
                });
                if let Some((x, y)) = both {
                    lines.push(format!(
                        "servers '{a}' and '{b}' can both show one prompt: '{x}' and '{y}' \
                         overlap. A prompt goes to the server that listed it, '{a}' if both \
                         did, and otherwise to '{a}', the first"
                    ));
                }
            }
        }
        lines
    }

    /// What stops this config from running: [`validate`]'s errors, and when it
    /// is checked strictly, every one of its [`warnings`] too, as
    /// `strict: <warning>`. It is, with `strict`, as `mcpdef validate
    /// --strict` asks, or with `[gateway] strict = true`. What is left of the
    /// warnings is only to be printed.
    ///
    /// [`validate`]: Config::validate
    /// [`warnings`]: Config::warnings
    pub fn check(&self, strict: bool) -> Checked {
        let mut errors = self.validate();
        let mut warnings = self.warnings();
        if strict || self.gateway.strict {
            errors.extend(warnings.drain(..).map(|w| format!("strict: {w}")));
        }
        Checked { errors, warnings }
    }

    /// Every secret this config names, with where it names it: client keys,
    /// `[server.auth]` secrets, and each value a `[server.env]` sets.
    fn secrets(&self) -> impl Iterator<Item = (String, &SecretRef)> + '_ {
        let env = self.servers.iter().flat_map(|s| {
            s.env.iter().map(move |(name, value)| {
                (format!("server '{}': [server.env] {name}", s.id), value)
            })
        });
        self.client_keys()
            .chain(self.listener_keys())
            .chain(self.auth_secrets())
            .chain(env)
    }

    /// The key of each listener certificate this config names, with where it
    /// names it.
    fn listener_keys(&self) -> impl Iterator<Item = (String, &SecretRef)> + '_ {
        let gateway = self
            .gateway
            .tls
            .key
            .iter()
            .map(|key| ("[gateway.tls] key".to_string(), key));
        let admin = self
            .gateway
            .admin
            .tls
            .iter()
            .filter_map(|tls| tls.key.as_ref())
            .map(|key| ("[gateway.admin.tls] key".to_string(), key));
        let oidc = self
            .gateway
            .admin
            .oidc
            .iter()
            .filter_map(|oidc| oidc.client_secret.as_ref())
            .map(|key| ("[gateway.admin.oidc] client_secret".to_string(), key));
        let session = self.gateway.admin.session.iter().flat_map(|session| {
            let key = session
                .key
                .iter()
                .map(|key| ("[gateway.admin.session] key".to_string(), key));
            let previous = session
                .previous_key
                .iter()
                .map(|key| ("[gateway.admin.session] previous_key".to_string(), key));
            key.chain(previous)
        });
        gateway.chain(admin).chain(session).chain(oidc)
    }

    /// Every `[server.auth]` secret this config names, with where it names it.
    fn auth_secrets(&self) -> impl Iterator<Item = (String, &SecretRef)> + '_ {
        self.servers.iter().filter_map(|s| {
            let (field, secret) = s.auth.as_ref()?.secret()?;
            Some((format!("server '{}': [server.auth] {field}", s.id), secret))
        })
    }

    /// Every client key this config names, with where it names it.
    fn client_keys(&self) -> impl Iterator<Item = (String, &SecretRef)> + '_ {
        let gateway = self
            .gateway
            .upstream_tls
            .client_key
            .iter()
            .map(|key| ("[gateway.upstream_tls] client_key".to_string(), key));
        let servers = self.servers.iter().filter_map(|s| {
            let key = s.tls.as_ref()?.client_key.as_ref()?;
            Some((format!("server '{}': [server.tls] client_key", s.id), key))
        });
        gateway.chain(servers)
    }

    /// Where this config holds a secret itself: each client key and
    /// `[server.auth]` secret written in it, and each `[server.env]` value
    /// written in it that is a secret, by its name or by its shape (see
    /// [`a_secret`]).
    fn literal_secrets(&self) -> impl Iterator<Item = String> + '_ {
        let keys = self
            .client_keys()
            .chain(self.listener_keys())
            .chain(self.auth_secrets())
            .filter(|(_, key)| key.scheme() == "literal")
            .map(|(name, _)| name);
        let env = self.servers.iter().flat_map(|s| {
            s.env
                .iter()
                .filter(|(name, value)| match value {
                    SecretRef::Literal(value) => a_secret(name, value.expose_secret()),
                    _ => false,
                })
                .map(move |(name, _)| format!("server '{}': [server.env] {name}", s.id))
        });
        keys.chain(env)
    }

    /// The variables of MCPdef's own environment this config reads secrets
    /// from. No stdio upstream inherits them: one sees such a variable only
    /// when its `[server.env]` sets it.
    pub fn secret_vars(&self) -> Vec<String> {
        let mut vars: Vec<String> = self
            .secrets()
            .filter_map(|(_, secret)| secret.var().map(str::to_string))
            .collect();
        vars.sort();
        vars.dedup();
        vars
    }

    /// Structural validation. Returns the list of problems (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.servers.is_empty() {
            errs.push(
                "no [[server]] entries — the gateway must front at least one upstream".to_string(),
            );
        }
        let mut seen = HashSet::new();
        for s in &self.servers {
            if s.id.trim().is_empty() {
                errs.push("a [[server]] has an empty `id`".to_string());
            } else if !seen.insert(s.id.clone()) {
                errs.push(format!("duplicate server id '{}'", s.id));
            }
            if !SUPPORTED_TRANSPORTS.contains(&s.transport.as_str()) {
                errs.push(format!(
                    "server '{}': unknown transport '{}' (expected one of {:?})",
                    s.id, s.transport, SUPPORTED_TRANSPORTS
                ));
                continue;
            }
            match s.transport.as_str() {
                "stdio" => {
                    if s.command.is_empty() {
                        errs.push(format!(
                            "server '{}': stdio transport needs a non-empty `command`",
                            s.id
                        ));
                    }
                }
                "streamable-http" | "sse" => {
                    if s.url.is_none() {
                        errs.push(format!(
                            "server '{}': '{}' transport needs a `url`",
                            s.id, s.transport
                        ));
                    }
                }
                "wasm" => {
                    if s.wasm_path().is_none() {
                        errs.push(format!(
                            "server '{}': wasm transport needs a `wasm` module path",
                            s.id
                        ));
                    }
                }
                "wasm-component" => {
                    if s.wasm_path().is_none() {
                        errs.push(format!(
                            "server '{}': wasm-component transport needs a `wasm` component path",
                            s.id
                        ));
                    }
                    // Surface a malformed egress allowlist entry at config-load time.
                    if let Err(e) = s.egress_allow() {
                        errs.push(e);
                    }
                }
                _ => {}
            }
            if let Some(p) = &s.profile {
                if !self.profiles.contains_key(p) {
                    errs.push(format!(
                        "server '{}': references unknown profile '{}'",
                        s.id, p
                    ));
                }
            }
            if s.max_inflight == Some(0) {
                errs.push(format!(
                    "server '{}': max_inflight must be at least 1 (0 would let no call through)",
                    s.id
                ));
            }
            for pattern in s.resources.iter().flatten() {
                if let Err(e) = UriGlob::new(pattern) {
                    errs.push(format!(
                        "server '{}': resources entry '{pattern}' {e}",
                        s.id
                    ));
                }
            }
            for name in s.env.keys() {
                if name.is_empty() || name.contains(['=', '\0']) {
                    errs.push(format!(
                        "server '{}': [server.env] {name:?} names no environment variable",
                        s.id
                    ));
                }
            }
            if s.auth.is_some() {
                if !s.is_http() {
                    let stdio = match s.transport.as_str() {
                        "stdio" => ": a stdio server gets its credentials in [server.env]",
                        _ => "",
                    };
                    errs.push(format!(
                        "server '{}': [server.auth] is for a streamable-http or sse upstream, \
                         and this one is {}{stdio}",
                        s.id, s.transport
                    ));
                } else if let Some(Err(e)) = s.credentials() {
                    errs.push(format!("server '{}': [server.auth] {e}", s.id));
                }
            }
        }
        if let Some(p) = &self.gateway.profile {
            if !self.profiles.contains_key(p) {
                errs.push(format!(
                    "[gateway] profile '{p}' is not defined as a [profile.{p}]"
                ));
            }
        }
        errs.extend(self.tls_problems());
        let proxy = self.gateway.trusted_proxy.as_ref();
        errs.extend(self.gateway.tls.problems("[gateway.tls]", proxy.is_some()));
        if let Some(tls) = &self.gateway.admin.tls {
            errs.extend(tls.problems("[gateway.admin.tls]", false));
        }
        errs.extend(self.gateway.admin_problems());
        if let Some(proxy) = proxy {
            errs.extend(proxy.problems(&self.gateway.tls.client_auth));
        }
        if self.gateway.state_dir.trim().is_empty() {
            errs.push(
                "[gateway] state_dir is empty: name a directory MCPdef can write to".to_string(),
            );
        }
        // Rate-limit sanity: a set rate must be positive and a set burst >= 1
        // (a sub-1 bucket can never hold a whole token, so it would deny every call).
        let rl = &self.gateway.rate_limit;
        for (name, rate) in [
            ("per_tool_per_sec", rl.per_tool_per_sec),
            ("global_per_sec", rl.global_per_sec),
        ] {
            if let Some(r) = rate {
                if !r.is_finite() || r <= 0.0 {
                    errs.push(format!(
                        "[gateway.rate_limit] {name} must be a finite number > 0"
                    ));
                }
            }
        }
        for (name, burst) in [
            ("per_tool_burst", rl.per_tool_burst),
            ("global_burst", rl.global_burst),
        ] {
            if let Some(b) = burst {
                if !b.is_finite() || b < 1.0 {
                    errs.push(format!(
                        "[gateway.rate_limit] {name} must be a finite number >= 1"
                    ));
                }
            }
        }
        // When the burst is omitted it DEFAULTS to the rate (see `rate_limit_settings`),
        // so a sub-1 rate without an explicit burst yields a bucket that can never
        // admit a whole token — every call would be denied. Reject that combination.
        for (rate_name, rate, burst_name, burst) in [
            (
                "per_tool_per_sec",
                rl.per_tool_per_sec,
                "per_tool_burst",
                rl.per_tool_burst,
            ),
            (
                "global_per_sec",
                rl.global_per_sec,
                "global_burst",
                rl.global_burst,
            ),
        ] {
            if burst.is_none() {
                if let Some(r) = rate {
                    if r.is_finite() && r < 1.0 {
                        errs.push(format!(
                            "[gateway.rate_limit] {rate_name} < 1 requires an explicit `{burst_name}` >= 1 (a sub-1 bucket admits no calls)"
                        ));
                    }
                }
            }
        }
        // Auth: when enabled, the RS needs an issuer, an audience (resource), and a
        // key source (inline JWKS or a jwks_uri). Treat blank/whitespace strings as
        // missing — an empty `issuer = ""` is no more usable than an unset one.
        let auth = &self.gateway.auth;
        let blank = |o: &Option<String>| match o.as_deref() {
            None => true,
            Some(s) => s.trim().is_empty(),
        };
        if auth.enabled && auth.takes(AuthMethod::Bearer) {
            if blank(&auth.issuer) {
                errs.push("[gateway.auth] enabled but `issuer` is not set".to_string());
            }
            if blank(&auth.resource) {
                errs.push(
                    "[gateway.auth] enabled but `resource` (audience) is not set".to_string(),
                );
            }
            if blank(&auth.jwks) && blank(&auth.jwks_uri) && !auth.discovery {
                errs.push(
                    "[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set".to_string(),
                );
            }
            if auth.discovery && !(blank(&auth.jwks) && blank(&auth.jwks_uri)) {
                errs.push(
                    "[gateway.auth] discovery finds jwks_uri itself: set it, or `jwks` or \
                     `jwks_uri`, not both"
                        .to_string(),
                );
            }
            for audience in &auth.audiences {
                if audience.trim().is_empty() {
                    errs.push("[gateway.auth] audiences holds an empty audience".to_string());
                }
            }
        }
        let api_audience = self
            .gateway
            .admin
            .oidc
            .as_ref()
            .and_then(|o| o.api_audience.as_deref());
        if let Some(audience) = api_audience.filter(|a| auth.audiences.iter().any(|b| b == a)) {
            errs.push(format!(
                "[gateway.admin.oidc] api_audience = {audience:?} is one of [gateway.auth] \
                 audiences: a token for the MCP listener would open the admin API; give the \
                 admin API an audience of its own"
            ));
        }
        errs.extend(self.auth_method_problems());
        errs.extend(self.key_problems());
        errs.extend(self.cert_map_problems());
        for role in &self.roles {
            if role.name.trim().is_empty() {
                errs.push("a [[role]] has an empty `name`".to_string());
            }
            for grant in &role.resource_grants {
                if let Err(e) = resource_grant(grant) {
                    errs.push(format!(
                        "[[role]] '{}': resource grant '{grant}' {e}",
                        role.name
                    ));
                }
            }
        }
        // Each tool prefix, when tools are listed with one, must be a start a
        // tool name may have: what is listed is `<prefix>__<name>`.
        if self.gateway.tool_namespace == ToolNamespace::Prefix {
            for s in &self.servers {
                let prefix = self.tool_prefix(s);
                let named = prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
                if prefix.is_empty() || !named {
                    let (whose, or) = match s.prefix {
                        None => (", its id,", ", or set `prefix`"),
                        Some(_) => ("", ""),
                    };
                    errs.push(format!(
                        "server '{}': tool prefix '{prefix}'{whose} is not one a tool name may \
                         start with: use letters, digits, '_', '-' and '.'{or}",
                        s.id
                    ));
                }
            }
        }
        // Inspect mode, if set, must be a recognized value — a typo silently
        // disabling scanning would be a dangerous fail-open.
        if let Some(mode) = &self.gateway.inspect.mode {
            if mcpdef_inspect::Mode::parse(mode).is_none() {
                errs.push(format!(
                    "[gateway.inspect] `mode` must be off/warn/enforce/redact, got '{mode}'"
                ));
            }
        }
        // Policy rules: a recognized effect, a name, and each arg predicate must
        // name exactly one operator (a mis-typed predicate that matched nothing
        // would silently weaken a deny).
        for r in &self.policy {
            if r.name.trim().is_empty() {
                errs.push("a [[policy]] rule has an empty `name`".to_string());
            }
            let transform = r.is_transform();
            if !transform
                && !r.effect.eq_ignore_ascii_case("allow")
                && !r.effect.eq_ignore_ascii_case("deny")
            {
                errs.push(format!(
                    "[[policy]] rule '{}' has `effect` '{}' (must be allow/deny/transform)",
                    r.name, r.effect
                ));
            }
            // A transform rewrites tool-call arguments, and the results of tool
            // calls and reads, and nothing else; its keys mean nothing on a
            // rule that allows or denies.
            if transform {
                if r.set_args.is_empty() && r.result.is_empty() {
                    errs.push(format!(
                        "[[policy]] rule '{}' is a transform with no `set_args` and no \
                         `result`, and so changes nothing",
                        r.name
                    ));
                }
                if r.uris.is_some() && !r.set_args.is_empty() {
                    errs.push(format!(
                        "[[policy]] rule '{}' is a transform with `set_args`, which edit \
                         tool-call arguments, and cannot name `uris`: a read has none",
                        r.name
                    ));
                }
                if r.prompts.is_some() {
                    errs.push(format!(
                        "[[policy]] rule '{}' is a transform, which rewrites tool calls and \
                         reads, and cannot name `prompts`",
                        r.name
                    ));
                }
                if let Err(why) = r.on_error() {
                    errs.push(format!("[[policy]] rule '{}' {why}", r.name));
                }
            } else {
                for (key, named) in [
                    ("set_args", !r.set_args.is_empty()),
                    ("on_error", r.on_error.is_some()),
                    ("result", !r.result.is_empty()),
                ] {
                    if named {
                        errs.push(format!(
                            "[[policy]] rule '{}' has `{key}`, which only a transform rule takes",
                            r.name
                        ));
                    }
                }
            }
            for (at, edit) in r.result.iter().enumerate() {
                if let Err(why) = edit.to_result_edit() {
                    errs.push(format!(
                        "[[policy]] rule '{}' result entry {} {why}",
                        r.name,
                        at + 1
                    ));
                }
            }
            for edit in &r.set_args {
                if let Err(why) = edit.to_arg_edit() {
                    errs.push(format!(
                        "[[policy]] rule '{}' set_args '{}' {why}",
                        r.name, edit.path
                    ));
                }
            }
            // An explicit empty condition list matches nothing at runtime, so a
            // `deny` with `servers = []` / `tools = []` / `agents = []` would never
            // fire (a silent fail-open). Require the field be omitted (= any) or
            // non-empty.
            for (dim, list) in [
                ("agents", &r.agents),
                ("servers", &r.servers),
                ("tools", &r.tools),
                ("uris", &r.uris),
                ("prompts", &r.prompts),
            ] {
                if matches!(list, Some(v) if v.is_empty()) {
                    errs.push(format!(
                        "[[policy]] rule '{}' has an empty `{dim}` list — omit it to match any, or list entries",
                        r.name
                    ));
                }
            }
            // What a rule is about: each request is exactly one of these.
            let kinds = [
                ("tools", r.tools.is_some()),
                ("uris", r.uris.is_some()),
                ("prompts", r.prompts.is_some()),
            ];
            for (a, b, why) in [
                (0, 1, "a tool call has no URI, and a read no tool"),
                (0, 2, "a tool call has no prompt, and a prompt get no tool"),
                (1, 2, "a read has no prompt, and a prompt get no URI"),
            ] {
                if kinds[a].1 && kinds[b].1 {
                    errs.push(format!(
                        "[[policy]] rule '{}' names both `{}` and `{}`, and so matches \
                         nothing: {why}",
                        r.name, kinds[a].0, kinds[b].0
                    ));
                }
            }
            if r.uris.is_some() && !r.args.is_empty() {
                errs.push(format!(
                    "[[policy]] rule '{}' names both `uris` and `args`, and so matches nothing: \
                     a read has no arguments",
                    r.name
                ));
            }
            for pattern in r.uris.iter().flatten() {
                if let Err(e) = UriGlob::new(pattern) {
                    errs.push(format!(
                        "[[policy]] rule '{}' uris entry '{pattern}' {e}",
                        r.name
                    ));
                }
            }
            for a in &r.args {
                let ops = [
                    a.equals.is_some(),
                    a.glob.is_some(),
                    a.contains.is_some(),
                    a.exists == Some(true),
                ]
                .iter()
                .filter(|b| **b)
                .count();
                if ops != 1 {
                    errs.push(format!(
                        "[[policy]] rule '{}' arg '{}' must name exactly one of equals/glob/contains/exists (found {ops})",
                        r.name, a.path
                    ));
                }
            }
        }
        errs
    }

    /// What is wrong with the TLS profiles: each table checked on its own,
    /// the files it names read, and what only `[server.tls]` may set.
    fn tls_problems(&self) -> Vec<String> {
        let gateway = &self.gateway.upstream_tls;
        let mut problems = Vec::new();
        if gateway.connect_to.is_some() {
            problems.push(
                "[gateway.upstream_tls] connect_to names one upstream's address: set it in \
                 that server's [server.tls]"
                    .to_string(),
            );
        }
        if gateway.insecure_skip_verify.is_some() {
            problems.push(
                "[gateway.upstream_tls] insecure_skip_verify is never a gateway-wide setting: \
                 set it in the [server.tls] of the one upstream that needs it"
                    .to_string(),
            );
        }
        if gateway.pin_sha256.is_some() {
            problems.push(
                "[gateway.upstream_tls] pin_sha256 names one upstream's key: set it in that \
                 server's [server.tls]"
                    .to_string(),
            );
        }
        problems.extend(gateway.problems("[gateway.upstream_tls]"));
        let egress = self.gateway.egress_policy();
        for s in &self.servers {
            let Some(tls) = &s.tls else { continue };
            let table = format!("server '{}': [server.tls]", s.id);
            if !s.is_https() {
                let what = match (s.is_http(), s.url.as_deref()) {
                    (true, Some(url)) => format!("its url is {}", crate::redact::redact_url(url)),
                    _ => format!("it is {}", s.transport),
                };
                problems.push(format!("{table} is for an https:// upstream, and {what}"));
                continue;
            }
            if let Some(pins) = &tls.pin_sha256 {
                if pins.is_empty() {
                    problems.push(format!(
                        "{table} pin_sha256 is empty, which pins nothing: list the pins \
                         `mcpdef tls pin` prints, or leave it out"
                    ));
                }
                if tls.insecure_skip_verify == Some(true) {
                    problems.push(format!(
                        "{table} pin_sha256 and insecure_skip_verify = true contradict each \
                         other: a pin is how to trust a server nothing else vouches for"
                    ));
                }
                let chain: Vec<&str> = [
                    ("roots", tls.roots.is_some()),
                    ("ca", tls.ca.is_some()),
                    ("crl", tls.crl.is_some()),
                ]
                .into_iter()
                .filter_map(|(key, set)| set.then_some(key))
                .collect();
                if !chain.is_empty() {
                    problems.push(format!(
                        "{table} pin_sha256 trusts the key alone, so {} would do nothing here: \
                         leave {} out",
                        chain.join(", "),
                        if chain.len() == 1 { "it" } else { "them" }
                    ));
                }
            }
            match s.connect_to() {
                Err(e) => problems.push(e),
                Ok(Some(ip)) => {
                    let url = s.url.as_deref().unwrap_or_default();
                    if let Err(e) = mcpdef_transport::check_connect_to(url, ip, &egress) {
                        let e = match e {
                            TransportError::Egress(e) => e,
                            e => e.to_string(),
                        };
                        problems.push(format!("{table} connect_to {ip}: {e}"));
                    }
                }
                Ok(None) => {}
            }
            problems.extend(tls.problems(&table));
        }
        problems
    }

    /// Resolve a server's effective allow/deny, applying its referenced profile.
    /// Inline `tools` **replaces** the profile's allowlist (a server-specific
    /// allowlist wins); inline `deny` is **appended** to the profile's deny
    /// (denies accumulate — deny-by-default safety).
    pub fn resolve_server(&self, s: &ServerConfig) -> ServerPolicy {
        let prof = s.profile.as_ref().and_then(|n| self.profiles.get(n));
        let allow_tools = s
            .tools
            .clone()
            .or_else(|| prof.and_then(|p| p.tools.clone()));
        let mut deny = prof.map(|p| p.deny.clone()).unwrap_or_default();
        deny.extend(s.deny.iter().cloned());
        ServerPolicy { allow_tools, deny }
    }

    /// The gateway's active profile as a [`ServerPolicy`], if set and defined.
    pub fn active_profile(&self) -> Option<ServerPolicy> {
        let name = self.gateway.profile.as_ref()?;
        let p = self.profiles.get(name)?;
        Some(ServerPolicy {
            allow_tools: p.tools.clone(),
            deny: p.deny.clone(),
        })
    }

    /// With `tool_namespace = "prefix"`, each server's tool prefix by its id:
    /// its `prefix`, or its id. `None` when tools are listed as served.
    pub fn tool_prefixes(&self) -> Option<HashMap<String, String>> {
        (self.gateway.tool_namespace == ToolNamespace::Prefix).then(|| {
            self.servers
                .iter()
                .map(|s| (s.id.clone(), self.tool_prefix(s).to_string()))
                .collect()
        })
    }

    /// `s`'s tool prefix, used with `tool_namespace = "prefix"`.
    fn tool_prefix<'a>(&self, s: &'a ServerConfig) -> &'a str {
        s.prefix.as_deref().unwrap_or(&s.id)
    }

    /// Build the allowlist policy: per-server rules (with profiles resolved) plus
    /// the gateway-wide active profile.
    pub fn to_policy(&self) -> Policy {
        let mut map = HashMap::new();
        for s in &self.servers {
            map.insert(s.id.clone(), self.resolve_server(s));
        }
        let mut policy = Policy::from_map(map).with_active(self.active_profile());
        for s in &self.servers {
            policy.insert_resources(s.id.clone(), s.resource_policy());
            policy.insert_prompts(s.id.clone(), s.prompts.clone().unwrap_or_default());
        }
        policy
    }

    /// Build the RBAC model from `[[role]]`. Each grant `"server:tool"` becomes a
    /// `(server-glob, tool-glob)`; a bare `"tool"` (no colon) grants it on any
    /// server. Prompt grants read the same way. Empty when no roles are defined
    /// (the RBAC gate stays off).
    pub fn rbac(&self) -> Rbac {
        let name_grant = |g: &String| match g.split_once(':') {
            Some((server, name)) => (server.to_string(), name.to_string()),
            None => ("*".to_string(), g.to_string()),
        };
        let mut rbac = Rbac::new();
        for role in &self.roles {
            rbac.insert_role(
                role.name.clone(),
                role.grants.iter().map(name_grant).collect(),
            );
            rbac.insert_prompt_grants(
                role.name.clone(),
                role.prompt_grants.iter().map(name_grant).collect(),
            );
            // A grant that is not one grants nothing; `validate` refuses it.
            let reads = role
                .resource_grants
                .iter()
                .filter_map(|g| resource_grant(g).ok())
                .collect();
            rbac.insert_resource_grants(role.name.clone(), reads);
        }
        for entry in &self.identity.cert_map {
            rbac.map_certificates(entry.identity.clone(), entry.roles.clone());
        }
        rbac
    }

    /// Build the policy-as-code rule set from `[[policy]]`, preserving config order
    /// (first-match-wins). Empty when no rules are defined (the engine stays off).
    pub fn policy_rules(&self) -> PolicyRules {
        let rules = self
            .policy
            .iter()
            .map(|r| Rule {
                name: r.name.clone(),
                // An edit or an `on_error` that is not one does nothing, and
                // denies on a failure; `validate` refuses both.
                effect: if r.is_transform() {
                    Effect::Transform(Transform {
                        edits: r
                            .set_args
                            .iter()
                            .filter_map(|edit| edit.to_arg_edit().ok())
                            .collect(),
                        result: r
                            .result
                            .iter()
                            .filter_map(|edit| edit.to_result_edit().ok())
                            .collect(),
                        on_error: r.on_error().unwrap_or_default(),
                    })
                } else if r.effect.eq_ignore_ascii_case("deny") {
                    Effect::Deny
                } else {
                    Effect::Allow
                },
                agents: r.agents.clone(),
                servers: r.servers.clone(),
                tools: r.tools.clone(),
                uris: r.uris.as_ref().map(|patterns| {
                    patterns
                        .iter()
                        .filter_map(|p| UriGlob::new(p).ok())
                        .collect()
                }),
                prompts: r.prompts.clone(),
                args: r
                    .args
                    .iter()
                    .filter_map(ArgMatchConfig::to_arg_match)
                    .collect(),
            })
            .collect();
        // A `redact` finds secrets as inspect does, with the operator's own
        // substrings, whatever inspect's mode.
        let redacts = self
            .policy
            .iter()
            .any(|r| r.result.iter().any(|edit| edit.redact.is_some()));
        let rules = PolicyRules::new(rules);
        let scanner = mcpdef_inspect::Scanner::new(mcpdef_inspect::Mode::Warn)
            .filter(|_| redacts)
            .map(|s| s.with_extra_secrets(self.gateway.inspect.secret_substrings.clone()));
        match scanner {
            Some(scanner) => rules.with_secrets(Arc::new(move |text: &str| {
                scanner
                    .find_all(text)
                    .into_iter()
                    .filter(|m| m.category == mcpdef_inspect::Category::Secret)
                    .map(|m| Detected {
                        range: m.range,
                        rule: m.rule_id,
                        secret: true,
                    })
                    .collect()
            })),
            None => rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::Decision;

    const GOOD: &str = r#"
        [gateway]
        listen = "127.0.0.1:7878"
        audit  = "./audit/mcpdef.log"

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        tools = ["list_issues"]
        deny = ["delete_*"]
    "#;

    #[test]
    fn parses_and_validates_good_config() {
        let cfg: Config = toml::from_str(GOOD).unwrap();
        assert!(cfg.validate().is_empty());
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.gateway.listen, "127.0.0.1:7878");
        let pol = cfg.to_policy();
        assert!(pol.is_governed("github"));
        assert!(pol.decide_tool("github", "delete_repo").as_str() == "deny");
        assert!(pol.decide_tool("github", "list_issues").is_allow());
    }

    /// The knob has to survive the round trip an operator actually makes:
    /// a string in TOML. An enum that only ever gets constructed in Rust is a
    /// knob nobody can turn.
    #[test]
    fn the_wire_mode_parses_from_toml_and_defaults_to_legacy() {
        let with = |line: &str| -> Result<Config, toml::de::Error> {
            toml::from_str(&format!(
                "[gateway]\n{line}\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n"
            ))
        };

        assert_eq!(
            with("").unwrap().gateway.wire,
            WireMode::Legacy,
            "an upgrade must not change what an existing deployment accepts"
        );
        assert_eq!(
            with(r#"wire = "legacy""#).unwrap().gateway.wire,
            WireMode::Legacy
        );
        assert_eq!(
            with(r#"wire = "dual""#).unwrap().gateway.wire,
            WireMode::Dual
        );
        assert_eq!(
            with(r#"wire = "modern""#).unwrap().gateway.wire,
            WireMode::Modern
        );

        // A typo is refused at load, naming what is accepted, rather than
        // silently leaving the listener on a wire the operator did not intend.
        let e = with(r#"wire = "stateless""#).unwrap_err().to_string();
        assert!(e.contains("legacy") && e.contains("modern"), "got: {e}");
    }

    /// The per-server knob, through the TOML an operator actually writes.
    #[test]
    fn an_upstream_spec_parses_from_toml_and_defaults_to_the_old_wire() {
        let with = |line: &str| -> Result<Config, toml::de::Error> {
            toml::from_str(&format!(
                "[gateway]\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n{line}\n"
            ))
        };

        assert_eq!(
            with("").unwrap().servers[0].spec,
            SpecSetting::V20251125,
            "an unset knob must keep speaking the old wire"
        );
        assert_eq!(
            with(r#"spec = "2026-07-28""#).unwrap().servers[0].spec,
            SpecSetting::V20260728
        );
        assert_eq!(
            with(r#"spec = "auto""#).unwrap().servers[0].spec,
            SpecSetting::Auto,
            "auto is accepted now that something actually probes"
        );

        // A revision MCPdef does not speak is refused at load, naming what it
        // does, rather than silently leaving the upstream on a wire the operator
        // did not intend.
        let e = with(r#"spec = "2024-11-05""#).unwrap_err().to_string();
        assert!(
            e.contains("2026-07-28") && e.contains("auto"),
            "the error must name what is accepted: {e}"
        );
    }

    /// `auto` validates on every transport, which it did not always.
    ///
    /// It was refused off stdio while the era probe sent `server/discover`: that
    /// message would have consumed the same first request `HttpClient` uses to
    /// select its binding. Probing with `initialize` removes the conflict —
    /// the probe *is* the opening request — so the knob means the same thing
    /// everywhere and the config no longer has to say otherwise.
    #[test]
    fn auto_is_accepted_on_every_transport() {
        for transport in ["stdio", "streamable-http", "sse"] {
            let body = if transport == "stdio" {
                r#"command = ["true"]"#.to_string()
            } else {
                r#"url = "http://127.0.0.1:9/mcp""#.to_string()
            };
            for spec in ["auto", "2025-11-25", "2026-07-28"] {
                let cfg: Config = toml::from_str(&format!(
                    r#"
                    [gateway]
                    [[server]]
                    id = "remote"
                    transport = "{transport}"
                    {body}
                    spec = "{spec}"
                "#
                ))
                .unwrap();
                assert!(
                    cfg.validate().is_empty(),
                    "{transport} + {spec} should validate, got: {:?}",
                    cfg.validate()
                );
            }
        }
    }

    #[test]
    fn defaults_fill_in() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert_eq!(cfg.gateway.listen, "127.0.0.1:7878");
        assert_eq!(cfg.gateway.audit, "./mcpdef-audit/audit.log");
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn flags_missing_command_and_unknown_transport() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "a"
            transport = "stdio"
            [[server]]
            id = "b"
            transport = "carrier-pigeon"
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("non-empty `command`")));
        assert!(errs.iter().any(|e| e.contains("unknown transport")));
    }

    #[test]
    fn wasm_transport_requires_a_module_path_and_carries_sandbox_limits() {
        // Missing `wasm` path is a validation error.
        let missing: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "sandboxed"
            transport = "wasm"
        "#,
        )
        .unwrap();
        assert!(missing
            .validate()
            .iter()
            .any(|e| e.contains("wasm transport needs a `wasm` module path")));

        // A blank / whitespace-only path is treated the same as missing (it would
        // otherwise fail later as a confusing file-not-found at load time).
        let blank: Config = toml::from_str(
            "[gateway]\n[[server]]\nid = \"sandboxed\"\ntransport = \"wasm\"\nwasm = \"   \"\n",
        )
        .unwrap();
        assert!(blank
            .validate()
            .iter()
            .any(|e| e.contains("wasm transport needs a `wasm` module path")));
        assert!(blank.servers[0].wasm_path().is_none());

        // With a module path it validates, and the per-server fuel/memory
        // overrides flow into the sandbox limits (others fall back to defaults).
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "sandboxed"
            transport = "wasm"
            wasm = "./echo.wasm"
            wasm_fuel = 5000000
            wasm_max_memory_mb = 16
            wasm_deadline_ms = 250
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty());
        let limits = ok.servers[0].sandbox_limits();
        assert_eq!(limits.fuel_per_call, 5_000_000);
        assert_eq!(limits.max_memory_bytes, 16 * 1024 * 1024);
        assert_eq!(limits.deadline, Some(std::time::Duration::from_millis(250)));
    }

    #[test]
    fn wasm_component_requires_path_and_validates_egress_allowlist() {
        // Missing component path → error.
        let missing: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
        "#,
        )
        .unwrap();
        assert!(missing
            .validate()
            .iter()
            .any(|e| e.contains("wasm-component transport needs a `wasm` component path")));

        // A malformed egress entry is rejected at config-load time.
        let bad_egress: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
            wasm = "./server.wasm"
            wasm_allow_egress = ["not-an-addr"]
        "#,
        )
        .unwrap();
        assert!(bad_egress
            .validate()
            .iter()
            .any(|e| e.contains("is not a valid ip:port")));

        // A well-formed component server with an ip:port allowlist validates, and
        // the allowlist parses.
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "comp"
            transport = "wasm-component"
            wasm = "./server.wasm"
            wasm_allow_egress = ["10.1.2.3:5432", "203.0.113.9:443"]
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty());
        assert!(ok.servers[0].egress_allow().is_ok());
    }

    #[test]
    fn flags_empty_server_list_and_duplicates() {
        let empty: Config = toml::from_str("[gateway]\n").unwrap();
        assert!(empty
            .validate()
            .iter()
            .any(|e| e.contains("at least one upstream")));

        let dup: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(dup
            .validate()
            .iter()
            .any(|e| e.contains("duplicate server id")));
    }

    const PROFILES: &str = r#"
        [gateway]
        profile = "readonly"

        [profile.readonly]
        tools = ["get_*", "list_*"]
        deny  = ["*_secret"]

        [[server]]
        id = "github"
        transport = "stdio"
        command = ["mcp-server-github"]
        profile = "readonly"
        deny = ["delete_*"]          # appended to the profile's deny

        [[server]]
        id = "db"
        transport = "stdio"
        command = ["mcp-db"]
        profile = "readonly"
        tools = ["query"]            # replaces the profile's allowlist
    "#;

    #[test]
    fn profile_resolution_merges_allow_and_deny() {
        let cfg: Config = toml::from_str(PROFILES).unwrap();
        assert!(cfg.validate().is_empty());

        // github: inherits the profile allowlist (get_*/list_*), deny is the
        // union of the profile's *_secret and the server's delete_*.
        let gh = cfg.resolve_server(&cfg.servers[0]);
        assert_eq!(gh.allow_tools.as_ref().unwrap(), &["get_*", "list_*"]);
        assert!(gh.deny.contains(&"*_secret".to_string()));
        assert!(gh.deny.contains(&"delete_*".to_string()));

        // db: inline tools REPLACE the profile allowlist; profile deny still applies.
        let db = cfg.resolve_server(&cfg.servers[1]);
        assert_eq!(db.allow_tools.as_ref().unwrap(), &["query"]);
        assert!(db.deny.contains(&"*_secret".to_string()));
    }

    #[test]
    fn active_profile_scopes_the_gateway() {
        let cfg: Config = toml::from_str(PROFILES).unwrap();
        let pol = cfg.to_policy();
        // github would expose get_*/list_* per its (profile) allowlist…
        assert!(pol.decide_tool("github", "get_file").is_allow());
        assert!(pol.decide_tool("github", "list_issues").is_allow());
        // …and the deny union still bites.
        assert_eq!(pol.decide_tool("github", "delete_repo").as_str(), "deny");
        assert_eq!(pol.decide_tool("github", "api_secret").as_str(), "deny");
        // db's inline allowlist is [query]; the active readonly profile excludes
        // it (query is neither get_* nor list_*), so it is denied gateway-wide.
        match pol.decide_tool("db", "query") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "not-in-active-profile"),
            other => panic!("expected active-profile deny, got {other:?}"),
        }
    }

    #[test]
    fn validate_flags_unknown_profile_references() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            profile = "ghost"
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
            profile = "nope"
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("unknown profile 'nope'")));
        assert!(errs.iter().any(|e| e.contains("profile 'ghost'")));
    }

    #[test]
    fn rate_limit_settings_default_burst_and_timeout() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            upstream_timeout_ms = 2000
            [gateway.rate_limit]
            per_tool_per_sec = 5
            global_per_sec = 100
            global_burst = 200
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty());
        let (per_tool, global) = cfg.gateway.rate_limit_settings();
        assert_eq!(per_tool, Some((5.0, 5.0))); // burst defaults to the rate
        assert_eq!(global, Some((100.0, 200.0))); // explicit burst kept
        assert_eq!(
            cfg.gateway.upstream_timeout(),
            Some(std::time::Duration::from_millis(2000))
        );
    }

    #[test]
    fn max_inflight_defaults_by_transport_and_is_at_least_one() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "a"
            transport = "stdio"
            command = ["true"]
            [[server]]
            id = "b"
            transport = "wasm"
            wasm = "m.wasm"
            [[server]]
            id = "c"
            transport = "wasm-component"
            wasm = "c.wasm"
            [[server]]
            id = "d"
            transport = "streamable-http"
            url = "http://127.0.0.1:1/mcp"
            max_inflight = 4
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
        let caps: Vec<usize> = cfg.servers.iter().map(ServerConfig::max_inflight).collect();
        assert_eq!(caps, [16, 1, 1, 4]);

        let zero: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "z"
            transport = "stdio"
            command = ["true"]
            max_inflight = 0
        "#,
        )
        .unwrap();
        assert_eq!(
            zero.validate(),
            ["server 'z': max_inflight must be at least 1 (0 would let no call through)"]
        );
    }

    #[test]
    fn validate_rejects_nonpositive_rate() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0
            global_burst = 0.5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("per_tool_per_sec")));
        assert!(errs.iter().any(|e| e.contains("global_burst")));
    }

    #[test]
    fn validate_rejects_sub1_rate_without_explicit_burst() {
        // rate < 1 with no burst → burst defaults to the rate → a dead bucket.
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0.5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(
            errs.iter()
                .any(|e| e.contains("per_tool_per_sec") && e.contains("per_tool_burst")),
            "got: {errs:?}"
        );

        // …but the same rate WITH an explicit burst >= 1 is fine.
        let ok: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.rate_limit]
            per_tool_per_sec = 0.5
            per_tool_burst = 5
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(ok.validate().is_empty(), "got: {:?}", ok.validate());
    }

    #[test]
    fn validate_treats_blank_auth_fields_as_missing() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled = true
            issuer = ""
            resource = "   "
            jwks = ""
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("`issuer`")), "got: {errs:?}");
        assert!(errs.iter().any(|e| e.contains("`resource`")));
        assert!(errs.iter().any(|e| e.contains("`jwks`")));
    }

    #[test]
    fn validate_flags_incomplete_auth() {
        // enabled but no issuer / resource / key source.
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled = true
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("`issuer`")));
        assert!(errs.iter().any(|e| e.contains("`resource`")));
        assert!(errs.iter().any(|e| e.contains("`jwks`")));
    }

    #[test]
    fn complete_auth_validates_and_rbac_builds() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [gateway.auth]
            enabled  = true
            issuer   = "https://auth.example.com"
            resource = "https://mcpdef.acme.internal/mcp"
            jwks     = "./jwks.json"

            [[role]]
            name   = "reader"
            grants = ["github:get_*", "list_*"]

            [[server]]
            id = "github"
            transport = "stdio"
            command = ["mcp-server-github"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty());

        let rbac = cfg.rbac();
        assert!(!rbac.is_empty());
        // "github:get_*" → (github, get_*) matches; "list_*" (no colon) → (*, list_*).
        assert!(rbac
            .decide(["reader"].into_iter(), "github", "get_file")
            .is_allow());
        assert!(rbac
            .decide(["reader"].into_iter(), "files", "list_dir")
            .is_allow());
        // not granted: write on github, and a caller who doesn't hold the role.
        assert!(!rbac
            .decide(["reader"].into_iter(), "github", "delete_repo")
            .is_allow());
        assert!(!rbac
            .decide(["viewer"].into_iter(), "github", "get_file")
            .is_allow());
    }

    #[test]
    fn flags_empty_role_name() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[role]]
            name = ""
            grants = ["x:y"]
            [[server]]
            id = "x"
            transport = "stdio"
            command = ["true"]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().iter().any(|e| e.contains("empty `name`")));
    }

    #[test]
    fn what_a_server_may_expose_is_not_part_of_how_it_is_reached() {
        let entry = |exposes: &str| {
            let text = format!(
                "[gateway]\n[[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n{exposes}"
            );
            Config::parse(&text).unwrap().servers.remove(0)
        };
        let bare = entry("");
        for exposes in [
            "tools = [\"t\"]",
            "deny = [\"t\"]",
            "resources = [\"file:///x/**\"]",
            "resource_templates = [\"file:///{p}\"]",
            "prompts = [\"p\"]",
        ] {
            let governed = entry(exposes);
            assert_ne!(governed, bare, "{exposes}");
            assert_eq!(governed.connection(), bare.connection(), "{exposes}");
        }
    }

    #[test]
    fn parses_policy_rules_and_builds_the_engine() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[server]]
            id = "github"
            transport = "stdio"
            command = ["mcp-server-github"]
            [[policy]]
            name = "no-delete-prod"
            effect = "deny"
            servers = ["github"]
            tools = ["delete_*"]
            args = [ { path = "name", glob = "prod-*" } ]
        "#,
        )
        .unwrap();
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
        let rules = cfg.policy_rules();
        assert!(!rules.is_empty());
        // The rule denies delete_repo on github when name is prod-*, and allows it
        // otherwise — proving the config→engine conversion carries every field.
        use mcpdef_policy::{PolicyContext, Target};
        let prod = serde_json::json!({ "name": "prod-secrets" });
        let dev = serde_json::json!({ "name": "dev-box" });
        assert!(!rules
            .evaluate(&PolicyContext {
                agent: "a",
                server: "github",
                target: Target::Tool("delete_repo"),
                args: &prod,
            })
            .is_allow());
        assert!(rules
            .evaluate(&PolicyContext {
                agent: "a",
                server: "github",
                target: Target::Tool("delete_repo"),
                args: &dev,
            })
            .is_allow());
    }

    #[test]
    fn validate_rejects_bad_effect_and_malformed_arg() {
        let cfg: Config = toml::from_str(
            r#"
            [gateway]
            [[policy]]
            name = "bad"
            effect = "maybe"
            servers = []
            args = [ { path = "x" } ]
        "#,
        )
        .unwrap();
        let errs = cfg.validate();
        assert!(errs.iter().any(|e| e.contains("effect")), "{errs:?}");
        assert!(
            errs.iter().any(|e| e.contains("empty `servers`")),
            "an explicit empty condition list must be rejected: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("exactly one")),
            "a predicate with no operator must be rejected: {errs:?}"
        );
    }

    /// A config of `rules`, with an empty `[gateway]` and one server.
    fn policy_config(rules: &str) -> Config {
        toml::from_str(&format!(
            "[gateway]\n[[server]]\nid = \"github\"\ntransport = \"stdio\"\n\
             command = [\"mcp-server-github\"]\n{rules}"
        ))
        .unwrap()
    }

    #[test]
    fn a_transform_rule_becomes_its_edits_in_order() {
        let cfg = policy_config(
            r#"
            [[policy]]
            name = "cap-page-size"
            effect = "Transform"
            tools = ["list_*"]
            set_args = [
              { path = "per_page", default = 500 },
              { path = "per_page", clamp = { min = 1, max = 100 } },
              { path = "filter.state", set = "open" },
              { path = "labels", set = ["bug", 2, 1.5, true, { deep = "x" }] },
              { path = "debug", remove = true },
            ]
            "#,
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let rules = cfg.policy_rules();
        let mut args = serde_json::json!({ "debug": true, "filter": { "state": "all" } });
        let done = rules.transform("agent:x", "github", "list_issues", &mut args);
        assert_eq!(done.fired, ["cap-page-size"]);
        assert_eq!(
            args,
            serde_json::json!({
                "per_page": 100,
                "filter": { "state": "open" },
                "labels": ["bug", 2, 1.5, true, { "deep": "x" }],
            })
        );
        // Not a tool it names.
        let mut args = serde_json::json!({ "per_page": 500 });
        assert!(rules
            .transform("agent:x", "github", "create_issue", &mut args)
            .fired
            .is_empty());
    }

    #[test]
    fn on_error_skip_is_read_and_deny_is_the_default() {
        let cfg = policy_config(
            r#"
            [[policy]]
            name = "cap-quietly"
            effect = "transform"
            on_error = "SKIP"
            set_args = [{ path = "per_page", clamp = { max = 100 } }]

            [[policy]]
            name = "cap"
            effect = "transform"
            set_args = [{ path = "per_page", clamp = { max = 100 } }]
            "#,
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let mut args = serde_json::json!({ "per_page": "all" });
        let done = cfg
            .policy_rules()
            .transform("agent:x", "github", "list_issues", &mut args);
        assert_eq!(done.skipped.len(), 1);
        assert_eq!(done.skipped[0].0, "cap-quietly");
        assert!(matches!(done.refused, Some(Decision::Deny { rule, .. }) if rule == "cap"));
    }

    #[test]
    fn validate_refuses_a_transform_rule_that_cannot_work() {
        let edit = |entry: &str| format!("effect = \"transform\"\nset_args = [{entry}]");
        for (rule, expected) in [
            ("effect = \"transform\"".to_string(), "no `set_args`"),
            (
                "effect = \"transform\"\nset_args = []".into(),
                "no `set_args`",
            ),
            (
                format!(
                    "uris = [\"file:///srv/**\"]\n{}",
                    edit("{ path = \"a\", remove = true }")
                ),
                "cannot name `uris`",
            ),
            (
                format!(
                    "prompts = [\"notes\"]\n{}",
                    edit("{ path = \"a\", remove = true }")
                ),
                "cannot name `prompts`",
            ),
            (
                "effect = \"deny\"\nset_args = [{ path = \"a\", remove = true }]".into(),
                "has `set_args`, which only a transform rule takes",
            ),
            (
                "effect = \"allow\"\non_error = \"skip\"".into(),
                "has `on_error`, which only a transform rule takes",
            ),
            (
                format!(
                    "on_error = \"ignore\"\n{}",
                    edit("{ path = \"a\", remove = true }")
                ),
                "`on_error` 'ignore' (must be deny/skip)",
            ),
            (
                "effect = \"deny\"\nresult = [{ redact = \"secrets\" }]".into(),
                "has `result`, which only a transform rule takes",
            ),
            (
                edit("{ path = \"\", remove = true }"),
                "keys joined by single dots",
            ),
            (
                edit("{ path = \"a..b\", remove = true }"),
                "keys joined by single dots",
            ),
            (
                edit("{ path = \"a.\", remove = true }"),
                "keys joined by single dots",
            ),
            (
                edit("{ path = \"a\" }"),
                "exactly one of set/default/remove/clamp (found 0)",
            ),
            (
                edit("{ path = \"a\", remove = false }"),
                "exactly one of set/default/remove/clamp (found 0)",
            ),
            (
                edit("{ path = \"a\", set = 1, remove = true }"),
                "exactly one of set/default/remove/clamp (found 2)",
            ),
            (
                edit("{ path = \"a\", clamp = {} }"),
                "names neither `min` nor `max`",
            ),
            (
                edit("{ path = \"a\", clamp = { min = 10, max = 1 } }"),
                "has its `min` above its `max`",
            ),
            (
                edit("{ path = \"a\", clamp = { max = \"10\" } }"),
                "`clamp` max is not a number",
            ),
            (
                edit("{ path = \"a\", clamp = { min = nan } }"),
                "`clamp` min holds a number that is not finite",
            ),
            (
                edit("{ path = \"a\", set = inf }"),
                "`set` holds a number that is not finite",
            ),
            (
                edit("{ path = \"a\", set = [1, -inf] }"),
                "`set` holds a number that is not finite",
            ),
            (
                edit("{ path = \"a\", default = 1979-05-27T07:32:00Z }"),
                "`default` holds a date",
            ),
        ] {
            let cfg = policy_config(&format!("[[policy]]\nname = \"r\"\n{rule}\n"));
            let errs = cfg.validate();
            assert!(
                errs.iter().any(|e| e.contains(expected)),
                "{rule}: {errs:?}"
            );
        }
    }

    #[test]
    fn an_edit_with_a_key_it_does_not_know_is_not_read() {
        for (entry, key) in [
            ("{ path = \"a\", remvoe = true }", "remvoe"),
            ("{ path = \"a\", clamp = { maximum = 100 } }", "maximum"),
        ] {
            let text = format!(
                "[gateway]\n[[policy]]\nname = \"r\"\neffect = \"transform\"\nset_args = [{entry}]\n"
            );
            let err = toml::from_str::<Config>(&text).unwrap_err().to_string();
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn a_result_edit_names_one_thing_to_do_and_how() {
        let result = |entry: &str| format!("effect = \"transform\"\nresult = [{entry}]");
        for (rule, expected) in [
            (
                result("{}"),
                "result entry 1 must name exactly one of redact/mask/remove/truncate (found 0)",
            ),
            (result("{ mask = \"a\", remove = \"b\" }"), "(found 2)"),
            (
                result("{ redact = \"keys\" }"),
                "`redact` is 'keys' (must be \"secrets\")",
            ),
            (
                result("{ mask = \"\" }"),
                "`mask` needs a path of keys joined by single dots",
            ),
            (result("{ remove = \"a..b\" }"), "keys joined by single dots"),
            (
                result("{ remove = \"items.*\" }"),
                "`remove` must end in a key, not `*`",
            ),
            (
                result("{ truncate = 0 }"),
                "`truncate` is 0 (must be a number of bytes, 1 or more)",
            ),
            (result("{ truncate = -5 }"), "`truncate` is -5"),
            (
                format!(
                    "uris = [\"file:///srv/**\"]\nset_args = [{{ path = \"a\", remove = true }}]\n{}",
                    result("{ truncate = 9 }")
                ),
                "cannot name `uris`",
            ),
            (
                format!("prompts = [\"notes\"]\n{}", result("{ truncate = 9 }")),
                "cannot name `prompts`",
            ),
            (
                "effect = \"allow\"\nresult = [{ truncate = 9 }]".into(),
                "has `result`, which only a transform rule takes",
            ),
        ] {
            let cfg = policy_config(&format!("[[policy]]\nname = \"r\"\n{rule}\n"));
            let errs = cfg.validate();
            assert!(
                errs.iter().any(|e| e.contains(expected)),
                "{rule}: {errs:?}"
            );
        }
        // An entry is named by where it is, from one.
        let cfg = policy_config(
            "[[policy]]\nname = \"r\"\neffect = \"transform\"\n\
             result = [{ truncate = 9 }, { redact = \"all\" }]\n",
        );
        let errs = cfg.validate();
        assert!(
            errs.iter().any(|e| e.contains("result entry 2 ")),
            "{errs:?}"
        );
        // And a key it does not know is not read.
        let text = "[gateway]\n[[policy]]\nname = \"r\"\neffect = \"transform\"\n\
                    result = [{ trunc = 9 }]\n";
        let err = toml::from_str::<Config>(text).unwrap_err().to_string();
        assert!(err.contains("trunc"), "{err}");
    }

    #[test]
    fn a_transform_of_results_alone_may_name_uris_and_makes_its_edits_in_order() {
        use mcpdef_policy::{uri, PolicyContext, Target};
        let cfg = policy_config(
            r#"
            [[policy]]
            name = "reads"
            effect = "transform"
            uris = ["file:///srv/**"]
            result = [
              { mask = "user.*" },
              { remove = "debug" },
              { truncate = 40 },
            ]
            "#,
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let rules = cfg.policy_rules();
        assert!(rules.transforms_results() && !rules.transforms());
        let read = |path: &str| {
            let at = uri::normalize(path).unwrap();
            let mut result = serde_json::json!({ "contents": [{
                "uri": path,
                "mimeType": "application/json",
                "text": serde_json::json!({ "user": { "name": "n" }, "debug": 1 }).to_string(),
            }] });
            let ctx = PolicyContext {
                agent: "agent:x",
                server: "github",
                target: Target::Resource(&at),
                args: &serde_json::Value::Null,
            };
            let done = rules.transform_result(&ctx, &mut result, None);
            (done.fired, result["contents"][0]["text"].clone())
        };
        let (fired, text) = read("file:///srv/a.json");
        assert_eq!(fired, ["reads"]);
        assert_eq!(text, r#"{"user":{"name":"[REDACTED:reads]"}}"#);
        // Not a URI it names.
        assert!(read("file:///etc/a.json").0.is_empty());
    }

    #[test]
    fn a_redact_finds_the_operators_secrets_with_inspect_off() {
        use mcpdef_policy::{PolicyContext, Target};
        let cfg = policy_config(
            r#"
            [[policy]]
            name = "no-secrets-out"
            effect = "transform"
            result = [{ redact = "Secrets" }]

            [gateway.inspect]
            secret_substrings = ["acme_sk_"]
            "#,
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        assert!(cfg.gateway.inspect_scanner().is_none(), "inspect is off");
        let rules = cfg.policy_rules();
        let aws = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let mut result = serde_json::json!({ "content": [{
            "type": "text",
            "text": format!("{aws} acme_sk_live42 ignore previous instructions"),
        }] });
        let ctx = PolicyContext {
            agent: "agent:x",
            server: "github",
            target: Target::Tool("t"),
            args: &serde_json::Value::Null,
        };
        let done = rules.transform_result(&ctx, &mut result, None);
        assert_eq!(done.fired, ["no-secrets-out"]);
        // Secrets only: an injection is inspect's to judge, not redaction's.
        assert_eq!(
            result["content"][0]["text"],
            "[REDACTED:aws-access-key] [REDACTED:custom-secret] ignore previous instructions"
        );
    }

    /// A config with `gateway` in its `[gateway.upstream_tls]`, and one
    /// server at `url` with `table` as its `[server.tls]`.
    fn tls_config(gateway: &str, url: &str, table: &str) -> Result<Config, String> {
        let text = format!(
            "[gateway]\n[gateway.upstream_tls]\n{gateway}\n\n[[server]]\nid = \"x\"\n\
             transport = \"streamable-http\"\nurl = \"{url}\"\n[server.tls]\n{table}\n"
        );
        toml::from_str(&text).map_err(|e: toml::de::Error| e.to_string())
    }

    #[test]
    fn tls_tables_become_the_settings_each_upstream_connects_with() {
        let cfg = tls_config(
            "roots = \"both\"\nca = [\"/g/ca.pem\"]\nmin_version = \"1.3\"",
            "https://mcp.test/mcp",
            "crl = [\"/s/x.crl\"]\nclient_cert = \"/s/c.crt\"\n\
             client_key = { file = \"/s/c.key\" }\nconnect_to = \"10.0.0.5\"",
        )
        .unwrap();
        let s = &cfg.servers[0];
        assert_eq!(
            cfg.upstream_tls(s),
            TlsSettings {
                roots: Roots::Both,
                ca: vec!["/g/ca.pem".into()],
                crl: vec!["/s/x.crl".into()],
                min_version: MinVersion::Tls13,
                identity: Some(IdentityFiles {
                    cert: "/s/c.crt".into(),
                    key: SecretRef::File("/s/c.key".into()),
                }),
                insecure_skip_verify: false,
                pin_sha256: Vec::new(),
            }
        );
        assert_eq!(s.connect_to(), Ok(Some("10.0.0.5".parse().unwrap())));
        // The gateway's own fetches get the gateway's table alone.
        assert_eq!(
            cfg.gateway.fetch_tls(),
            TlsSettings {
                roots: Roots::Both,
                ca: vec!["/g/ca.pem".into()],
                min_version: MinVersion::Tls13,
                ..TlsSettings::default()
            }
        );
        // Every file either table names, for a reload to watch.
        let files = cfg.referenced_files();
        for file in ["/g/ca.pem", "/s/x.crl", "/s/c.crt", "/s/c.key"] {
            assert!(files.contains(&file.to_string()), "{file}: {files:?}");
        }
        // No table at all: the bundled roots, as before profiles.
        let plain: Config = toml::from_str(GOOD).unwrap();
        assert_eq!(
            plain.upstream_tls(&plain.servers[0]),
            TlsSettings::default()
        );
    }

    #[test]
    fn a_server_table_replaces_what_it_sets_and_keeps_the_rest() {
        let gateway = TlsConfig {
            roots: Some(RootsSetting::System),
            ca: Some(vec!["/g.pem".into()]),
            crl: Some(vec!["/g.crl".into()]),
            min_version: Some(TlsVersion::V1_3),
            client_cert: Some("/g.crt".into()),
            client_key: Some(SecretRef::File("/g.key".into())),
            ..TlsConfig::default()
        };
        assert_eq!(
            TlsConfig::default().over(&gateway).settings(),
            gateway.settings()
        );
        // `ca = []` leaves the gateway's CAs out.
        let server = TlsConfig {
            ca: Some(Vec::new()),
            ..TlsConfig::default()
        };
        let merged = server.over(&gateway).settings();
        assert!(merged.ca.is_empty());
        assert_eq!(merged.crl, vec![PathBuf::from("/g.crl")]);
        // The certificate and its key go as a pair.
        let server = TlsConfig {
            client_cert: Some("/s.crt".into()),
            client_key: Some(SecretRef::File("/s.key".into())),
            ..TlsConfig::default()
        };
        assert_eq!(
            server.over(&gateway).settings().identity,
            Some(IdentityFiles {
                cert: "/s.crt".into(),
                key: SecretRef::File("/s.key".into()),
            })
        );
        // What only a server may set is never inherited.
        let under = TlsConfig {
            connect_to: Some("10.0.0.5".into()),
            insecure_skip_verify: Some(true),
            ..TlsConfig::default()
        };
        let merged = TlsConfig::default().over(&under);
        assert_eq!(
            (merged.connect_to, merged.insecure_skip_verify),
            (None, None)
        );
    }

    #[test]
    fn tls_tables_that_cannot_work_are_refused() {
        let url = "https://mcp.test/mcp";
        let refused = |gateway: &str, url: &str, table: &str| {
            tls_config(gateway, url, table).unwrap().validate()
        };
        let errs = refused("", url, "client_cert = \"/s/c.crt\"");
        assert_eq!(
            errs,
            ["server 'x': [server.tls] client_cert and client_key go together: set both, or neither"]
        );
        let errs = refused("client_key = { file = \"/g/c.key\" }", url, "");
        assert_eq!(
            errs,
            ["[gateway.upstream_tls] client_cert and client_key go together: set both, or neither"]
        );
        let errs = refused(
            "connect_to = \"10.0.0.5\"\ninsecure_skip_verify = false",
            url,
            "",
        );
        assert_eq!(errs.len(), 2, "{errs:?}");
        assert!(errs[0].contains("connect_to names one upstream's address"));
        assert!(errs[1].contains("insecure_skip_verify is never a gateway-wide setting"));

        let errs = refused("", "http://mcp.test/mcp", "min_version = \"1.3\"");
        assert_eq!(
            errs,
            ["server 'x': [server.tls] is for an https:// upstream, and its url is http://mcp.test/mcp"]
        );
        let stdio: Config = toml::from_str(
            "[gateway]\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n\
             [server.tls]\nmin_version = \"1.3\"\n",
        )
        .unwrap();
        assert_eq!(
            stdio.validate(),
            ["server 'x': [server.tls] is for an https:// upstream, and it is stdio"]
        );

        let errs = refused("", url, "connect_to = \"mcp.internal\"");
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].contains("connect_to must be an IP address"),
            "{errs:?}"
        );
        let errs = refused("", "https://10.0.0.9/mcp", "connect_to = \"10.0.0.5\"");
        assert!(errs[0].contains("needs a url with a host name"), "{errs:?}");
        let errs = refused("", url, "connect_to = \"169.254.169.254\"");
        assert!(errs[0].contains("always blocked"), "{errs:?}");
        // Private addresses follow `[gateway.egress]`.
        let text = format!(
            "[gateway]\n[gateway.egress]\nallow_private = false\n\n[[server]]\nid = \"x\"\n\
             transport = \"streamable-http\"\nurl = \"{url}\"\n[server.tls]\nconnect_to = \"10.0.0.5\"\n"
        );
        let hardened: Config = toml::from_str(&text).unwrap();
        assert!(hardened.validate()[0].contains("allow_private = false"));
    }

    #[test]
    fn a_tls_table_on_a_plain_http_url_names_it_without_the_secrets_it_holds() {
        let config: Config = toml::from_str(
            "[gateway]\n[[server]]\nid = \"x\"\ntransport = \"streamable-http\"\n\
             url = \"http://mcpdef:s3cret@mcp.test/mcp?api_key=s3cret-key\"\n\
             [server.tls]\nmin_version = \"1.3\"\n",
        )
        .unwrap();
        let errs = config.validate();
        let shown = "server 'x': [server.tls] is for an https:// upstream, and its url is \
                     http://***:***@mcp.test/mcp?api_key=***";
        assert!(errs.iter().any(|e| e == shown), "{errs:?}");
        assert!(!errs.join("\n").contains("s3cret"), "{errs:?}");
    }

    #[test]
    fn tls_mistakes_in_the_toml_say_what_is_expected() {
        let url = "https://mcp.test/mcp";
        let error = tls_config("", url, "cafile = [\"/x.pem\"]").unwrap_err();
        assert!(error.contains("unknown field `cafile`"), "{error}");
        // A plain string is the key itself, so a path there parses, and is
        // refused when the key is read: see the transport's tests.
        let cfg = tls_config("", url, "client_key = \"/s/c.key\"").unwrap();
        let key = cfg.servers[0].tls.as_ref().unwrap().client_key.as_ref();
        assert_eq!(key.map(SecretRef::scheme), Some("literal"));
        let error = tls_config("", url, "client_key = { path = \"/s/c.key\" }").unwrap_err();
        assert!(
            error.contains("`path` is not where a secret comes from"),
            "{error}"
        );
        let error = tls_config("roots = \"sytem\"", url, "").unwrap_err();
        assert!(error.contains("unknown variant `sytem`"), "{error}");
        let error = tls_config("", url, "min_version = \"1.1\"").unwrap_err();
        assert!(error.contains("unknown variant `1.1`"), "{error}");
    }

    #[test]
    fn the_files_a_tls_table_names_are_checked_by_validate() {
        let dir = tempfile::tempdir().unwrap();
        let pki = mcpdef_testkit::Pki::new("mcpdef test CA");
        let root = pki.write_root(dir.path(), "root");
        let der = dir.path().join("root.der");
        std::fs::write(&der, pki.root_der()).unwrap();
        let missing = dir.path().join("missing.pem");
        let url = "https://mcp.test/mcp";

        let good = tls_config(
            &format!("ca = [{root:?}]"),
            url,
            &format!("ca = [{root:?}]"),
        );
        assert_eq!(good.unwrap().validate(), Vec::<String>::new());

        let errs = tls_config(
            &format!("ca = [{missing:?}]"),
            url,
            &format!("crl = [{der:?}]"),
        )
        .unwrap()
        .validate();
        assert_eq!(errs.len(), 2, "{errs:?}");
        assert!(
            errs[0].starts_with(&format!(
                "[gateway.upstream_tls] ca {}: ",
                missing.display()
            )),
            "{errs:?}"
        );
        assert!(
            errs[1].starts_with(&format!(
                "server 'x': [server.tls] crl {}: is not PEM",
                der.display()
            )),
            "{errs:?}"
        );
        // The host's store is not the config's: `roots = "system"` reads
        // nothing when a config is checked.
        let system = tls_config("roots = \"system\"", url, "").unwrap();
        assert_eq!(system.validate(), Vec::<String>::new());
    }

    #[test]
    fn insecure_skip_verify_is_warned_about_not_refused() {
        let cfg = tls_config("", "https://mcp.test/mcp", "insecure_skip_verify = true").unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let warnings = cfg.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with("server 'x': [server.tls] insecure_skip_verify = true:"),
            "{warnings:?}"
        );
        assert!(cfg.upstream_tls(&cfg.servers[0]).insecure_skip_verify);
        let off = tls_config("", "https://mcp.test/mcp", "insecure_skip_verify = false").unwrap();
        assert!(off.warnings().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_warned_about_not_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, mode: u32| {
            let path = dir.path().join(name);
            std::fs::write(&path, "").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let (open, closed) = (file("open.key", 0o644), file("closed.key", 0o600));
        let cfg = tls_config(
            &format!("client_cert = \"/g.crt\"\nclient_key = {{ file = {open:?} }}"),
            "https://mcp.test/mcp",
            &format!("client_cert = \"/s.crt\"\nclient_key = {{ file = {closed:?} }}"),
        )
        .unwrap();
        assert_eq!(
            cfg.warnings(),
            [format!(
                "[gateway.upstream_tls] client_key: {} can be read by its group and every user \
                 (mode 644): make it readable by MCPdef's user alone, with `chmod 600`, or let \
                 root own it and MCPdef's group alone read it, with `chmod 640`",
                open.display()
            )]
        );
        let cfg = tls_config(
            "",
            "https://mcp.test/mcp",
            &format!("client_cert = \"/s.crt\"\nclient_key = {{ file = {open:?} }}"),
        )
        .unwrap();
        let warnings = cfg.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].starts_with("server 'x': [server.tls] client_key: "),
            "{warnings:?}"
        );
    }

    #[test]
    fn the_variables_secrets_are_read_from_are_listed_once_each() {
        let key = |from: &str| format!("client_cert = \"/c.crt\"\nclient_key = {from}");
        let cfg = tls_config(
            &key("{ env = \"MCPDEF_KEY_B\" }"),
            "https://mcp.test/mcp",
            &key("{ env = \"MCPDEF_KEY_A\" }"),
        )
        .unwrap();
        assert_eq!(cfg.secret_vars(), ["MCPDEF_KEY_A", "MCPDEF_KEY_B"]);
        let same = tls_config(
            &key("{ env = \"MCPDEF_KEY\" }"),
            "https://mcp.test/mcp",
            &key("{ env = \"MCPDEF_KEY\" }"),
        )
        .unwrap();
        assert_eq!(same.secret_vars(), ["MCPDEF_KEY"]);
        let none = tls_config(
            &key("{ file = \"/g.key\" }"),
            "https://mcp.test/mcp",
            &key("\"a literal\""),
        )
        .unwrap();
        assert!(none.secret_vars().is_empty());
    }

    #[test]
    fn pins_are_a_servers_own_and_replace_the_chain_check() {
        let url = "https://mcp.test/mcp";
        let pin = "kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg=";
        let table = format!("pin_sha256 = [\"{pin}\"]");
        let cfg = tls_config("", url, &table).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        assert_eq!(cfg.upstream_tls(&cfg.servers[0]).pin_sha256, [pin]);

        let refused =
            |gateway: &str, table: &str| tls_config(gateway, url, table).unwrap().validate();
        assert_eq!(
            refused(&table, ""),
            [
                "[gateway.upstream_tls] pin_sha256 names one upstream's key: set it in that \
              server's [server.tls]"
            ]
        );
        let errs = refused("", "pin_sha256 = []");
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].contains("pins nothing"), "{errs:?}");
        let errs = refused("", &format!("{table}\ninsecure_skip_verify = true"));
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].contains("contradict"), "{errs:?}");
        let errs = refused("", &format!("{table}\nca = []\ncrl = []"));
        assert_eq!(
            errs,
            [
                "server 'x': [server.tls] pin_sha256 trusts the key alone, so ca, crl would do \
              nothing here: leave them out"
            ]
        );
        let errs = refused("", &format!("{table}\nroots = \"system\""));
        assert!(
            errs[0].contains("so roots would do nothing here: leave it out"),
            "{errs:?}"
        );
        let errs = refused("", "pin_sha256 = [\"nope\"]");
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].starts_with("server 'x': [server.tls] pin_sha256 'nope' is not a pin"),
            "{errs:?}"
        );
        // The gateway's CAs under a pinned server are its to keep: only a
        // server's own table can contradict its pin.
        let dir = tempfile::tempdir().unwrap();
        let root = mcpdef_testkit::Pki::new("mcpdef test CA").write_root(dir.path(), "root");
        let errs = refused(&format!("ca = [{root:?}]"), &table);
        assert_eq!(errs, Vec::<String>::new());
        // Nor is a pin ever inherited.
        let under = TlsConfig {
            pin_sha256: Some(vec![pin.to_string()]),
            ..TlsConfig::default()
        };
        assert_eq!(TlsConfig::default().over(&under).pin_sha256, None);
    }

    /// A config with one stdio server whose `[server.env]` is `env`.
    fn with_env(env: &str) -> Config {
        let text = format!(
            "[gateway]\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n\
             [server.env]\n{env}\n"
        );
        Config::parse(&text).unwrap()
    }

    #[test]
    fn an_env_value_is_a_secret_reference_in_each_form() {
        let cfg = with_env(
            "PLAIN = \"debug\"\nFROM_ENV = { env = \"MCPDEF_SOURCE\" }\n\
             FROM_FILE = { file = \"/run/secrets/token\" }\n\
             FROM_EXEC = { exec = [\"op\", \"read\", \"op://infra/x/y\"] }",
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let env = &cfg.servers[0].env;
        let schemes: Vec<(&str, &str)> = env
            .iter()
            .map(|(name, value)| (name.as_str(), value.scheme()))
            .collect();
        assert_eq!(
            schemes,
            [
                ("FROM_ENV", "env"),
                ("FROM_EXEC", "exec"),
                ("FROM_FILE", "file"),
                ("PLAIN", "literal"),
            ]
        );
        // The variable is withheld from every stdio child, the file is watched,
        // and nothing here is warned about: `PLAIN` is no secret.
        assert_eq!(cfg.secret_vars(), ["MCPDEF_SOURCE"]);
        assert_eq!(cfg.referenced_files(), ["/run/secrets/token"]);
        assert_eq!(cfg.warnings(), Vec::<String>::new());
        // A value is not a table that says where it is from.
        let wrong = "[gateway]\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\n\
                     command = [\"srv\"]\n[server.env]\nA = { path = \"/x\" }\n";
        let error = Config::parse(wrong).unwrap_err().to_string();
        assert!(
            error.contains("`path` is not where a secret comes from"),
            "{error}"
        );
    }

    #[test]
    fn an_env_name_no_variable_can_have_is_refused() {
        for name in ["\"\"", "\"A=B\"", "\"A\\u0000B\""] {
            let cfg = with_env(&format!("{name} = \"v\""));
            let errs = cfg.validate();
            assert_eq!(errs.len(), 1, "{name}: {errs:?}");
            assert!(
                errs[0].starts_with("server 'x': [server.env] ")
                    && errs[0].ends_with(" names no environment variable"),
                "{errs:?}"
            );
        }
    }

    #[test]
    fn a_secret_written_in_the_config_is_warned_about() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let cfg = with_env(&format!(
            "GITHUB_TOKEN = \"t\"\nNOTE = \"{token}\"\nLOG_LEVEL = \"debug\"\n\
             SSH_KEY_PATH = \"/k\"\nAPI_KEY = \"\"\nDB_PASSWORD = {{ env = \"DB\" }}"
        ));
        let warned: Vec<&str> = cfg
            .warnings()
            .iter()
            .map(|w| w.split(" is a secret").next().unwrap())
            .map(|w| match w {
                "server 'x': [server.env] GITHUB_TOKEN" => "GITHUB_TOKEN",
                "server 'x': [server.env] NOTE" => "NOTE",
                other => panic!("{other}"),
            })
            .collect();
        assert_eq!(warned, ["GITHUB_TOKEN", "NOTE"]);
        let warning = &cfg.warnings()[0];
        assert!(
            warning.ends_with(
                "read it from a file, a variable or a command instead, as { file = \"…\" }, \
                 { env = \"…\" } or { exec = [\"…\"] }"
            ),
            "{warning}"
        );
        // No value is repeated.
        assert!(cfg.warnings().iter().all(|w| !w.contains(&token)));
        // A client key written in the config is always one.
        let key = tls_config(
            "client_cert = \"/c.crt\"\nclient_key = \"the key\"",
            "https://mcp.test/mcp",
            "",
        )
        .unwrap();
        assert_eq!(key.warnings().len(), 1);
        assert!(key.warnings()[0]
            .starts_with("[gateway.upstream_tls] client_key is a secret written in the config"));
    }

    #[test]
    fn a_name_or_a_shape_says_what_is_a_secret() {
        for name in [
            "GITHUB_TOKEN",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "HF_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "CLIENT_SECRET",
            "POSTGRES_PASSWORD",
            "PGPASSWORD",
            "GPG_PASSPHRASE",
            "DB_PASS",
            "GITLAB_PAT",
            "api-key",
            "KEY",
        ] {
            assert!(a_secret(name, "v"), "{name}");
        }
        for name in [
            "LOG_LEVEL",
            "NODE_ENV",
            "PATH",
            "SSH_KEY_PATH",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "MONKEY",
            "TOKEN_TTL",
            "BYPASS",
        ] {
            assert!(!a_secret(name, "v"), "{name}");
        }
        assert!(!a_secret("GITHUB_TOKEN", ""));
        assert!(a_secret("NOTE", &format!("ghp_{}", "a1B2".repeat(9))));
    }

    #[cfg(unix)]
    #[test]
    fn an_env_file_others_can_read_is_warned_about() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "t").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let cfg = with_env(&format!("TOKEN = {{ file = {path:?} }}"));
        assert_eq!(
            cfg.warnings(),
            [format!(
                "server 'x': [server.env] TOKEN: {} can be read by its group (mode 640): make \
                 it readable by MCPdef's user alone, with `chmod 600`, or let root own it and \
                 MCPdef's group alone read it, with `chmod 640`",
                path.display()
            )]
        );
    }

    /// A config with one server at `url`, whose `[server.auth]` is `table`.
    fn with_auth(url: &str, table: &str) -> Result<Config, String> {
        let transport = match url {
            "" => "transport = \"stdio\"\ncommand = [\"srv\"]".to_string(),
            url => format!("transport = \"streamable-http\"\nurl = \"{url}\""),
        };
        let text =
            format!("[gateway]\n\n[[server]]\nid = \"x\"\n{transport}\n[server.auth]\n{table}\n");
        Config::parse(&text).map_err(|e| format!("{e:#}"))
    }

    #[test]
    fn each_auth_kind_parses_and_says_what_it_lacks() {
        let url = "https://mcp.test/mcp";
        for table in [
            "kind = \"bearer\"\ntoken = { env = \"T\" }",
            "kind = \"header\"\nname = \"X-Api-Key\"\nvalue = { file = \"/k\" }",
            "kind = \"basic\"\nusername = \"mcpdef\"\npassword = { exec = [\"op\", \"read\", \"x\"] }",
        ] {
            let cfg = with_auth(url, table).unwrap();
            assert_eq!(cfg.validate(), Vec::<String>::new(), "{table}");
            assert!(cfg.servers[0].auth.as_ref().unwrap().credential().is_ok());
        }
        for (table, says) in [
            ("kind = \"bearer\"", "kind = \"bearer\" needs `token`"),
            (
                "kind = \"bearer\"\ntoken = \"t\"\nname = \"X\"",
                "`name` is not for kind = \"bearer\"",
            ),
            (
                "kind = \"header\"\nname = \"X-Api-Key\"",
                "kind = \"header\" needs `value`",
            ),
            (
                "kind = \"header\"\nname = \"Content-Type\"\nvalue = \"v\"",
                "content-type is a header HTTP, MCP's transport or a proxy sets",
            ),
            (
                "kind = \"basic\"\nusername = \"a:b\"\npassword = \"p\"",
                "username holds a `:`",
            ),
            (
                "kind = \"basic\"\nusername = \"u\"",
                "kind = \"basic\" needs `password`",
            ),
        ] {
            let errs = with_auth(url, table).unwrap().validate();
            assert_eq!(errs.len(), 1, "{table}: {errs:?}");
            assert!(
                errs[0].starts_with("server 'x': [server.auth] ") && errs[0].contains(says),
                "{table}: {errs:?}"
            );
        }
        for (table, says) in [
            ("kind = \"oauth\"", "unknown kind `oauth`"),
            (
                "kind = \"bearer\"\nname = { env = \"N\" }",
                "`name` is a string",
            ),
            ("kind = \"bearer\"\ntokn = \"t\"", "unknown field `tokn`"),
        ] {
            let error = with_auth(url, table).unwrap_err();
            assert!(error.contains(says), "{table}: {error}");
        }
    }

    #[test]
    fn auth_is_for_http_upstreams() {
        let cfg = with_auth("", "kind = \"bearer\"\ntoken = { env = \"T\" }").unwrap();
        assert_eq!(
            cfg.validate(),
            [
                "server 'x': [server.auth] is for a streamable-http or sse upstream, and this one \
              is stdio: a stdio server gets its credentials in [server.env]"
            ]
        );
    }

    #[test]
    fn an_auth_secret_is_withheld_and_warned_about_like_others() {
        let url = "https://mcp.test/mcp";
        let cfg = with_auth(url, "kind = \"bearer\"\ntoken = { env = \"MCPDEF_TOKEN\" }").unwrap();
        assert_eq!(cfg.secret_vars(), ["MCPDEF_TOKEN"]);
        assert_eq!(cfg.warnings(), Vec::<String>::new());
        // Written in the config, whatever it is named.
        let cfg = with_auth(
            url,
            "kind = \"header\"\nname = \"X-Tenant\"\nvalue = \"acme\"",
        )
        .unwrap();
        assert_eq!(cfg.warnings().len(), 1);
        assert!(cfg.warnings()[0]
            .starts_with("server 'x': [server.auth] value is a secret written in the config"));
        // Not a file a reload watches: a 401 has it read again.
        let cfg = with_auth(url, "kind = \"bearer\"\ntoken = { file = \"/t\" }").unwrap();
        assert!(cfg.referenced_files().is_empty());
    }

    #[test]
    fn credentials_over_plain_http_are_warned_about() {
        let table = "kind = \"bearer\"\ntoken = { env = \"T\" }";
        let warned = |url: &str| with_auth(url, table).unwrap().warnings();
        assert_eq!(
            warned("http://mcp.example.com/mcp"),
            [
                "server 'x': [server.auth] sends its credentials over plain HTTP to \
              mcp.example.com, where anyone on the path can read them: use https://"
            ]
        );
        for url in [
            "https://mcp.example.com/mcp",
            "http://127.0.0.1:8080/mcp",
            "http://localhost/mcp",
            "http://[::1]:9/mcp",
        ] {
            assert_eq!(warned(url), Vec::<String>::new(), "{url}");
        }
    }
    /// An `oauth2` table: its four required fields, as `fields` changes them.
    /// An empty value leaves the field out.
    fn oauth2(fields: &[(&str, &str)]) -> String {
        let mut table = BTreeMap::from([
            ("kind", "\"oauth2\""),
            ("token_url", "\"https://idp.test/token\""),
            ("client_id", "\"mcpdef\""),
            ("client_secret", "{ file = \"/run/secrets/s\" }"),
        ]);
        for (field, value) in fields {
            match *value {
                "" => table.remove(field),
                value => table.insert(field, value),
            };
        }
        let lines: Vec<String> = table.iter().map(|(k, v)| format!("{k} = {v}")).collect();
        lines.join("\n")
    }

    #[test]
    fn an_oauth2_table_parses_and_asks_for_a_token_for_its_server() {
        let url = "https://mcp.test/mcp";
        let grant = |url: &str, table: &str| {
            let cfg = with_auth(url, table).unwrap();
            assert_eq!(cfg.validate(), Vec::<String>::new(), "{table}");
            match cfg.servers[0].credentials() {
                Some(Ok(UpstreamAuth::OAuth2(grant))) => grant,
                other => panic!("{table}: {other:?}"),
            }
        };
        let g = grant(url, &oauth2(&[("scopes", "[\"mcp:tools\", \"read\"]")]));
        assert_eq!(g.token_url, "https://idp.test/token");
        assert_eq!(g.client_id, "mcpdef");
        assert_eq!(g.client_secret, SecretRef::File("/run/secrets/s".into()));
        assert_eq!(g.client_auth, ClientAuth::Basic);
        assert_eq!(g.scopes, ["mcp:tools", "read"]);
        // RFC 8707's resource: the server, unless the table says another or
        // none.
        assert_eq!(g.resource.as_deref(), Some(url));
        let g = grant(
            url,
            &oauth2(&[
                ("resource", "\"https://api.test/\""),
                ("client_auth", "\"client_secret_post\""),
            ]),
        );
        assert_eq!(g.resource.as_deref(), Some("https://api.test/"));
        assert_eq!(g.client_auth, ClientAuth::Post);
        assert_eq!(grant(url, &oauth2(&[("resource", "\"\"")])).resource, None);
        let g = grant("https://mcp.test/mcp#part", &oauth2(&[]));
        assert_eq!(g.resource.as_deref(), Some(url));
        assert!(g.scopes.is_empty());
    }

    /// A default `resource` is the server's `url` as the config writes it,
    /// less what a resource must not carry: the credentials the URL holds are
    /// for the upstream, never the authorization server.
    #[test]
    fn a_default_resource_is_the_url_without_its_user_info_query_or_fragment() {
        let resource = |url: &str| {
            let cfg = with_auth(url, &oauth2(&[])).unwrap();
            match cfg.servers[0].credentials() {
                Some(Ok(UpstreamAuth::OAuth2(grant))) => grant.resource,
                other => panic!("{url}: {other:?}"),
            }
        };
        for (url, resource_is) in [
            (
                "https://svc:hunter2@mcp.test/mcp?api_key=k1#part",
                "https://mcp.test/mcp",
            ),
            (
                "https://t0ken@mcp.test:8443/v1/mcp",
                "https://mcp.test:8443/v1/mcp",
            ),
            ("https://mcp.test/mcp?tenant=a", "https://mcp.test/mcp"),
            ("https://a@b@mcp.test/mcp", "https://mcp.test/mcp"),
            // Otherwise as written: no path added, no case changed.
            ("https://MCP.test", "https://MCP.test"),
            ("https://[::1]:8443/mcp", "https://[::1]:8443/mcp"),
        ] {
            assert_eq!(resource(url).as_deref(), Some(resource_is), "{url}");
        }
    }

    #[test]
    fn an_oauth2_table_says_what_is_wrong_with_it() {
        let url = "https://mcp.test/mcp";
        for (table, says) in [
            (
                oauth2(&[("client_secret", "")]),
                "kind = \"oauth2\" needs `client_secret`",
            ),
            (
                oauth2(&[("token_url", "")]),
                "kind = \"oauth2\" needs `token_url`",
            ),
            (
                oauth2(&[("token", "\"t\"")]),
                "`token` is not for kind = \"oauth2\"",
            ),
            (
                "kind = \"bearer\"\ntoken = \"t\"\nscopes = [\"a\"]".to_string(),
                "`scopes` is not for kind = \"bearer\"",
            ),
            (
                oauth2(&[("token_url", "\"idp.test/token\"")]),
                "token_url is not a URL: relative URL without a base",
            ),
            (
                oauth2(&[("token_url", "\"https://mcpdef:hunter2@[idp.test/token\"")]),
                "token_url is not a URL",
            ),
            (
                oauth2(&[("token_url", "\"ftp://mcpdef:hunter2@idp.test/token\"")]),
                "token_url holds a user name or password",
            ),
            (
                oauth2(&[("token_url", "\"ftp://idp.test/token\"")]),
                "is not an https:// or http:// URL",
            ),
            (
                oauth2(&[("token_url", "\"https://idp.test/token#f\"")]),
                "has a fragment, which a token endpoint's URL cannot",
            ),
            (
                oauth2(&[("token_url", "\"https://mcpdef:hunter2@idp.test/token\"")]),
                "token_url holds a user name or password: give the client's as `client_id` and \
                 `client_secret`",
            ),
            (oauth2(&[("client_id", "\"\"")]), "client_id is empty"),
            (
                oauth2(&[("client_auth", "\"private_key_jwt\"")]),
                "unknown client_auth `private_key_jwt`, expected `client_secret_basic` or \
                 `client_secret_post`",
            ),
            (
                oauth2(&[("scopes", "[\"a b\"]")]),
                "scope \"a b\" is not one: a scope is printable ASCII, with no space",
            ),
            (oauth2(&[("scopes", "[\"\"]")]), "scope \"\" is not one"),
            (
                oauth2(&[("resource", "\"mcp.test\"")]),
                "resource \"mcp.test\" is not an absolute URI",
            ),
            (
                oauth2(&[("resource", "\"https://mcp.test/#f\"")]),
                "has a fragment, which RFC 8707 does not allow",
            ),
        ] {
            let errs = with_auth(url, &table).unwrap().validate();
            assert_eq!(errs.len(), 1, "{table}: {errs:?}");
            assert!(
                errs[0].starts_with("server 'x': [server.auth] ") && errs[0].contains(says),
                "{table}: {errs:?}"
            );
            assert!(!errs[0].contains("hunter2"), "{errs:?}");
        }
        for (table, says) in [
            (
                oauth2(&[("scopes", "\"mcp:tools\"")]),
                "invalid type: string \"mcp:tools\", expected a sequence",
            ),
            (
                oauth2(&[("client_id", "{ env = \"ID\" }")]),
                "`client_id` is a string, not a place to read one",
            ),
            (oauth2(&[("scope", "[\"a\"]")]), "unknown field `scope`"),
            (
                "kind = \"oauth\"".to_string(),
                "expected one of `bearer`, `header`, `basic`, `oauth2`",
            ),
        ] {
            let error = with_auth(url, &table).unwrap_err();
            assert!(error.contains(says), "{table}: {error}");
        }
    }

    #[test]
    fn an_oauth2_client_secret_is_withheld_and_warned_about_like_other_secrets() {
        let url = "https://mcp.test/mcp";
        let cfg = with_auth(
            url,
            &oauth2(&[("client_secret", "{ env = \"MCPDEF_CLIENT_SECRET\" }")]),
        )
        .unwrap();
        assert_eq!(cfg.secret_vars(), ["MCPDEF_CLIENT_SECRET"]);
        assert_eq!(cfg.warnings(), Vec::<String>::new());
        // Written in the config.
        let cfg = with_auth(url, &oauth2(&[("client_secret", "\"s3cret\"")])).unwrap();
        let warnings = cfg.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with(
            "server 'x': [server.auth] client_secret is a secret written in the config"
        ));
        // Sent over plain HTTP to another machine.
        let warned = |token_url: &str| {
            with_auth(url, &oauth2(&[("token_url", token_url)]))
                .unwrap()
                .warnings()
        };
        assert_eq!(
            warned("\"http://idp.example.com/token\""),
            [
                "server 'x': [server.auth] sends its client secret over plain HTTP to \
                 idp.example.com, where anyone on the path can read it: give token_url as \
                 https://"
            ]
        );
        assert_eq!(
            warned("\"http://127.0.0.1:8080/token\""),
            Vec::<String>::new()
        );
        // Not a file a reload watches: each fetch reads it.
        let cfg = with_auth(url, &oauth2(&[])).unwrap();
        assert!(cfg.referenced_files().is_empty());
    }
    /// A config whose one server is `server`, a `[[server]]` table's body.
    fn with_server(gateway: &str, server: &str) -> Config {
        Config::parse(&format!(
            "[gateway]\n{gateway}\n\n[[server]]\nid = \"x\"\n{server}\n"
        ))
        .unwrap()
    }

    #[test]
    fn strict_makes_each_warning_an_error_and_leaves_none_to_print() {
        let lax = "transport = \"streamable-http\"\nurl = \"https://mcp.test/mcp\"\n\
                   [server.tls]\ninsecure_skip_verify = true";
        let warning = "server 'x': [server.tls] insecure_skip_verify = true";
        let checked = with_server("", lax).check(false);
        assert!(checked.errors.is_empty(), "{checked:?}");
        assert_eq!(checked.warnings.len(), 1);
        assert!(checked.warnings[0].starts_with(warning), "{checked:?}");
        // Asked for, or said in the config: the same.
        for (gateway, flag) in [
            ("", true),
            ("strict = true", false),
            ("strict = true", true),
        ] {
            let checked = with_server(gateway, lax).check(flag);
            assert!(checked.warnings.is_empty(), "{checked:?}");
            assert_eq!(checked.errors.len(), 1, "{checked:?}");
            assert!(
                checked.errors[0].starts_with(&format!("strict: {warning}")),
                "{checked:?}"
            );
        }
        // After what `validate` finds, which strict leaves as it is.
        let broken = with_server(
            "strict = true",
            "transport = \"stdio\"\n[server.tls]\n\
                                  insecure_skip_verify = true",
        );
        let checked = broken.check(false);
        assert_eq!(
            checked.errors[..checked.errors.len() - 1],
            broken.validate()[..]
        );
        assert!(checked.errors.last().unwrap().starts_with("strict: "));
        // Nothing to warn about: nothing to refuse.
        let clean = with_server(
            "strict = true",
            "transport = \"stdio\"\ncommand = [\"srv\"]",
        );
        assert_eq!(clean.check(true), Checked::default());
    }

    #[test]
    fn a_secret_in_a_url_is_warned_about_and_not_repeated() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let warned = |url: &str| {
            with_server(
                "",
                &format!("transport = \"streamable-http\"\nurl = {url:?}"),
            )
            .warnings()
        };
        for (url, holds) in [
            ("https://mcpdef:hunter2@mcp.test/mcp", "a password"),
            (
                "https://mcp.test/mcp?api_key=hunter2",
                "a secret, its query parameter `api_key`",
            ),
            (
                "https://mcp.test/mcp?page=2&access_token=hunter2",
                "a secret, its query parameter `access_token`",
            ),
            (
                &format!("https://mcp.test/{token}/mcp"),
                "a secret, a github-token by its shape",
            ),
        ] {
            let warnings = warned(url);
            assert_eq!(
                warnings,
                [format!(
                    "server 'x': url holds {holds}, so every copy of the config holds it too, \
                     and so does every message that names the URL: send it with [server.auth] \
                     instead, if the upstream takes it in a header"
                )],
                "{url}"
            );
            assert!(!warnings[0].contains("hunter2") && !warnings[0].contains(&token));
        }
        for url in [
            "https://mcp.test/mcp",
            "https://mcpdef@mcp.test/mcp",
            "https://mcp.test/mcp?page=2&keyword=token",
            "https://mcp.test/mcp?api_key=",
        ] {
            assert_eq!(warned(url), Vec::<String>::new(), "{url}");
        }
    }

    /// A config with `gateway` in its `[gateway]`, `tls` as its
    /// `[gateway.tls]`, and one stdio server.
    fn with_tls(gateway: &str, tls: &str) -> Config {
        Config::parse(&format!(
            "[gateway]\n{gateway}\n[gateway.tls]\n{tls}\n\n\
             [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_listener_tls_table_takes_what_its_mode_uses_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let pki = mcpdef_testkit::Pki::new("mcpdef test CA");
        let leaf = pki.server(&["127.0.0.1"]);
        let (cert, key) = leaf.write(dir.path(), "listener");
        let (other, _) = pki.server(&["127.0.0.1"]).write(dir.path(), "other");
        let der = dir.path().join("listener.der");
        std::fs::write(&der, leaf.key_der().secret_der()).unwrap();
        let files = format!("mode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}");
        assert_eq!(with_tls("", &files).validate(), Vec::<String>::new());
        let named =
            "mode = \"self-signed\"\nhostnames = [\"mcpdef.internal\", \"10.1.2.3\", \"::1\"]";
        assert_eq!(with_tls("", named).validate(), Vec::<String>::new());
        assert_eq!(with_tls("", "").validate(), Vec::<String>::new());
        let needs = "[gateway.tls] mode = \"files\" needs `cert` and `key`: the certificate to \
                     serve, and its key";
        for (tls, problem) in [
            ("mode = \"files\"".to_string(), needs.to_string()),
            (
                format!("mode = \"files\"\ncert = {cert:?}"),
                needs.to_string(),
            ),
            (
                format!("mode = \"self-signed\"\ncert = {cert:?}"),
                "[gateway.tls] has `cert`, which only mode = \"files\" takes, and its mode is \
                 \"self-signed\""
                    .to_string(),
            ),
            (
                format!("key = {{ file = {key:?} }}"),
                "[gateway.tls] has `key`, which only mode = \"files\" takes, and its mode is \
                 \"off\""
                    .to_string(),
            ),
            (
                format!("{files}\nhostnames = [\"a.test\"]"),
                "[gateway.tls] has `hostnames`, which only mode = \"self-signed\" takes, and its \
                 mode is \"files\": a certificate from files is for the names it was issued for"
                    .to_string(),
            ),
            (
                "mode = \"self-signed\"\nhostnames = [\"*.mcpdef.internal\"]".to_string(),
                "[gateway.tls] hostnames entry \"*.mcpdef.internal\" is a wildcard: name each \
                 host"
                    .to_string(),
            ),
            (
                "mode = \"self-signed\"\nhostnames = [\"not a name\"]".to_string(),
                "[gateway.tls] hostnames entry \"not a name\" is neither a DNS name nor an IP \
                 address"
                    .to_string(),
            ),
            (
                "mode = \"self-signed\"\nhostnames = [\"mcpdef.internal.\"]".to_string(),
                "[gateway.tls] hostnames entry \"mcpdef.internal.\" is neither a DNS name nor an \
                 IP address"
                    .to_string(),
            ),
            // Read as a client certificate is, the refusal naming the table.
            (
                format!("mode = \"files\"\ncert = {other:?}\nkey = {{ file = {key:?} }}"),
                format!(
                    "[gateway.tls] key {}: does not match the certificate first in cert {}",
                    key.display(),
                    other.display()
                ),
            ),
            (
                format!("mode = \"files\"\ncert = {key:?}\nkey = {{ file = {key:?} }}"),
                format!(
                    "[gateway.tls] cert {}: holds no certificate (-----BEGIN CERTIFICATE-----)",
                    key.display()
                ),
            ),
            // A key in DER is told how to become PEM, as a key.
            (
                format!("mode = \"files\"\ncert = {cert:?}\nkey = {{ file = {der:?} }}"),
                format!(
                    "[gateway.tls] key {}: is not PEM, and MCPdef reads PEM only: if it is DER, \
                     convert it with `openssl pkey -inform DER -in FILE -out FILE.pem`",
                    der.display()
                ),
            ),
        ] {
            assert_eq!(with_tls("", &tls).validate(), [problem], "{tls}");
        }
        // The admin listener's own table, by its own name.
        let admin = "[gateway.admin]\nenabled = true\n[gateway.admin.tls]\nmode = \"files\"";
        assert_eq!(
            with_tls(admin, "").validate(),
            [needs.replace("[gateway.tls]", "[gateway.admin.tls]")]
        );
        assert_eq!(
            with_tls("state_dir = \" \"", "").validate(),
            ["[gateway] state_dir is empty: name a directory MCPdef can write to"]
        );
        // What is not part of the table, or not a mode, does not parse.
        for bad in [
            "[gateway.tls]\nmode = \"files\"\ncertificate = \"x\"\n",
            "[gateway.tls]\nmode = \"on\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_auth_takes_what_its_mode_uses_and_reads_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let pki = mcpdef_testkit::Pki::new("agents CA");
        let ca = pki.write_root(dir.path(), "agents-ca");
        let crl = pki.crl(&[]).write(dir.path(), "agents");
        let missing = dir.path().join("missing.pem");
        let on = "mode = \"self-signed\"\n[gateway.tls.client_auth]";
        let spiffe = format!(
            "mode = \"required\"\nca = [{ca:?}]\ncrl = [{crl:?}]\nidentity = \"spiffe\"\n\
             trust_domains = [\"prod.acme.internal\", \"staging_2.acme\"]"
        );
        let cfg = with_tls("", &format!("{on}\n{spiffe}"));
        assert_eq!(cfg.validate(), Vec::<String>::new());
        // Its files are watched, as the certificate's are.
        let watched = cfg.referenced_files();
        for file in [&ca, &crl] {
            assert!(watched.contains(&file.display().to_string()), "{watched:?}");
        }
        for identity in ["san-dns", "san-email", "subject-cn"] {
            let tls =
                format!("{on}\nmode = \"optional\"\nca = [{ca:?}]\nidentity = \"{identity}\"");
            assert_eq!(
                with_tls("", &tls).validate(),
                Vec::<String>::new(),
                "{identity}"
            );
        }
        let table = "[gateway.tls.client_auth]";
        for (client_auth, problem) in [
            (
                "mode = \"required\"\nidentity = \"san-dns\"".to_string(),
                format!(
                    "{table} mode = \"required\" needs `ca`: the CA certificates a client's \
                     certificate has to chain to"
                ),
            ),
            (
                format!("mode = \"required\"\nca = [{ca:?}]"),
                format!(
                    "{table} mode = \"required\" needs `identity`: which of a certificate's names \
                     is its client's, \"spiffe\", \"san-dns\", \"san-email\" or \"subject-cn\""
                ),
            ),
            (
                format!("mode = \"optional\"\nca = [{ca:?}]\nidentity = \"spiffe\""),
                format!(
                    "{table} identity = \"spiffe\" needs `trust_domains`: the trust domains a \
                     SPIFFE ID may name"
                ),
            ),
            (
                format!(
                    "mode = \"optional\"\nca = [{ca:?}]\nidentity = \"spiffe\"\n\
                     trust_domains = [\"spiffe://prod.acme.internal\"]"
                ),
                format!(
                    "{table} trust_domains entry \"spiffe://prod.acme.internal\" is not a trust \
                     domain: one is lowercase letters, digits, '.', '-' and '_', written without \
                     spiffe://"
                ),
            ),
            (
                format!(
                    "mode = \"optional\"\nca = [{ca:?}]\nidentity = \"spiffe\"\n\
                     trust_domains = [\"\"]"
                ),
                format!("{table} trust_domains entry \"\" is empty"),
            ),
            (
                format!(
                    "mode = \"optional\"\nca = [{ca:?}]\nidentity = \"san-dns\"\n\
                     trust_domains = [\"prod.acme.internal\"]"
                ),
                format!(
                    "{table} has `trust_domains`, which only identity = \"spiffe\" takes, and its \
                     identity is \"san-dns\""
                ),
            ),
            (
                format!("ca = [{ca:?}]"),
                format!(
                    "{table} has `ca`, which only mode = \"optional\" or \"required\" takes, and \
                     its mode is \"off\""
                ),
            ),
            (
                format!("mode = \"off\"\ncrl = [{crl:?}]"),
                format!(
                    "{table} has `crl`, which only mode = \"optional\" or \"required\" takes, and \
                     its mode is \"off\""
                ),
            ),
            (
                "identity = \"spiffe\"".to_string(),
                format!(
                    "{table} has `identity`, which only mode = \"optional\" or \"required\" \
                     takes, and its mode is \"off\""
                ),
            ),
            // Read as an upstream's CAs and CRLs are, the refusal naming the
            // table.
            (
                format!("mode = \"required\"\nca = [{crl:?}]\nidentity = \"san-dns\""),
                format!(
                    "{table} ca {}: holds a X509 CRL section, where it should hold CA \
                     certificates only",
                    crl.display()
                ),
            ),
            (
                format!(
                    "mode = \"required\"\nca = [{ca:?}]\ncrl = [{ca:?}]\nidentity = \"san-dns\""
                ),
                format!(
                    "{table} crl {}: holds a CERTIFICATE section, where it should hold CRLs only",
                    ca.display()
                ),
            ),
            (
                format!("mode = \"required\"\nca = [{missing:?}]\nidentity = \"san-dns\""),
                format!(
                    "{table} ca {}: No such file or directory (os error 2)",
                    missing.display()
                ),
            ),
        ] {
            assert_eq!(
                with_tls("", &format!("{on}\n{client_auth}")).validate(),
                [problem],
                "{client_auth}"
            );
        }
        // On a listener with no TLS, there is no handshake to ask at.
        let plain = format!(
            "\n[gateway.tls.client_auth]\nmode = \"required\"\nca = [{ca:?}]\nidentity = \"san-dns\""
        );
        assert_eq!(
            with_tls("", &plain).validate(),
            [format!(
                "{table} mode = \"required\" needs TLS on its listener, and [gateway.tls] mode \
                 is \"off\""
            )]
        );
        // The admin listener's own, by its own name.
        let admin =
            "[gateway.admin]\nenabled = true\n[gateway.admin.tls]\nmode = \"self-signed\"\n\
                     [gateway.admin.tls.client_auth]\nmode = \"required\"";
        assert_eq!(
            with_tls(admin, "").validate(),
            [
                "[gateway.admin.tls.client_auth] mode = \"required\" needs `ca`: the CA \
                 certificates a client's certificate has to chain to",
                "[gateway.admin.tls.client_auth] mode = \"required\" needs `identity`: which of a \
                 certificate's names is its client's, \"spiffe\", \"san-dns\", \"san-email\" or \
                 \"subject-cn\""
            ]
        );
        // What is not part of the table, or not one of its values, does not
        // parse: `max_depth` among them, which rustls has no setting for.
        for bad in [
            "max_depth = 3",
            "mode = \"on\"",
            "identity = \"spiffe-id\"",
            "trust_domains = \"prod.acme.internal\"",
        ] {
            let text = format!(
                "[gateway]\n[gateway.tls]\nmode = \"self-signed\"\n[gateway.tls.client_auth]\n{bad}\n"
            );
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_trusted_proxy_names_its_addresses_and_reads_with_client_auth() {
        let dir = tempfile::tempdir().unwrap();
        let pki = mcpdef_testkit::Pki::new("agents CA");
        let ca = pki.write_root(dir.path(), "agents-ca");
        let client_auth = format!(
            "[gateway.tls.client_auth]\nmode = \"required\"\nca = [{ca:?}]\nidentity = \"san-dns\"\n"
        );
        // On every address, with no TLS of its own: the proxy's.
        let proxied = |proxy: &str, client_auth: &str, gateway: &str| {
            Config::parse(&format!(
                "[gateway]\nlisten = \"0.0.0.0:7878\"\n{gateway}\n{client_auth}\
                 [gateway.trusted_proxy]\n{proxy}\n\n\
                 [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n"
            ))
            .unwrap()
        };
        // Behind a proxy, `client_auth` needs no TLS of its own, and the
        // listener is not taken for one exposed in the clear.
        let cfg = proxied(
            "cidrs = [\"10.0.0.0/8\", \"fd00::/8\", \"192.0.2.7\"]\n\
             client_cert_header = \"x-forwarded-client-cert\"",
            &client_auth,
            "",
        );
        assert_eq!(cfg.validate(), Vec::<String>::new());
        assert_eq!(cfg.warnings(), Vec::<String>::new());
        let header = |cfg: Config| cfg.gateway.trusted_proxy.unwrap().client_cert_header;
        assert_eq!(header(cfg), ClientCertHeader::XForwardedClientCert);
        // RFC 9440's is the default.
        let rfc_9440 = proxied("cidrs = [\"10.0.0.0/8\"]", &client_auth, "");
        assert_eq!(header(rfc_9440), ClientCertHeader::ClientCert);

        // Under `optional`, a client that connects to the listener directly,
        // past the proxy, is served as no one: with auth off, that listener
        // is exposed in the clear. Refused under strict.
        let optional = format!(
            "[gateway.tls.client_auth]\nmode = \"optional\"\nca = [{ca:?}]\nidentity = \"san-dns\"\n"
        );
        let exposed = "[gateway] listen = \"0.0.0.0:7878\" takes connections from other \
                       machines, and neither TLS nor auth is on: whoever can reach it can call \
                       every tool it allows, and read what passes. [gateway.trusted_proxy] does \
                       not stop a client connecting to it directly, and one that does is served \
                       as no one unless [gateway.tls.client_auth] mode = \"required\". Set that \
                       mode, or [gateway.auth], or listen on 127.0.0.1 beside the proxy";
        let cfg = proxied("cidrs = [\"10.0.0.0/8\"]", &optional, "");
        assert_eq!(cfg.validate(), Vec::<String>::new());
        assert_eq!(cfg.warnings(), [exposed]);
        let strict = proxied("cidrs = [\"10.0.0.0/8\"]", &optional, "strict = true");
        assert_eq!(strict.check(false).errors, [format!("strict: {exposed}")]);
        // With auth on, a request needs a credential: nothing to say.
        let mtls = proxied(
            "cidrs = [\"10.0.0.0/8\"]",
            &optional,
            "[gateway.auth]\nenabled = true\nmethods = [\"mtls\"]",
        );
        assert_eq!(mtls.validate(), Vec::<String>::new());
        assert_eq!(mtls.warnings(), Vec::<String>::new());

        let table = "[gateway.trusted_proxy]";
        for (proxy, client_auth, problem) in [
            (
                "",
                client_auth.as_str(),
                format!(
                    "{table} needs `cidrs`: the addresses of the proxy in front of the listener"
                ),
            ),
            (
                "cidrs = [\"10.0.0.1/8\"]",
                &client_auth,
                format!(
                    "{table} cidrs entry \"10.0.0.1/8\" has bits set past its prefix length: \
                     the range is 10.0.0.0/8"
                ),
            ),
            (
                "cidrs = [\"proxy.internal\"]",
                &client_auth,
                format!(
                    "{table} cidrs entry \"proxy.internal\" is not an address, or a range such \
                     as 10.0.0.0/8 or fd00::/8"
                ),
            ),
            // Nothing to check what it forwards with: it would be read for
            // nothing.
            (
                "cidrs = [\"10.0.0.0/8\"]",
                "",
                format!(
                    "{table} reads the client certificates the proxy forwards, and \
                     [gateway.tls.client_auth] mode is \"off\": set it, to say how they are \
                     checked and read"
                ),
            ),
        ] {
            assert_eq!(
                proxied(proxy, client_auth, "").validate(),
                [problem],
                "{proxy}"
            );
        }

        // A range of every address: anyone could forward a client's
        // certificate. Warned about, and refused under strict.
        let every = "[gateway.trusted_proxy] cidrs entry \"0.0.0.0/0\" trusts every address: a \
                     client's certificate is no secret, so whoever reaches the listener can \
                     forward one, and be taken for that client. Name the proxy's own addresses";
        let cfg = proxied("cidrs = [\"0.0.0.0/0\"]", &client_auth, "");
        assert_eq!(cfg.warnings(), [every]);
        let strict = proxied("cidrs = [\"0.0.0.0/0\"]", &client_auth, "strict = true");
        assert_eq!(strict.check(false).errors, [format!("strict: {every}")]);

        // What is not part of the table, or not one of its headers, does
        // not parse.
        for bad in [
            "cidrs = [\"10.0.0.0/8\"]\nheader = \"client-cert\"",
            "client_cert_header = \"x-ssl-client-cert\"",
            "cidrs = \"10.0.0.0/8\"",
        ] {
            let text = format!("[gateway]\n[gateway.trusted_proxy]\n{bad}\n");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

    /// A config with `client_auth` as its `[gateway.tls.client_auth]`, on
    /// TLS from the local CA, and `auth` as its `[gateway.auth]`.
    fn with_methods(dir: &Path, client_auth: bool, auth: &str) -> Config {
        let pki = mcpdef_testkit::Pki::new("agents CA");
        let ca = pki.write_root(dir, "agents-ca");
        let client_auth = match client_auth {
            true => format!(
                "[gateway.tls.client_auth]\nmode = \"optional\"\nca = [{ca:?}]\n\
                 identity = \"san-dns\"\n"
            ),
            false => String::new(),
        };
        Config::parse(&format!(
            "[gateway]\n[gateway.tls]\nmode = \"self-signed\"\n{client_auth}\
             [gateway.auth]\n{auth}\n\n\
             [[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n"
        ))
        .unwrap()
    }

    #[test]
    fn auth_methods_name_each_method_once_and_mtls_needs_a_certificate_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let bearer = "issuer = \"https://as.test\"\nresource = \"https://gw.test\"\njwks = \"{}\"";
        let ok = |client_auth: bool, auth: &str| {
            assert_eq!(
                with_methods(dir.path(), client_auth, auth).validate(),
                Vec::<String>::new(),
                "{auth}"
            );
        };
        // A certificate alone needs no issuer, audience or keys.
        ok(true, "enabled = true\nmethods = [\"mtls\"]");
        ok(
            true,
            &format!(
                "enabled = true\nmethods = [\"bearer\", \"mtls\"]\nrequire = \"all\"\n{bearer}"
            ),
        );
        ok(false, &format!("enabled = true\n{bearer}"));
        ok(
            false,
            &format!("enabled = true\nmethods = [\"bearer\"]\nrequire = \"any\"\n{bearer}"),
        );
        let mtls_unasked = "[gateway.auth] methods names \"mtls\", and the listener asks for no \
                            client certificate: set [gateway.tls.client_auth] mode = \"optional\" \
                            or \"required\"";
        for (client_auth, auth, problems) in [
            (
                false,
                "enabled = true\nmethods = [\"mtls\"]".to_string(),
                vec![mtls_unasked.to_string()],
            ),
            (
                true,
                "enabled = true\nmethods = []".to_string(),
                vec![
                    "[gateway.auth] methods is empty: name \"bearer\", \"mtls\", \"key\" or more"
                        .into(),
                ],
            ),
            (
                true,
                "enabled = true\nmethods = [\"mtls\", \"mtls\"]".to_string(),
                vec!["[gateway.auth] methods names \"mtls\" twice".into()],
            ),
            // A token among the methods needs what a token is checked by.
            (
                true,
                "enabled = true\nmethods = [\"mtls\", \"bearer\"]".to_string(),
                vec![
                    "[gateway.auth] enabled but `issuer` is not set".into(),
                    "[gateway.auth] enabled but `resource` (audience) is not set".into(),
                    "[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set".into(),
                ],
            ),
            // Set while auth is off, they would make it look on.
            (
                true,
                "methods = [\"mtls\"]\nrequire = \"all\"".to_string(),
                vec![
                    "[gateway.auth] has `methods`, which applies only with enabled = true".into(),
                    "[gateway.auth] has `require`, which applies only with enabled = true".into(),
                ],
            ),
        ] {
            assert_eq!(
                with_methods(dir.path(), client_auth, &auth).validate(),
                problems,
                "{auth}"
            );
        }
        for bad in [
            "methods = [\"password\"]",
            "require = \"both\"",
            "methods = \"mtls\"",
        ] {
            let text = format!("[gateway]\n[gateway.auth]\nenabled = true\n{bad}\n");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
        let auth = with_methods(dir.path(), true, "enabled = true\nmethods = [\"mtls\"]");
        assert_eq!(auth.gateway.auth.methods(), [AuthMethod::Mtls]);
        assert!(!auth.gateway.auth.takes(AuthMethod::Bearer));
        // Unset, a token alone, as before methods.
        assert_eq!(AuthConfig::default().methods(), [AuthMethod::Bearer]);
    }

    /// The one server a config that validates needs.
    const ONE_SERVER: &str =
        "\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n";

    #[test]
    fn a_console_role_is_one_of_three_and_needs_no_role_table() {
        let cfg = |roles: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[[identity.cert_map]]\nidentity = \"spiffe://acme/ops/*\"\n\
                 roles = {roles}\n{ONE_SERVER}"
            ))
            .unwrap()
        };
        let mapped = cfg("[\"console:viewer\", \"console:operator\", \"console:admin\"]");
        assert_eq!(mapped.validate(), Vec::<String>::new());
        assert_eq!(mapped.warnings(), Vec::<String>::new());
        let misspelt = cfg("[\"console:viewers\"]");
        assert_eq!(
            misspelt.validate(),
            ["[[identity.cert_map]] entry 1 (\"spiffe://acme/ops/*\") maps to 'console:viewers', \
              which is no console role: name console:viewer, console:operator or console:admin"]
        );
    }

    #[test]
    fn an_admin_listener_other_machines_reach_needs_a_sign_in_or_a_proxy_said_to_give_one() {
        let admin = |rest: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[gateway.admin]\nenabled = true\nlisten = \"0.0.0.0:7879\"\n{rest}\
                 {ONE_SERVER}"
            ))
            .unwrap()
            .validate()
        };
        let refused = admin("");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with(
                "[gateway.admin] listen = \"0.0.0.0:7879\" takes connections from other machines, \
                 and nothing signs its callers in"
            ),
            "{refused:?}"
        );
        assert_eq!(
            admin("allow_unauthenticated = true\n"),
            Vec::<String>::new()
        );
        let certificates = admin(
            "[gateway.admin.tls]\nmode = \"self-signed\"\n\
             [gateway.admin.tls.client_auth]\nmode = \"required\"\nca = [\"/ca.pem\"]\n\
             identity = \"subject-cn\"\n",
        );
        // The CA is not there to read, and that is all that is wrong.
        assert!(
            certificates
                .iter()
                .all(|p| !p.contains("nothing signs its callers in")),
            "{certificates:?}"
        );
        // Off, or on loopback, it is not asked.
        let off = Config::parse(&format!(
            "[gateway]\n\n[gateway.admin]\nlisten = \"0.0.0.0:7879\"\n{ONE_SERVER}"
        ))
        .unwrap();
        assert_eq!(off.validate(), Vec::<String>::new());
    }

    #[test]
    fn client_keys_are_named_digested_and_given_roles() {
        let digest = "ab".repeat(32);
        let key = |name: &str, sha256: &str, roles: &str| {
            format!("\n[[key]]\nname = {name:?}\nsha256 = {sha256:?}\nroles = {roles}\n")
        };
        let config = |methods: &str, keys: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[gateway.auth]\nenabled = true\nmethods = {methods}\n\n\
                 [[role]]\nname = \"reader\"\ngrants = [\"a:*\"]\n{keys}{ONE_SERVER}"
            ))
            .unwrap()
        };
        let good = config("[\"key\"]", &key("ci-bot", &digest, "[\"reader\"]"));
        assert_eq!(good.validate(), Vec::<String>::new());
        assert_eq!(good.warnings(), Vec::<String>::new());
        assert_eq!(good.issued_keys().len(), 1);
        assert_eq!(good.issued_keys()[0].digest, [0xab; 32]);
        for (keys, why) in [
            (
                key("two words", &digest, "[\"reader\"]"),
                "has the name \"two words\"",
            ),
            (key("", &digest, "[\"reader\"]"), "has the name \"\""),
            (
                key("ci-bot", "abc", "[\"reader\"]"),
                "sha256 is no SHA-256 in hex",
            ),
            (key("ci-bot", &digest, "[]"), "has no roles"),
            (
                format!(
                    "{}{}",
                    key("ci-bot", &digest, "[\"reader\"]"),
                    key("ci-bot", &"cd".repeat(32), "[\"reader\"]")
                ),
                "is named twice",
            ),
        ] {
            let problems = config("[\"key\"]", &keys).validate();
            assert!(
                problems.len() == 1 && problems[0].contains(why),
                "{why:?}: {problems:?}"
            );
        }
        // Keys no listener reads, and a role no [[role]] defines.
        let unread = config("[\"mtls\"]", &key("ci-bot", &digest, "[\"writer\"]"));
        let warnings = unread.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("no listener takes keys")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("holds role 'writer', which no [[role]] defines")),
            "{warnings:?}"
        );
        // A request carries one bearer token.
        let both = Config::parse(&format!(
            "[gateway]\n\n[gateway.auth]\nenabled = true\nissuer = \"https://as.example\"\n\
             resource = \"https://mcp.example/mcp\"\njwks = \"{{}}\"\n\
             methods = [\"bearer\", \"key\"]\nrequire = \"all\"\n{ONE_SERVER}"
        ))
        .unwrap()
        .validate();
        assert!(
            both.iter()
                .any(|p| p.contains("requires both \"bearer\" and \"key\"")),
            "{both:?}"
        );
        // The gateway's own issuer is no authorization server's.
        let own = Config::parse(&format!(
            "[gateway]\n\n[gateway.auth]\nenabled = true\nissuer = \"mcpdef\"\n\
             resource = \"https://mcp.example/mcp\"\njwks = \"{{}}\"\n{ONE_SERVER}"
        ))
        .unwrap()
        .validate();
        assert!(
            own.iter()
                .any(|p| p.contains("issuer = \"mcpdef\" is the issuer")),
            "{own:?}"
        );
    }

    #[test]
    fn discovery_stands_for_the_keys_and_audiences_are_named() {
        let auth = |rest: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[gateway.auth]\nenabled = true\nissuer = \"https://as.example\"\n\
                 resource = \"https://mcp.example/mcp\"\n{rest}{ONE_SERVER}"
            ))
            .unwrap()
            .validate()
        };
        assert_eq!(auth("discovery = true\n"), Vec::<String>::new());
        assert_eq!(
            auth("discovery = true\naudiences = [\"api://0000-aaaa\"]\n"),
            Vec::<String>::new()
        );
        for keys in [
            "jwks_uri = \"https://as.example/keys\"\n",
            "jwks = \"{}\"\n",
        ] {
            let problems = auth(&format!("discovery = true\n{keys}"));
            assert!(
                problems
                    .iter()
                    .any(|p| p.contains("[gateway.auth] discovery finds jwks_uri itself")),
                "{keys}: {problems:?}"
            );
        }
        assert_eq!(
            auth(""),
            ["[gateway.auth] enabled but neither `jwks` nor `jwks_uri` is set"]
        );
        assert_eq!(
            auth("discovery = true\naudiences = [\" \"]\n"),
            ["[gateway.auth] audiences holds an empty audience"]
        );
        // The admin API's audience is the admin API's alone.
        let shared = Config::parse(&format!(
            "[gateway]\n\n[gateway.auth]\nenabled = true\nissuer = \"https://as.example\"\n\
             resource = \"https://mcp.example/mcp\"\ndiscovery = true\n\
             audiences = [\"api://admin\"]\n\n\
             [gateway.admin]\npublic_url = \"https://console.example\"\n\n\
             [gateway.admin.oidc]\nissuer = \"https://as.example\"\nclient_id = \"console\"\n\
             api_audience = \"api://admin\"\n{ONE_SERVER}"
        ))
        .unwrap()
        .validate();
        assert_eq!(shared.len(), 1, "{shared:?}");
        assert!(
            shared[0].contains("is one of [gateway.auth] audiences"),
            "{shared:?}"
        );
    }

    #[test]
    fn the_consoles_sign_in_and_its_break_glass_token_are_checked() {
        let admin = |rest: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[gateway.auth]\nenabled = true\nissuer = \"https://idp.example\"\n\
                 resource = \"https://mcp.example/mcp\"\njwks = \"{{}}\"\n\n\
                 [gateway.admin]\nenabled = true\nlisten = \"0.0.0.0:7879\"\n{rest}{ONE_SERVER}"
            ))
            .unwrap()
            .validate()
            .into_iter()
            .filter(|p| !p.contains("jwks"))
            .collect::<Vec<_>>()
        };
        let oidc = |more: &str| {
            format!(
                "public_url = \"https://console.example\"\n\n[gateway.admin.oidc]\n\
                 issuer = \"https://idp.example\"\nclient_id = \"console\"\n{more}"
            )
        };
        // Either signs callers in, so the listener may face other machines.
        assert_eq!(admin(&oidc("")), Vec::<String>::new());
        assert_eq!(
            admin(&format!(
                "[gateway.admin.break_glass]\ntoken_sha256 = \"{}\"\n",
                "ab".repeat(32)
            )),
            Vec::<String>::new()
        );
        assert_eq!(
            admin(&oidc(
                "api_audience = \"https://console.example/api\"\nscopes = [\"groups\"]\n\
                 client_auth = \"client_secret_post\"\nclient_secret = { env = \"S\" }\n"
            )),
            Vec::<String>::new()
        );
        let one = |rest: &str, why: &str| {
            let problems = admin(rest);
            assert!(
                problems.len() == 1 && problems[0].contains(why),
                "{why:?} not the one problem of {rest:?}: {problems:?}"
            );
        };
        one(
            "[gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n",
            "needs [gateway.admin] public_url",
        );
        for (issuer, why) in [
            ("http://idp.example", "is no https URL with a host"),
            ("https://u:p@idp.example", "holds credentials"),
            (
                "https://idp.example/?realm=ops",
                "has a query or a fragment",
            ),
            ("idp.example", "is no URL"),
        ] {
            one(
                &format!(
                    "public_url = \"https://console.example\"\n\n[gateway.admin.oidc]\n\
                     issuer = {issuer:?}\nclient_id = \"c\"\n"
                ),
                why,
            );
        }
        // On this machine, a provider may be plain HTTP.
        assert_eq!(
            admin(
                "public_url = \"https://console.example\"\n\n[gateway.admin.oidc]\n\
                 issuer = \"http://127.0.0.1:8080/realms/ops\"\nclient_id = \"c\"\n"
            ),
            Vec::<String>::new()
        );
        one(
            &oidc("").replace("client_id = \"console\"", "client_id = \" \""),
            "has an empty client_id",
        );
        one(
            &oidc("client_auth = \"private_key_jwt\"\n"),
            "client_secret_basic or client_secret_post",
        );
        one(
            &oidc("scopes = [\"groups email\"]\n"),
            "an empty scope, or one with a space",
        );
        one(&oidc("api_audience = \"\"\n"), "has an empty api_audience");
        one(
            &oidc("api_audience = \"https://mcp.example/mcp\"\n"),
            "a token for the MCP listener would open the admin API",
        );
        one(
            &oidc("api_audience = \"console\"\n"),
            "an ID token would open the admin API",
        );
        for digest in ["", "ab", &"zz".repeat(32), &"ab".repeat(33)] {
            one(
                &format!("[gateway.admin.break_glass]\ntoken_sha256 = {digest:?}\n"),
                "token_sha256 is no SHA-256 in hex",
            );
        }
    }

    #[test]
    fn public_url_is_the_consoles_origin_and_hosts_are_names() {
        let admin = |rest: &str| {
            Config::parse(&format!("[gateway]\n\n[gateway.admin]\n{rest}{ONE_SERVER}"))
                .unwrap()
                .validate()
        };
        for good in [
            "https://console.acme.internal",
            "https://console.acme.internal:8443/",
            "http://127.0.0.1:7879",
            "http://localhost:7879",
            "http://[::1]:7879",
        ] {
            assert_eq!(
                admin(&format!("public_url = {good:?}\n")),
                Vec::<String>::new(),
                "{good}"
            );
        }
        for (bad, why) in [
            ("console.acme.internal", "is not a URL"),
            ("ftp://console.acme.internal", "is not an http or https URL"),
            ("https://ops:pw@console.acme.internal", "holds credentials"),
            (
                "https://console.acme.internal/mcpdef",
                "names a path, a query or a fragment",
            ),
            (
                "https://console.acme.internal/?x=1",
                "names a path, a query or a fragment",
            ),
            ("http://console.acme.internal", "is http to another machine"),
        ] {
            let problems = admin(&format!("public_url = {bad:?}\n"));
            assert_eq!(problems.len(), 1, "{bad}: {problems:?}");
            assert!(problems[0].contains(why), "{bad}: {problems:?}");
        }
        assert_eq!(
            admin("hosts = [\"mcpdef-admin.monitoring.svc\"]\n"),
            Vec::<String>::new()
        );
        for bad in ["", "https://x", "x:7879", "a b"] {
            assert_eq!(admin(&format!("hosts = [{bad:?}]\n")).len(), 1, "{bad:?}");
        }
    }

    #[test]
    fn the_identity_model_reads_its_claims_and_checks_its_map() {
        let cfg = |identity: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n\n\
                 [[role]]\nname = \"reader\"\ngrants = [\"x:read\"]\n\n{identity}"
            ))
            .unwrap()
        };
        // None: a token is read as it always was.
        assert_eq!(
            cfg("").identity.model(),
            mcpdef_auth::IdentityModel::default()
        );
        let set = cfg(
            "[identity]\nsubject_claim = \"email\"\nroles_claims = [\"realm_access.roles\", \"groups\"]\n\n\
             [[identity.role_map]]\nclaim = \"hd\"\nvalue = \"example.com\"\nroles = [\"reader\", \"console:viewer\"]\n",
        );
        assert_eq!(set.validate(), Vec::<String>::new());
        assert_eq!(set.warnings(), Vec::<String>::new());
        let model = set.identity.model();
        assert_eq!(model.subject_claim, "email");
        assert_eq!(model.roles_claims, ["realm_access.roles", "groups"]);
        assert_eq!(model.role_map[0].roles, ["reader", "console:viewer"]);
        for (identity, problem) in [
            (
                "[identity]\nsubject_claim = \"a..b\"",
                "[identity] names the claim \"a..b\": a claim's name, or a path of names joined by \
                 single dots",
            ),
            (
                "[identity]\nroles_claims = [\"\"]",
                "[identity] names the claim \"\": a claim's name, or a path of names joined by \
                 single dots",
            ),
            (
                "[[identity.role_map]]\nclaim = \"groups\"\nvalue = \"\"\nroles = [\"reader\"]",
                "[[identity.role_map]] entry 1 (groups) has an empty `value`",
            ),
            (
                "[[identity.role_map]]\nclaim = \"groups\"\nvalue = \"ops\"\nroles = []",
                "[[identity.role_map]] entry 1 (groups = \"ops\") maps to no role: name the `roles` \
                 it gives",
            ),
            (
                "[[identity.role_map]]\nclaim = \"groups\"\nvalue = \"ops\"\nroles = [\"console:root\"]",
                "[[identity.role_map]] entry 1 (groups = \"ops\") maps to 'console:root', which is no \
                 console role: name console:viewer, console:operator or console:admin",
            ),
        ] {
            assert_eq!(cfg(identity).validate(), [problem], "{identity}");
        }
        let misspelled =
            cfg("[[identity.role_map]]\nclaim = \"groups\"\nvalue = \"ops\"\nroles = [\"raeder\"]");
        assert_eq!(
            misspelled.warnings(),
            [
                "[[identity.role_map]] maps groups = \"ops\" to role 'raeder', which no [[role]] \
              defines: it grants nothing"
            ]
        );
    }

    #[test]
    fn a_cert_map_maps_identities_to_roles_and_names_roles_that_exist() {
        let cfg = |cert_map: &str| {
            Config::parse(&format!(
                "[gateway]\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n\n\
                 [[role]]\nname = \"ci\"\ngrants = [\"x:*\"]\n\n\
                 [[role]]\nname = \"reader\"\ngrants = [\"x:read\"]\n\n{cert_map}"
            ))
            .unwrap()
        };
        let mapped = cfg(
            "[[identity.cert_map]]\nidentity = \"spiffe://acme/ci/*\"\nroles = [\"ci\"]\n\n\
             [[identity.cert_map]]\nidentity = \"spiffe://acme/ci/sa/bot\"\nroles = [\"reader\"]\n",
        );
        assert_eq!(mapped.validate(), Vec::<String>::new());
        assert_eq!(mapped.warnings(), Vec::<String>::new());
        // Every entry that matches gives its roles; none, no role.
        let rbac = mapped.rbac();
        let roles = |identity: &str| {
            rbac.certificate_roles(identity)
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(roles("spiffe://acme/ci/sa/bot"), ["ci", "reader"]);
        assert_eq!(roles("spiffe://acme/ci/sa/other"), ["ci"]);
        assert_eq!(roles("spiffe://acme/web/sa/app"), Vec::<String>::new());
        for (cert_map, problem) in [
            (
                "[[identity.cert_map]]\nidentity = \" \"\nroles = [\"ci\"]",
                "[[identity.cert_map]] entry 1 has an empty `identity`",
            ),
            (
                "[[identity.cert_map]]\nidentity = \"spiffe://acme/ci/*\"\nroles = []",
                "[[identity.cert_map]] entry 1 (\"spiffe://acme/ci/*\") maps to no role: name the \
                 `roles` it holds",
            ),
            (
                "[[identity.cert_map]]\nidentity = \"spiffe://acme/ci/*\"\nroles = [\"\"]",
                "[[identity.cert_map]] entry 1 (\"spiffe://acme/ci/*\") has an empty role",
            ),
        ] {
            assert_eq!(cfg(cert_map).validate(), [problem], "{cert_map}");
        }
        // A role no [[role]] defines grants nothing: most likely misspelled.
        let misspelled =
            cfg("[[identity.cert_map]]\nidentity = \"spiffe://acme/ci/*\"\nroles = [\"cl\"]");
        assert_eq!(misspelled.validate(), Vec::<String>::new());
        assert_eq!(
            misspelled.warnings(),
            [
                "[[identity.cert_map]] maps \"spiffe://acme/ci/*\" to role 'cl', which no [[role]] \
                 defines: it grants nothing"
            ]
        );
        for bad in [
            "[[identity.cert_map]]\nidentity = \"a\"\nroles = [\"ci\"]\nrole = \"ci\"",
            "[[identity.cert_map]]\nroles = [\"ci\"]",
            "[identity]\nsubject = \"sub\"",
        ] {
            let text = format!("[gateway]\n{bad}\n");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_listener_other_machines_reach_with_neither_tls_nor_auth_is_warned_about() {
        let exposed = "[gateway] listen = \"0.0.0.0:7878\" takes connections from other \
                       machines, and neither TLS nor auth is on: whoever can reach it can call \
                       every tool it allows, and read what passes. Set [gateway.tls] and \
                       [gateway.auth], or listen on 127.0.0.1";
        assert_eq!(
            with_tls("listen = \"0.0.0.0:7878\"", "").warnings(),
            [exposed]
        );
        let strict = with_tls("listen = \"0.0.0.0:7878\"\nstrict = true", "");
        assert_eq!(strict.check(false).errors, [format!("strict: {exposed}")]);
        // Any address but a loopback one: the machine's own on a network,
        // every one, or a name.
        for listen in ["10.1.2.3:7878", "[::]:7878", "mcpdef.internal:7878"] {
            let warnings = with_tls(&format!("listen = \"{listen}\""), "").warnings();
            assert_eq!(warnings.len(), 1, "{listen}: {warnings:?}");
            assert!(warnings[0].contains("neither TLS nor auth"), "{warnings:?}");
        }
        // TLS on, auth on, or a loopback bind: nothing to say.
        let auth = "listen = \"0.0.0.0:7878\"\n[gateway.auth]\nenabled = true\n\
                    issuer = \"https://as.test\"\nresource = \"https://gw.test\"\njwks = \"{}\"";
        for (gateway, tls) in [
            ("listen = \"0.0.0.0:7878\"", "mode = \"self-signed\""),
            (auth, ""),
            ("listen = \"127.0.0.1:7878\"", ""),
            ("listen = \"127.5.6.7:7878\"", ""),
            ("listen = \"localhost:7878\"", ""),
            ("listen = \"[::1]:7878\"", ""),
            ("", ""),
        ] {
            assert_eq!(
                with_tls(gateway, tls).warnings(),
                Vec::<String>::new(),
                "{gateway} {tls}"
            );
        }
    }

    #[test]
    fn a_listener_key_is_a_secret_like_any_other() {
        let dir = tempfile::tempdir().unwrap();
        // Written in the config: said so, and refused under strict.
        let literal = with_tls(
            "",
            "mode = \"files\"\ncert = \"/tls.crt\"\nkey = \"not-pem\"",
        );
        let warnings = literal.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("[gateway.tls] key is a secret written in the config"),
            "{warnings:?}"
        );
        // A file others can read: said so.
        let key = dir.path().join("tls.key");
        std::fs::write(&key, "k").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
            let readable = with_tls(
                "[gateway.admin]\nenabled = true\n[gateway.admin.tls]\nmode = \"files\"\n\
                 cert = \"/tls.crt\"",
                &format!("mode = \"files\"\ncert = \"/tls.crt\"\nkey = {{ file = {key:?} }}"),
            );
            let warnings = readable.warnings();
            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert!(
                warnings[0].starts_with(&format!("[gateway.tls] key: {}", key.display())),
                "{warnings:?}"
            );
        }
        // A variable it is read from is MCPdef's own, which no stdio
        // upstream inherits.
        let env = with_tls(
            "",
            "mode = \"files\"\ncert = \"/tls.crt\"\nkey = { env = \"MCPDEF_TLS_KEY\" }",
        );
        assert_eq!(env.secret_vars(), ["MCPDEF_TLS_KEY"]);
        // Its files are inputs: a certificate renewed in place is a change
        // the watch sees. The admin listener's own too.
        let both = with_tls(
            "[gateway.admin]\nenabled = true\n[gateway.admin.tls]\nmode = \"files\"\n\
             cert = \"/admin.crt\"\nkey = { file = \"/admin.key\" }",
            "mode = \"files\"\ncert = \"/tls.crt\"\nkey = { file = \"/tls.key\" }",
        );
        assert_eq!(
            both.referenced_files(),
            ["/tls.crt", "/tls.key", "/admin.crt", "/admin.key"]
        );
    }

    #[test]
    fn a_secret_in_a_command_is_warned_about_and_not_repeated() {
        let token = format!("ghp_{}", "a1B2".repeat(9));
        let cfg = with_server(
            "",
            &format!(
                "transport = \"stdio\"\ncommand = [\"srv\", \"--token\", \"{token}\", \
                 \"--key\", \"not-a-shape\", \"--dir\", \"/data\"]"
            ),
        );
        let warnings = cfg.warnings();
        assert_eq!(
            warnings,
            [
                "server 'x': command[2] holds a secret, a github-token by its shape, so every \
              copy of the config holds it too, and any user of this machine can read a \
              process's arguments: give it to the server in [server.env] instead, read from a \
              file, a variable or a command"
            ]
        );
        assert!(!warnings[0].contains(&token));
    }
}
