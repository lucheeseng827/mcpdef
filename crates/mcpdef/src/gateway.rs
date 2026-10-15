// SPDX-License-Identifier: Apache-2.0
//! The Phase-1 gateway proxy loop: front one or more upstream MCP servers,
//! apply the static tool allowlist to `tools/call`, and append every governed
//! call to the tamper-evident audit ledger.
//!
//! The gateway *is* the server the client talks to. It answers `initialize`,
//! `ping`, `server/discover` and the lists itself, routes `tools/call`,
//! `resources/read`, `prompts/get` and `completion/complete` through the gates
//! to the server that has what each names, and refuses any other request:
//! nothing reaches an upstream that is not governed.

use crate::metrics::Metrics;
use crate::redact::redact_urls;
use anyhow::{anyhow, bail, Context, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use mcpdef_audit::{Attrs, Entry, Kind, Ledger, LedgerHandle};
use mcpdef_auth::Principal;
use mcpdef_core::wire::{self, SpecSetting, UpstreamSpec, WireMode, WireModel};
use mcpdef_core::{method, Decision, Id, Message};
use mcpdef_inspect::{Category, Finding, Scanner};
use mcpdef_pin::{tool_hash, PinCheck, PinStore};
use mcpdef_policy::{
    redact_result, Detected, Policy, PolicyContext, PolicyRules, Rbac, Target, Transformed,
    Unredacted,
};
use mcpdef_ratelimit::{RateDecision, RateLimiter};
use mcpdef_transport::{
    CallError, DownWatch, HandleOptions, ParamHeaders, RequestAuth, TlsWatch, Transport,
    UpstreamHandle, DEFAULT_MAX_INFLIGHT,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};

mod actions;
mod caller;
mod completion;
mod input;
mod lists;
mod mirror;
mod prompts;
mod reconfigure;
mod relist;
mod resources;
mod supervise;
pub use self::actions::Refused;
use self::caller::Who;
pub use self::caller::{issued, Caller, IssuedKey};
use self::lists::Listing;
use self::mirror::Mirroring;
pub use self::reconfigure::{Planned, RateScope, Reconfig, Reconfigured};
pub use self::supervise::{
    Connect, ConnectFuture, CredentialStatus, HealthState, LastError, LastOk, Offers, Startup,
    Supervised, TlsStatus, ToolCollision, UpstreamStatus,
};
use self::supervise::{Health, Tenure, UpstreamEvent};

/// The `agent` of a record the gateway writes about itself, such as an
/// upstream going down, rather than about a caller's request.
const GATEWAY_AGENT: &str = "mcpdef";

/// How many upstream connections have opened: the next one's `serial`.
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// `ttlMs` on each result the gateway answers itself that the 2026-07-28
/// revision requires caching hints on. Zero is immediately stale; why the
/// gateway promises nothing longer is on [`handle_discover`].
const CACHE_TTL_MS: u64 = 0;

/// `cacheScope` on the same results: never shared across callers.
const CACHE_SCOPE: &str = "private";

/// An initialized upstream connection, and what the gateway learned opening it.
///
/// When the upstream lists its tools again, a copy with the new list takes
/// this one's place, on the same connection and under the same `serial`.
struct Upstream {
    /// The connection, shared by every call to this upstream: it gives each
    /// request a private id and routes each reply back to its caller.
    handle: UpstreamHandle,
    /// Which connection this is: each one opened gets the next number.
    serial: u64,
    /// Which MCP era this upstream speaks, from its `spec` knob. A modern one
    /// has no handshake to have learned the protocol version from, so every
    /// request sent to it carries that itself — see [`Upstream::stamp`].
    era: WireModel,
    /// The revision string to declare to it.
    spec_version: &'static str,
    /// Tool definitions from the upstream's `tools/list`, at connect and again
    /// each time it says they changed: what `tools/list` aggregates and
    /// `tools/call` routes by.
    tools: Vec<serde_json::Value>,
    /// For an HTTPS upstream, what its connection shows of the server's
    /// certificate, kept up to date by the transport.
    tls: Option<TlsWatch>,
    /// The credentials its connection adds to each request, if it adds any
    /// (`[server.auth]`): what they are now, and when they expire.
    auth: Option<Arc<dyn RequestAuth>>,
    /// What `tools` asks of a call to each through `x-mcp-header`: judged
    /// with them, and replaced with them.
    mirroring: Arc<Mirroring>,
    /// Where its connection learns what each call mirrors into headers, if
    /// it sends any: a Streamable-HTTP upstream's.
    params: Option<ParamHeaders>,
    /// What it said it offers when this connection opened.
    offers: Offers,
}

/// The gateway: a policy, an audit ledger, and the set of upstreams, in config
/// order, which breaks ties between them.
///
/// A cheap handle: clones share one gateway, and any number of calls run
/// through it at once. Each call reads one governance snapshot from start to
/// finish. The little state a call changes (the rate-limit buckets, a stdio
/// client's name) sits under short locks, never held across an `.await`.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

/// What every clone of a [`Gateway`] shares.
struct Inner {
    /// Everything a call is judged against. Calls read it without a lock, and a
    /// change (connecting an upstream today, a reload later) replaces it whole
    /// for the calls that start after.
    governance: ArcSwap<Governance>,
    /// The audit ledger; every record takes its turn on the handle's lock, in order.
    ledger: LedgerHandle,
    /// The audit identity of a call with no principal: the one the gateway was
    /// built with, or the name a stdio client gives in `initialize`.
    agent: RwLock<String>,
    /// Token-bucket rate limiter for `tools/call`, if configured.
    rate_limiter: ArcSwapOption<Mutex<RateLimiter>>,
    /// The tool-def pin store, if pinning is enabled (`[gateway] pins`).
    pins: RwLock<Option<Pins>>,
    /// What MCPdef calls itself to a modern upstream. Built once, shared by
    /// reference: it goes on every request to such a server.
    client_info: Arc<serde_json::Value>,
    /// Dropped with the gateway, which tells every upstream's keeper to stop.
    shutdown: watch::Sender<()>,
    /// Held for the whole of a reconfiguration, so they run one at a time.
    reconfiguring: tokio::sync::Mutex<()>,
    /// Which server recently showed each resource URI and prompt name, so a
    /// read or a get goes back to it. Held for a lookup or an insert, never
    /// across an `.await`.
    routes: Mutex<lists::Routes>,
    /// A digest of what `tools/list` shows, changed whenever that does: what a
    /// client that can hear `notifications/tools/list_changed` is told by.
    listed: watch::Sender<u64>,
    /// What inspect found lately, oldest first: the last [`FINDINGS_KEPT`].
    findings: Mutex<VecDeque<InspectFinding>>,
}

/// One configured upstream: its health, and its connection once it has one.
#[derive(Clone)]
struct Slot {
    id: String,
    health: Arc<Health>,
    /// This place's claim, held by whatever keeps or watches its connection.
    tenure: Arc<Tenure>,
    /// Whether the gateway starts it again when it goes down.
    supervised: bool,
    /// Whether it is sent credentials (`[server.auth]`), and so shows how
    /// they fare.
    credentials: bool,
    /// The connection, once one has opened. After it goes down it stays until a
    /// restart replaces it, and its handle fails every call at once meanwhile.
    conn: Option<Arc<Upstream>>,
    /// Tools whose definition drifted from its pin: a suspected rug-pull. They
    /// are hidden from `tools/list`, and a call to one is denied and audited.
    drifted: Arc<HashSet<String>>,
    /// Tools whose description tripped the injection rule pack when the
    /// connection opened (tool poisoning). In enforce mode they are hidden and
    /// denied, the description-side analog of `drifted`.
    poisoned: Arc<HashSet<String>>,
}

/// The pin store and where it is saved.
struct Pins {
    store: PinStore,
    path: PathBuf,
    /// True if connect recorded new pins that should be written back.
    dirty: bool,
}

/// Everything a call is judged against, as one version.
///
/// Cheap to copy: the large parts are shared, so a change clones the rest and
/// swaps the whole in.
#[derive(Clone)]
struct Governance {
    policy: Arc<Policy>,
    /// Every upstream, in config order.
    upstreams: Vec<Slot>,
    /// Each tool, by the name `tools/list` gives it, and where a call to it
    /// goes: see [`Governance::reroute`].
    routes: HashMap<String, Route>,
    /// With `tool_namespace = "prefix"`, each server's prefix by its id. `None`
    /// lists each tool as its server names it.
    prefixes: Option<Arc<HashMap<String, String>>>,
    /// The names more than one server offers.
    collisions: Arc<Vec<ToolCollision>>,
    /// Inline injection / secret-exfil scanner (`[gateway.inspect]`); `None` = off.
    /// Descriptions are scanned at connect, tool-call results per call.
    inspect: Option<Arc<Scanner>>,
    /// Per-call upstream response timeout — a wedged upstream is failed (and
    /// audited) instead of hanging the gateway. `None` = wait indefinitely.
    upstream_timeout: Option<Duration>,
    /// Role-based access control layered over the allowlist for authenticated
    /// callers. `None` = no RBAC gate (the allowlist alone decides).
    rbac: Option<Arc<Rbac>>,
    /// Policy-as-code rules (per-agent / per-argument allow/deny) evaluated after
    /// the allowlist passes. Empty = engine off.
    policy_rules: Arc<PolicyRules>,
    /// Whether an `initialize`'s `clientInfo.name` may set the audit identity.
    /// True for a stdio gateway (one long-lived client — its name is a useful
    /// label). The HTTP listener sets this **false**: it serves many clients over
    /// one shared instance, so letting request content rename the shared identity
    /// would let one client's `initialize` mis-attribute another's audit records.
    capture_client_info: bool,
    /// Shared metrics registry for the OSS admin server; incremented at each
    /// audited decision. `None` = metrics off (nothing observing).
    metrics: Option<Arc<Metrics>>,
    /// The MCP revisions this gateway answers for, from `[gateway] wire`.
    /// `server/discover` reports exactly this, so it must never name a revision
    /// the listener will then refuse. Defaults to legacy-only, matching the
    /// config default.
    served: &'static [&'static str],
    /// The client keys this gateway issued (`[[key]]`).
    keys: Arc<Vec<IssuedKey>>,
}

/// Where a call to a listed tool name goes: an upstream, and the tool's name
/// there.
#[derive(Clone)]
struct Route {
    index: usize,
    tool: String,
}

impl Governance {
    /// `slot`'s tool prefix, when tools are listed with one.
    fn prefix<'a>(&'a self, slot: &'a Slot) -> Option<&'a str> {
        let prefixes = self.prefixes.as_deref()?;
        Some(
            prefixes
                .get(&slot.id)
                .map_or(slot.id.as_str(), String::as_str),
        )
    }

    /// Whether `slot` offers `tool`: its connection lists it, which the caller
    /// checks, and its allowlist takes it. A tool that drifts from its pin or
    /// trips the scanner is still offered, and so keeps its name: it is
    /// hidden and refused, never handed to another server.
    fn offers(&self, slot: &Slot, tool: &str) -> bool {
        self.policy.tool_is_exposed(&slot.id, tool)
    }

    /// Route each listed name to the first upstream, in config order, that
    /// offers it: the one `tools/list` shows. A name another upstream offers
    /// too is a collision. A name no upstream offers goes to the first whose
    /// connection lists it, so a call to it meets the gate that hides it.
    fn reroute(&mut self) {
        let mut routes = HashMap::new();
        let mut offered: Vec<(String, Vec<usize>)> = Vec::new();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (index, slot) in self.upstreams.iter().enumerate() {
            let Some(up) = &slot.conn else { continue };
            for tool in up.tool_names().filter(|tool| self.offers(slot, tool)) {
                let listed = listed_tool_name(self.prefix(slot), tool);
                match seen.get(&listed) {
                    Some(&at) => {
                        let servers = &mut offered[at].1;
                        if servers.last() != Some(&index) {
                            servers.push(index);
                        }
                    }
                    None => {
                        seen.insert(listed.clone(), offered.len());
                        let tool = tool.to_string();
                        routes.insert(listed.clone(), Route { index, tool });
                        offered.push((listed, vec![index]));
                    }
                }
            }
        }
        for (index, slot) in self.upstreams.iter().enumerate() {
            for tool in slot.conn.iter().flat_map(|up| up.tool_names()) {
                routes
                    .entry(listed_tool_name(self.prefix(slot), tool))
                    .or_insert_with(|| Route {
                        index,
                        tool: tool.to_string(),
                    });
            }
        }
        let collisions = offered
            .into_iter()
            .filter(|(_, servers)| servers.len() > 1)
            .map(|(tool, servers)| ToolCollision {
                tool,
                servers: servers
                    .iter()
                    .map(|&i| self.upstreams[i].id.clone())
                    .collect(),
            })
            .collect();
        self.collisions = Arc::new(collisions);
        self.routes = routes;
    }

    fn slot_mut(&mut self, id: &str) -> Option<&mut Slot> {
        self.upstreams.iter_mut().find(|slot| slot.id == id)
    }

    /// Where a call to a name nobody routes goes: the first upstream that has
    /// never opened, and so never listed its tools, whose allowlist names the
    /// tool. With prefixes, the name must carry that upstream's.
    fn claimant(&self, listed: &str) -> Option<Route> {
        self.upstreams.iter().enumerate().find_map(|(index, slot)| {
            if slot.conn.is_some() {
                return None;
            }
            let tool = match self.prefix(slot) {
                None => listed,
                Some(prefix) => listed
                    .strip_prefix(prefix)?
                    .strip_prefix(TOOL_PREFIX_SEPARATOR)?,
            };
            self.policy.lists_tool(&slot.id, tool).then(|| Route {
                index,
                tool: tool.to_string(),
            })
        })
    }
}

impl Slot {
    fn new(
        id: String,
        health: Arc<Health>,
        tenure: Arc<Tenure>,
        supervised: bool,
        credentials: bool,
    ) -> Self {
        Slot {
            id,
            health,
            tenure,
            supervised,
            credentials,
            conn: None,
            drifted: Arc::default(),
            poisoned: Arc::default(),
        }
    }

    fn state(&self) -> HealthState {
        if self.health.is_starting() {
            return HealthState::Starting;
        }
        match &self.conn {
            Some(up) if up.handle.down_reason().is_none() => {
                if up.handle.failures() > 0 {
                    HealthState::Degraded
                } else {
                    HealthState::Up
                }
            }
            _ => HealthState::Down,
        }
    }

    fn status(&self) -> UpstreamStatus {
        let conn = self.conn.as_ref();
        let tls = conn.and_then(|up| up.tls.as_ref());
        UpstreamStatus {
            id: self.id.clone(),
            health: self.state(),
            restarts: self.health.restarts(),
            last_error: self.health.last_error(),
            tls: tls.map(TlsStatus::of),
            credential: self.credentials.then(|| {
                let expires_at = conn.and_then(|up| up.auth.as_ref()?.expires_at());
                self.health.credential(expires_at)
            }),
            auth_failures: self.health.auth_failures(),
            tool_collisions: Vec::new(),
            offers: conn.map(|up| up.offers),
        }
    }

    /// Note that its connection `up` answered a call: if it sent
    /// credentials, the upstream took them.
    fn answered(&self, up: &Upstream) {
        if up.auth.is_some() {
            self.health.credential_taken();
        }
    }

    /// The decision for a call to this upstream that went down: `why` it did,
    /// or, with no connection, why it has none.
    fn down(&self, why: Option<&str>) -> Decision {
        let why = match why {
            Some(why) => redact_urls(why).into_owned(),
            None => self
                .health
                .last_error()
                .map(|e| e.message)
                .unwrap_or_else(|| "it has not started".into()),
        };
        let restarting = if self.supervised {
            "; MCPdef is restarting it — retry shortly"
        } else {
            ""
        };
        Decision::Deny {
            rule: "upstream-down".into(),
            reason: format!("upstream '{}' is down ({why}){restarting}", self.id),
        }
    }

    /// The decision for a call, to `what` (a tool, or a method), that this
    /// upstream did not answer in time, or could not take or answer at all.
    /// A refusal of MCPdef's credentials, or none to send, is recorded as
    /// theirs.
    fn failure(&self, error: &CallError, what: &str, timeout: Option<Duration>) -> Decision {
        match error {
            CallError::Timeout(_) => Decision::Deny {
                rule: "upstream-timeout".into(),
                reason: format!(
                    "upstream '{}' did not respond to '{what}' within {}ms",
                    self.id,
                    timeout.map(|d| d.as_millis()).unwrap_or(0)
                ),
            },
            CallError::Down(why) => self.down(Some(why)),
            CallError::Failed(why) => Decision::Deny {
                rule: "upstream-error".into(),
                reason: format!(
                    "upstream '{}' failed the call: {}",
                    self.id,
                    redact_urls(why)
                ),
            },
            // Fail closed: the call is not sent again without credentials the
            // upstream takes.
            CallError::Unauthorized(why) => {
                let why = redact_urls(why);
                self.health.credential_failed(why.to_string());
                Decision::Deny {
                    rule: "upstream-auth-failed".into(),
                    reason: format!("upstream '{}' refused MCPdef's credentials: {why}", self.id),
                }
            }
            // Fail closed: nothing is sent without them.
            CallError::NoCredentials(why) => {
                let why = redact_urls(why);
                // As the transport says it when an opening has none.
                self.health.credential_failed(format!("credentials: {why}"));
                Decision::Deny {
                    rule: "credentials-unavailable".into(),
                    reason: format!("no credentials for upstream '{}': {why}", self.id),
                }
            }
        }
    }
}

impl Upstream {
    fn tool_names(&self) -> impl Iterator<Item = &str> {
        self.tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
    }

    /// Fit a request's per-request `_meta` to the wire this upstream speaks.
    ///
    /// A modern upstream gets MCPdef's own version, identity and capabilities on
    /// every request, since it has no handshake to have learned them from. A
    /// legacy one gets none: its `initialize` handshake carried them, and a
    /// 2025-11-25 server has no rule for them. That includes the ones a
    /// 2026-07-28 client put on a request relayed here, which would otherwise
    /// claim a revision this upstream does not speak.
    fn stamp(&self, req: &mut Message, client: &serde_json::Value) {
        match self.era {
            WireModel::Modern => wire::stamp_request(req, self.spec_version, client),
            WireModel::Legacy => wire::strip_modern_meta(req),
        }
    }

    /// [`stamp`](Self::stamp) a request relayed from a client that can be
    /// asked for `offered` ([`wire::input_capabilities`]): a modern upstream
    /// is told it may ask for that, since what it asks comes back to the
    /// client ([`input`]).
    fn stamp_offering(
        &self,
        req: &mut Message,
        client: &serde_json::Value,
        offered: &serde_json::Value,
    ) {
        match self.era {
            WireModel::Modern => {
                wire::stamp_request_offering(req, self.spec_version, client, offered)
            }
            WireModel::Legacy => wire::strip_modern_meta(req),
        }
    }
}

impl Gateway {
    /// A gateway with no upstream yet, governing calls by `policy` and
    /// recording them in `ledger`. A call with no principal is recorded as
    /// `agent`, until a stdio client's `initialize` gives its own name.
    pub fn new(policy: Policy, ledger: Ledger, agent: impl Into<String>) -> Self {
        let governance = Governance {
            policy: Arc::new(policy),
            upstreams: Vec::new(),
            routes: HashMap::new(),
            prefixes: None,
            collisions: Arc::default(),
            inspect: None,
            upstream_timeout: None,
            rbac: None,
            policy_rules: Arc::default(),
            capture_client_info: true,
            metrics: None,
            served: WireMode::default().served(),
            keys: Arc::default(),
        };
        let listed = watch::channel(listed_digest(&governance)).0;
        Gateway {
            inner: Arc::new(Inner {
                governance: ArcSwap::from_pointee(governance),
                ledger: LedgerHandle::new(ledger),
                agent: RwLock::new(agent.into()),
                rate_limiter: ArcSwapOption::empty(),
                pins: RwLock::new(None),
                client_info: Arc::new(client_info()),
                shutdown: watch::channel(()).0,
                reconfiguring: tokio::sync::Mutex::new(()),
                routes: Mutex::default(),
                listed,
                findings: Mutex::default(),
            }),
        }
    }

    /// Change the governance for every call that starts after this, as one step.
    /// Two changes at once both land: each applies to the other's result.
    fn govern(&self, change: impl Fn(&mut Governance)) {
        self.inner.governance.rcu(|current| {
            let mut next = Governance::clone(current);
            change(&mut next);
            next
        });
        // Whether what `tools/list` shows moved: judged under the watch's lock
        // against the governance as it now stands, so two changes at once
        // cannot leave the digest of the older.
        self.inner.listed.send_if_modified(|digest| {
            let now = listed_digest(&self.inner.governance.load());
            let moved = now != *digest;
            *digest = now;
            moved
        });
    }

    /// A watch that changes each time what `tools/list` shows does: an
    /// upstream's tools changed, a reload changed an allowlist, a restarted
    /// upstream lists new tools. The stdio server tells its client by it.
    pub fn tool_list_changes(&self) -> watch::Receiver<u64> {
        self.inner.listed.subscribe()
    }

    /// List each tool as `<prefix>__<name>`, with `prefixes` giving each
    /// server's prefix by its id (its id when it has none there), or as its
    /// server names it (`None`, the default).
    pub fn with_tool_prefixes(self, prefixes: Option<HashMap<String, String>>) -> Self {
        let prefixes = prefixes.map(Arc::new);
        self.govern(|g| {
            g.prefixes = prefixes.clone();
            g.reroute();
        });
        self
    }

    /// What its operator should know about the tools this gateway lists: each
    /// name more than one server offers, and, with prefixes, each listed name
    /// longer than [`LISTED_NAME_WARN`]. Startup prints them, and under
    /// `strict` refuses to start with any.
    pub fn tool_warnings(&self) -> Vec<String> {
        let g = self.inner.governance.load();
        let mut lines: Vec<String> = g.collisions.iter().map(ToString::to_string).collect();
        if g.prefixes.is_some() {
            for slot in &g.upstreams {
                let Some(up) = &slot.conn else { continue };
                for tool in up.tool_names().filter(|tool| g.offers(slot, tool)) {
                    let listed = listed_tool_name(g.prefix(slot), tool);
                    if listed.chars().count() > LISTED_NAME_WARN {
                        lines.push(long_name(&slot.id, tool, &listed));
                    }
                }
            }
        }
        lines
    }

    /// Set which MCP revisions this gateway answers for.
    ///
    /// Only `server/discover` reads it today: the listener does the per-request
    /// era check itself, because that needs the HTTP headers. Keeping the list
    /// here too means the one method whose whole job is to answer "what do you
    /// speak" gives the same answer on stdio as over HTTP.
    pub fn with_wire(self, mode: WireMode) -> Self {
        self.govern(|g| g.served = mode.served());
        self
    }

    /// Attach a shared [`Metrics`] registry so every audited decision is counted
    /// for the admin server / `/metrics`. A no-op observability-wise when unset.
    pub fn with_metrics(self, metrics: Arc<Metrics>) -> Self {
        self.govern(|g| g.metrics = Some(Arc::clone(&metrics)));
        self
    }

    /// Mark this gateway as serving many clients over one shared instance (the
    /// HTTP listener), so an `initialize`'s self-asserted `clientInfo.name` will
    /// **not** set the shared audit identity — preventing one client from
    /// mis-attributing another's audit records on the unauthenticated path.
    pub fn shared_across_clients(self) -> Self {
        self.govern(|g| g.capture_client_info = false);
        self
    }

    /// Take the client keys `keys`, as `[[key]]` lists them.
    pub fn with_keys(self, keys: Vec<IssuedKey>) -> Self {
        self.set_keys(keys);
        self
    }

    /// Take `keys` from now on, in place of the keys taken before: a reload's.
    pub fn set_keys(&self, keys: Vec<IssuedKey>) {
        let keys = Arc::new(keys);
        self.govern(|g| g.keys = Arc::clone(&keys));
    }

    /// The caller a client key this gateway issued names, if `token` is
    /// one: `key:<name>` in its records, holding its roles. Found by the
    /// token's SHA-256, compared in constant time.
    pub fn issued_key(&self, token: &str) -> Option<Principal> {
        caller::issued(&self.inner.governance.load().keys, token)
    }

    /// Layer RBAC over the allowlist: authenticated callers must hold a role that
    /// grants `(server, tool)`. A no-op (gate off) when `rbac` is empty/`None`.
    pub fn with_rbac(self, rbac: Option<Rbac>) -> Self {
        let rbac = rbac.filter(|r| !r.is_empty()).map(Arc::new);
        self.govern(|g| g.rbac = rbac.clone());
        self
    }

    /// Layer the policy-as-code rule engine over the allowlist: after a `tools/call`
    /// passes the allowlist, the rules (per-agent / per-argument, first-match-wins)
    /// can deny it. A no-op when the rule set is empty.
    pub fn with_policy_rules(self, rules: PolicyRules) -> Self {
        let rules = Arc::new(rules);
        self.govern(|g| g.policy_rules = Arc::clone(&rules));
        self
    }

    /// Enable token-bucket rate limiting on `tools/call`. `per_tool` / `global`
    /// are `(refill_per_sec, burst)`; either may be `None`. A no-op (limiter stays
    /// off) when both are `None`.
    pub fn with_rate_limit(self, per_tool: Option<(f64, f64)>, global: Option<(f64, f64)>) -> Self {
        let limiter = RateLimiter::new(per_tool, global, Instant::now());
        self.inner
            .rate_limiter
            .store(limiter.map(|l| Arc::new(Mutex::new(l))));
        self
    }

    /// Fail a `tools/call` (and any forwarded request) whose upstream does not
    /// respond within `timeout`, instead of blocking the gateway.
    pub fn with_upstream_timeout(self, timeout: Option<Duration>) -> Self {
        self.govern(|g| g.upstream_timeout = timeout);
        self
    }

    /// Enable tool-def pinning: tools are checked against `store` at connect
    /// (trust-on-first-use records unseen tools; a changed definition is flagged
    /// as drift), and TOFU additions are written back to `path` by
    /// [`persist_pins`](Gateway::persist_pins).
    pub fn with_pins(self, store: PinStore, path: impl Into<PathBuf>) -> Self {
        *write(&self.inner.pins) = Some(Pins {
            store,
            path: path.into(),
            dirty: false,
        });
        self
    }

    /// Enable inline injection / secret-exfil scanning (`[gateway.inspect]`). Tool
    /// descriptions are scanned at connect and tool-call results per call; a finding
    /// hides/denies the tool or refuses the result in enforce mode (logs only in
    /// warn). A no-op when `scanner` is `None` (mode off).
    pub fn with_inspect(self, scanner: Option<Scanner>) -> Self {
        let scanner = scanner.map(Arc::new);
        self.govern(|g| g.inspect = scanner.clone());
        self
    }

    /// Persist any trust-on-first-use pin additions made during connect. A no-op
    /// when pinning is off or nothing changed.
    pub fn persist_pins(&mut self) -> Result<()> {
        self.write_pins()
    }

    fn write_pins(&self) -> Result<()> {
        if let Some(pins) = write(&self.inner.pins).as_mut().filter(|p| p.dirty) {
            pins.store.save(&pins.path)?;
            pins.dirty = false;
        }
        Ok(())
    }

    /// Number of tools flagged as drifted (rug-pull) across all upstreams.
    pub fn drift_count(&self) -> usize {
        let g = self.inner.governance.load();
        g.upstreams.iter().map(|slot| slot.drifted.len()).sum()
    }

    /// Connect an upstream: run the MCP lifecycle handshake (initialize →
    /// notifications/initialized), cache its `tools/list` for routing, and
    /// check each tool against the pin store (if pinning is enabled).
    /// Connect an upstream that speaks the legacy (2025-11-25) wire.
    ///
    /// The default, and every existing caller: an upstream's era is a fact about
    /// that server, so assuming the newer one would break configs on upgrade.
    pub async fn add_upstream(
        &mut self,
        id: impl Into<String>,
        transport: Box<dyn Transport>,
    ) -> Result<()> {
        self.add_upstream_speaking(id, transport, SpecSetting::default())
            .await
    }

    /// Connect an upstream, saying which revision it speaks (`[[server]] spec`).
    ///
    /// A legacy upstream gets the `initialize` handshake it expects. A modern one
    /// gets no handshake at all — there is none in that revision — just
    /// `server/discover` to confirm it really does speak what the config claims,
    /// then a `tools/list` carrying its own `_meta`.
    pub async fn add_upstream_speaking(
        &mut self,
        id: impl Into<String>,
        transport: Box<dyn Transport>,
        spec: SpecSetting,
    ) -> Result<()> {
        let options = UpstreamOptions {
            spec,
            ..UpstreamOptions::default()
        };
        self.add_upstream_with(id, transport, options).await
    }

    /// Connect an upstream with everything its `[[server]]` entry says about the
    /// connection.
    ///
    /// The opening (the handshake, or the era probe and `server/discover`) runs
    /// on `transport` directly. Only then does the transport pass to the
    /// [`UpstreamHandle`] that carries every call after it, and the upstream
    /// joins the governance, whole, for the calls that start after that.
    ///
    /// The gateway does not start it again if it goes down: it has only this
    /// transport. [`start_supervised`](Self::start_supervised) is for that.
    pub async fn add_upstream_with(
        &mut self,
        id: impl Into<String>,
        mut transport: Box<dyn Transport>,
        options: UpstreamOptions,
    ) -> Result<()> {
        let id = id.into();
        let client = Arc::clone(&self.inner.client_info);
        let budget = self.opening_budget(options.spec);
        let listed = open_within(&id, &mut *transport, options.spec, &client, &budget).await?;
        let opened = self.admit(&id, transport, listed, options).await;
        let watch = opened.upstream.handle.watch();
        let health = Arc::new(Health::default());
        let tenure = Tenure::new();
        self.govern(|g| {
            let mut slot = Slot::new(
                id.clone(),
                Arc::clone(&health),
                Arc::clone(&tenure),
                false,
                options.credentials,
            );
            opened.fill(&mut slot);
            g.upstreams.push(slot);
            g.reroute();
        });
        self.watch_tools(&id, opened);
        self.watch_unsupervised(id, health, &tenure, watch);
        Ok(())
    }

    /// How long an opening may take, from `upstream_timeout_ms` as it stands.
    fn opening_budget(&self, spec: SpecSetting) -> Budget {
        Budget::of(self.inner.governance.load().upstream_timeout, spec)
    }

    /// Judge a freshly opened upstream's tools against the pins and the
    /// injection rules, and hand its transport to the handle that carries every
    /// call from now on.
    async fn admit(
        &self,
        id: &str,
        transport: Box<dyn Transport>,
        listed: Listed,
        options: UpstreamOptions,
    ) -> Opened {
        let scanner = self.inner.governance.load().inspect.clone();
        self.admit_with(scanner.as_deref(), id, transport, listed, options)
            .await
    }

    /// [`admit`](Self::admit), scanning with `scanner` rather than the one in
    /// force: a reload judges what it opens by the configuration it applies.
    async fn admit_with(
        &self,
        scanner: Option<&Scanner>,
        id: &str,
        transport: Box<dyn Transport>,
        listed: Listed,
        options: UpstreamOptions,
    ) -> Opened {
        let Listed {
            spec,
            tools,
            changed,
            offers,
        } = listed;
        if options.tls_verify_disabled {
            // Whoever answered, its certificate was not checked: every
            // connection that says so is on the record.
            self.audit_upstream(id, UpstreamEvent::Unverified).await;
        }
        let drifted = self.pin_check(id, &tools);
        let poisoned = self.inspect_check(scanner, id, &tools, "connect").await;
        let (tls, auth) = (transport.tls(), transport.auth());
        // Before the handle takes the transport, and so before any call can
        // reach it.
        let params = transport.param_headers();
        let mirroring = Mirroring::judge(id, &tools, params.as_ref(), None);
        let (handle, notices) = UpstreamHandle::spawn_listening(
            id,
            transport,
            HandleOptions {
                max_inflight: options.max_inflight,
                trip_after: options.trip_after,
            },
        );
        Opened {
            upstream: Arc::new(Upstream {
                handle,
                serial: CONNECTIONS.fetch_add(1, Ordering::Relaxed),
                era: spec.era(),
                spec_version: spec.version(),
                tools,
                tls,
                auth,
                mirroring: Arc::new(mirroring),
                params,
                offers,
            }),
            drifted: Arc::new(drifted),
            poisoned: Arc::new(poisoned),
            notices,
            changed,
        }
    }

    /// Put a new connection in upstream `id`'s place, and route calls to it.
    /// Returns a watch on it, or `None` if the place is gone or is no longer
    /// held under `tenure`.
    fn install(&self, id: &str, tenure: &Arc<Tenure>, opened: Opened) -> Option<DownWatch> {
        let watch = opened.upstream.handle.watch();
        self.govern(|g| {
            if let Some(slot) = g.slot_mut(id).filter(|s| Arc::ptr_eq(&s.tenure, tenure)) {
                opened.fill(slot);
                g.reroute();
            }
        });
        let governance = self.inner.governance.load();
        let installed = governance.upstreams.iter().any(|slot| {
            slot.conn
                .as_ref()
                .is_some_and(|up| Arc::ptr_eq(up, &opened.upstream))
        });
        if installed {
            self.watch_tools(id, opened);
        }
        installed.then_some(watch)
    }

    /// What each upstream adds to `tools/list`, in config order: how many
    /// tools it offers, how many of them are listed, and the bytes those take
    /// up in the answer, which every agent that lists the tools reads into
    /// its context.
    pub fn tool_costs(&self) -> Vec<ToolCost> {
        let g = self.inner.governance.load();
        let mut costs: Vec<ToolCost> = g
            .upstreams
            .iter()
            .map(|slot| ToolCost {
                id: slot.id.clone(),
                offered: slot.conn.as_ref().map_or(0, |up| up.tools.len()),
                listed: 0,
                bytes: 0,
            })
            .collect();
        for (slot, entry) in entries(&g) {
            if let Some(cost) = costs.iter_mut().find(|cost| cost.id == slot.id) {
                cost.listed += 1;
                // As sent: compact, through the serializer every message
                // goes through.
                cost.bytes += entry.to_string().len();
            }
        }
        costs
    }

    /// What the connection of the upstream `id` offers, each tool with what
    /// became of it; `None` when no upstream has that id, and empty until its
    /// connection opens.
    pub fn server_tools(&self, id: &str) -> Option<Vec<ToolState>> {
        let g = self.inner.governance.load();
        let (index, slot) = g.upstreams.iter().enumerate().find(|(_, s)| s.id == id)?;
        let pinning = read(&self.inner.pins).is_some();
        let Some(up) = &slot.conn else {
            return Some(Vec::new());
        };
        let tools = up.tools.iter().filter_map(|t| {
            let name = t.get("name")?.as_str()?;
            let listed_as = listed_tool_name(g.prefix(slot), name);
            let drifted = slot.drifted.contains(name);
            // In the order `listed` hides them.
            let hidden = if !g.offers(slot, name) {
                Some("allowlist")
            } else if drifted {
                Some("drift")
            } else if slot.poisoned.contains(name) {
                Some("inspect")
            } else if up.mirroring.refused.contains_key(name) {
                Some("x-mcp-header")
            } else if g.routes.get(&listed_as).map(|r| r.index) != Some(index) {
                Some("collision")
            } else {
                None
            };
            Some(ToolState {
                name: name.to_string(),
                listed_as,
                hidden,
                pin: match (pinning, drifted) {
                    (false, _) => "off",
                    (true, true) => "drift",
                    (true, false) => "pinned",
                },
                hash: tool_hash(t),
                description: t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(str::to_string),
            })
        });
        Some(tools.collect())
    }

    /// What inspect found lately, newest first: the last [`FINDINGS_KEPT`].
    pub fn inspect_findings(&self) -> Vec<InspectFinding> {
        lock(&self.inner.findings).iter().rev().cloned().collect()
    }

    /// Keep `finding` for the console, letting the oldest go.
    fn found(&self, finding: InspectFinding) {
        let mut kept = lock(&self.inner.findings);
        if kept.len() == FINDINGS_KEPT {
            kept.pop_front();
        }
        kept.push_back(finding);
    }

    /// Keep what inspect made of the answer `resp` from `server` on
    /// `surface`, about `target`.
    fn note_inspected(
        &self,
        g: &Governance,
        inspected: &Inspected,
        resp: &Message,
        surface: &'static str,
        server: &str,
        target: &str,
    ) {
        let (finding, outcome) = match inspected {
            Inspected::Clean => return,
            Inspected::Warned(f) => (*f, "warned"),
            Inspected::Blocked(f, _) => (*f, "blocked"),
            Inspected::Redacted(rules) => {
                for rule in rules {
                    let secret = Finding {
                        category: Category::Secret,
                        rule_id: rule,
                    };
                    self.found(InspectFinding::new(
                        &secret,
                        surface,
                        server,
                        Some(target.to_string()),
                        "redacted",
                        None,
                    ));
                }
                return;
            }
        };
        let matched = match (g.inspect.as_deref(), &resp.result) {
            (Some(scanner), Some(result)) => matched_words(scanner, &result.to_string(), &finding),
            _ => None,
        };
        self.found(InspectFinding::new(
            &finding,
            surface,
            server,
            Some(target.to_string()),
            outcome,
            matched,
        ));
    }

    /// Each upstream's health, in config order.
    pub fn upstream_status(&self) -> Vec<UpstreamStatus> {
        let governance = self.inner.governance.load();
        governance
            .upstreams
            .iter()
            .map(|slot| {
                let mut status = slot.status();
                status.tool_collisions = governance
                    .collisions
                    .iter()
                    .filter(|c| c.servers.contains(&slot.id))
                    .cloned()
                    .collect();
                status
            })
            .collect()
    }

    /// Classify each tool against the pin store (no-op if pinning is off):
    /// trust-on-first-use records an unseen tool; a changed governed definition
    /// is flagged as drift (a suspected rug-pull), and its name returned so the
    /// tool is hidden + denied.
    fn pin_check(&self, server: &str, tools: &[serde_json::Value]) -> HashSet<String> {
        let mut pins = write(&self.inner.pins);
        let Some(pins) = pins.as_mut() else {
            return HashSet::new();
        };
        // Judge the whole list against the store as it was, then record.
        let mut to_record: Vec<(String, String)> = Vec::new();
        let mut drift = HashSet::new();
        for t in tools {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                let h = tool_hash(t);
                match pins.store.check(server, name, &h) {
                    PinCheck::Match => {}
                    PinCheck::New => to_record.push((name.to_string(), h)),
                    PinCheck::Drift => {
                        drift.insert(name.to_string());
                    }
                }
            }
        }
        if !to_record.is_empty() {
            for (name, h) in to_record {
                pins.store.record(server, &name, h);
            }
            pins.dirty = true;
        }
        drift
    }

    /// Scan each tool's definition against the injection rule pack (no-op if
    /// inspect is off): at connect, and when an upstream's tools change. In
    /// enforce mode a finding is audited under the method `during` names, the
    /// tool is marked `poisoned` (hidden + denied), the description-side analog
    /// of a rug-pull, and its name returned. Warn mode logs the finding only.
    async fn inspect_check(
        &self,
        scanner: Option<&Scanner>,
        server: &str,
        tools: &[serde_json::Value],
        during: &str,
    ) -> HashSet<String> {
        let governance = self.inner.governance.load_full();
        let Some(scanner) = scanner else {
            return HashSet::new();
        };
        let hits: Vec<(String, Finding, Option<String>)> = tools
            .iter()
            .filter_map(|t| {
                // Scan the whole serialized def (description, schema, annotations).
                let text = t.to_string();
                scanner.scan(&text).map(|f| {
                    let name = t
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let matched = matched_words(scanner, &text, &f);
                    (name, f, matched)
                })
            })
            .collect();
        let mut poisoned = HashSet::new();
        if hits.is_empty() {
            return poisoned;
        }
        let started = Instant::now();
        let who = Who::named(read(&self.inner.agent).clone());
        for (name, f, matched) in hits {
            self.found(InspectFinding::new(
                &f,
                "tool-description",
                server,
                Some(name.clone()),
                if scanner.blocks() {
                    "blocked"
                } else {
                    "warned"
                },
                matched,
            ));
            if scanner.blocks() {
                let dec = Decision::Deny {
                    rule: f.category.rule().to_string(),
                    reason: format!("tool '{name}' on '{server}': {}", f.reason("description")),
                };
                // Audited as a synthetic method, `connect` or `tools-changed`,
                // not `tools/list`: no client `tools/list` request occurred, and
                // mislabeling it would muddy audit correlation.
                self.audit(
                    &governance,
                    &who,
                    &dec,
                    Some(during),
                    Some(&name),
                    server,
                    started,
                )
                .await;
                poisoned.insert(name);
            } else {
                eprintln!(
                    "mcpdef: inspect (warn) — tool '{name}' on '{server}': {}",
                    f.reason("description")
                );
            }
        }
        poisoned
    }

    /// Handle one downstream message from an unauthenticated transport (stdio).
    pub async fn handle(&self, msg: Message) -> Result<Option<Message>> {
        self.handle_authed(msg, None).await
    }

    /// Handle one downstream message, carrying the authenticated [`Principal`] when
    /// the transport validated one: [`handle_from`](Self::handle_from) with a
    /// caller that bearer token alone names. The principal's subject is the
    /// audit identity, and its scopes/roles drive the RBAC gate. Returns the
    /// response to send back (`None` for notifications).
    ///
    /// Takes `&self`: any number of calls run at once, each judged against the
    /// governance as it stood when the call arrived.
    pub async fn handle_authed(
        &self,
        msg: Message,
        principal: Option<&Principal>,
    ) -> Result<Option<Message>> {
        let caller = Caller {
            principal: principal.cloned(),
            ..Caller::default()
        };
        self.handle_from(msg, &caller).await
    }

    /// Handle one downstream message from `caller`, as its transport
    /// established it. Its subject is the audit identity, the token's when it
    /// carried one and its client certificate's otherwise, and its roles drive
    /// the RBAC gate. A certificate behind a token is recorded as the `actor`,
    /// and the client's address as the `peer`. Returns the response to send
    /// back (`None` for notifications).
    ///
    /// Takes `&self`: any number of calls run at once, each judged against the
    /// governance as it stood when the call arrived.
    pub async fn handle_from(&self, msg: Message, caller: &Caller) -> Result<Option<Message>> {
        if msg.is_notification() || msg.is_response() {
            // Phase 1: lifecycle notifications are absorbed (the gateway already
            // initialized the upstreams); a stray client response is ignored.
            return Ok(None);
        }
        let Some(id) = msg.id.clone() else {
            return Ok(None);
        };
        let governance = self.inner.governance.load_full();
        let g = &*governance;
        // The audit identity for THIS request: an authenticated subject overrides
        // the (stdio) client identity captured at `initialize`. Computed per call
        // and threaded into `audit` — never stored on `self` — so one request's
        // identity can never bleed into the audit record of another running
        // alongside it.
        let who = Who::of(caller, || read(&self.inner.agent).clone());
        let method = msg.method().unwrap_or_default().to_string();
        // The era the request was sent in shapes the results the gateway writes
        // itself, never how a call is governed. It comes off the message by the
        // revision's own rule for a dual-era server, through the same
        // `WireModel::of` the listener's era check switches on, so the two
        // cannot disagree about a request that got this far. stdio has no such
        // check and still answers each request in its own era. A request that
        // names no era is answered as legacy, which is how the listener serves it.
        let era = WireModel::of(&msg).unwrap_or(WireModel::Legacy);

        match method.as_str() {
            method::INITIALIZE => Ok(Some(self.handle_initialize(g, id, &msg))),
            method::TOOLS_LIST => Ok(Some(handle_tools_list(g, id, era))),
            method::TOOLS_CALL => self
                .handle_tools_call(g, id, msg, &who, era)
                .await
                .map(Some),
            method::PING => Ok(Some(Message::result(id, serde_json::json!({})))),
            method::SERVER_DISCOVER => Ok(Some(handle_discover(g, id))),
            method::RESOURCES_LIST => Ok(Some(
                self.handle_list(g, id, &msg, era, Listing::Resources).await,
            )),
            method::RESOURCES_TEMPLATES_LIST => Ok(Some(
                self.handle_list(g, id, &msg, era, Listing::Templates).await,
            )),
            method::RESOURCES_READ => {
                Ok(Some(self.handle_resource_read(g, id, msg, &who, era).await))
            }
            method::PROMPTS_LIST => Ok(Some(
                self.handle_list(g, id, &msg, era, Listing::Prompts).await,
            )),
            method::PROMPTS_GET => Ok(Some(self.handle_prompt_get(g, id, msg, &who, era).await)),
            method::COMPLETION_COMPLETE => {
                Ok(Some(self.handle_completion(g, id, msg, &who, era).await))
            }
            // No server→client stream carries updates, so a subscription
            // could never be kept; the gateway does not advertise one.
            method::RESOURCES_SUBSCRIBE | method::RESOURCES_UNSUBSCRIBE => Ok(Some(
                self.refuse(g, id, &method, &who, SUBSCRIPTIONS_REFUSED)
                    .await,
            )),
            // Fail closed: what the gateway neither answers nor routes goes
            // nowhere. Before, it went to the first server, ungoverned.
            _ => Ok(Some(self.refuse(g, id, &method, &who, NOT_SERVED).await)),
        }
    }

    /// Answer `initialize` with what the gateway serves.
    fn handle_initialize(&self, g: &Governance, id: Id, msg: &Message) -> Message {
        // Capture the client's self-asserted identity for the audit trail, if it
        // sent one — but only on a single-client (stdio) gateway. On the shared
        // HTTP listener this is disabled so one client can't rename the identity
        // used to audit another's calls (see `shared_across_clients`).
        if g.capture_client_info {
            if let Some(name) = msg
                .params
                .as_ref()
                .and_then(|p| p.get("clientInfo"))
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
            {
                *write(&self.inner.agent) = format!("agent:{name}");
            }
        }
        // The gateway is the server the client talks to.
        Message::result(
            id,
            serde_json::json!({
                "protocolVersion": wire::SPEC_2025_11_25,
                "capabilities": capabilities(g),
                "serverInfo": { "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") }
            }),
        )
    }
}

/// What the gateway offers a client: tools always, resources or prompts when
/// some server's allowlist exposes any, and completions when there is a
/// prompt or a resource template to complete. It offers no `subscribe`, and
/// no `listChanged` of its own: the stdio server adds `tools.listChanged` to
/// the `initialize` it answers, being the one transport that can send the
/// notification (see [`serve_stdio_on`](crate::serve_stdio_on)).
fn capabilities(g: &Governance) -> serde_json::Value {
    let mut capabilities = serde_json::json!({ "tools": {} });
    if g.policy.exposes_resources() {
        capabilities["resources"] = serde_json::json!({});
    }
    if g.policy.exposes_prompts() {
        capabilities["prompts"] = serde_json::json!({});
    }
    if g.policy.exposes_prompts() || g.policy.exposes_templates() {
        capabilities["completions"] = serde_json::json!({});
    }
    capabilities
}

/// `server/discover` — how a modern client learns what this gateway speaks.
///
/// The 2026-07-28 revision requires every server to implement it, and on
/// stdio it is also how a dual-era client probes which era it is talking to:
/// a real result means modern, anything else means fall back to
/// `initialize`. So it is answered on both transports, from the same list.
///
/// `ttlMs: 0`: the revision requires caching hints on this result, and zero
/// meets that without promising a lifetime, because a result with it should
/// be considered immediately stale. A lifetime is what a gateway cannot
/// promise. Its tool surface moves underneath it — a pin drifts, a
/// description trips the injection scanner, an upstream goes away — and
/// any longer TTL would have clients acting on a surface that is no longer
/// offered.
///
/// `cacheScope: "private"`, because what is offered is governance state and
/// filtering it per caller is planned. `"public"` would then let a shared
/// cache hand one caller's view to another. `"private"` is never wrong about
/// privacy, and at `ttlMs: 0` there are no fresh hits for a shared cache to
/// lose.
///
/// Unlike `tools/list`, the hints go on whoever asks. The method has no
/// legacy form, so this is a `DiscoverResult` either way, already marked
/// `resultType: "complete"`, and that is what the requirement attaches to.
fn handle_discover(g: &Governance, id: Id) -> Message {
    let mut meta = serde_json::Map::new();
    meta.insert(
        wire::meta_key::SERVER_INFO.to_string(),
        serde_json::json!({ "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") }),
    );
    Message::result(
        id,
        serde_json::json!({
            "resultType": "complete",
            "supportedVersions": g.served,
            "capabilities": capabilities(g),
            "_meta": meta,
            "instructions": "Tool calls through this gateway are governed: an \
                allow-list, an argument policy, a tool-definition pin and a rate limit \
                apply, and every call is recorded in a tamper-evident ledger. A denied \
                call comes back as a tool error naming the rule that matched, so it can \
                be corrected and retried rather than treated as a transport failure.",
            "ttlMs": CACHE_TTL_MS,
            "cacheScope": CACHE_SCOPE,
        }),
    )
}

/// The tools `tools/list` shows, in order: each with its server and the name
/// it is listed by.
///
/// It hides any the allowlist denies, that drifted from their pin, whose
/// description tripped the scanner, or whose `x-mcp-header` annotations no
/// client may honour (none of them is ever offered to the client). An
/// upstream that is down keeps its tools listed while it restarts; a call to
/// one fails at once, saying so.
fn listed(g: &Governance) -> Vec<(&Slot, &serde_json::Value, String)> {
    let mut out = Vec::new();
    let mut shown = HashSet::new();
    for (index, slot) in g.upstreams.iter().enumerate() {
        let Some(up) = &slot.conn else { continue };
        for t in &up.tools {
            let Some(name) = t.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            if !g.offers(slot, name)
                || slot.drifted.contains(name)
                || slot.poisoned.contains(name)
                || up.mirroring.refused.contains_key(name)
            {
                continue;
            }
            // Each name once, from the server a call to it goes to.
            let listed = listed_tool_name(g.prefix(slot), name);
            if g.routes.get(&listed).map(|r| r.index) != Some(index)
                || !shown.insert(listed.clone())
            {
                continue;
            }
            out.push((slot, t, listed));
        }
    }
    out
}

/// A digest of what `tools/list` shows: each tool's server, the name it is
/// listed by and its definition, in order. It changes when any of them does.
fn listed_digest(g: &Governance) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut digest = std::collections::hash_map::DefaultHasher::new();
    for (slot, tool, name) in listed(g) {
        slot.id.hash(&mut digest);
        name.hash(&mut digest);
        // As text, through the serializer the gateway already has: one for a
        // writer of its own would be a second copy of it in the binary.
        tool.to_string().hash(&mut digest);
    }
    digest.finish()
}

/// Each tool `tools/list` shows, with its server, as the answer carries it:
/// by the name it is listed by, and naming its server in `_meta`.
fn entries(g: &Governance) -> Vec<(&Slot, serde_json::Value)> {
    listed(g)
        .into_iter()
        .map(|(slot, tool, listed)| {
            // Each names its server. Only the copy listed does: the pin
            // keeps hashing what the upstream sent.
            let mut entry = tool.clone();
            if g.prefixes.is_some() {
                entry["name"] = serde_json::Value::from(listed);
            }
            lists::attribute(&mut entry, &slot.id);
            (slot, entry)
        })
        .collect()
}

/// Answer `tools/list`: every tool the gateway shows, each naming its server.
fn handle_tools_list(g: &Governance, id: Id, era: WireModel) -> Message {
    let out: Vec<serde_json::Value> = entries(g).into_iter().map(|(_, entry)| entry).collect();
    // A modern client gets what its revision requires of a complete list
    // result: a `resultType`, and the caching hints `server/discover` carries,
    // for the same reasons. A legacy one gets exactly what it always has,
    // because 2025-11-25 defines none of the three.
    let result = match era {
        WireModel::Modern => serde_json::json!({
            "resultType": "complete",
            "tools": out,
            "ttlMs": CACHE_TTL_MS,
            "cacheScope": CACHE_SCOPE,
        }),
        WireModel::Legacy => serde_json::json!({ "tools": out }),
    };
    Message::result(id, result)
}

impl Gateway {
    async fn handle_tools_call(
        &self,
        g: &Governance,
        id: Id,
        msg: Message,
        who: &Who<'_>,
        era: WireModel,
    ) -> Result<Message> {
        let started = Instant::now();
        let requested = msg.tool_name().unwrap_or_default().to_string();

        let route = g.routes.get(&requested).cloned();
        let Some(Route { index: idx, tool }) = route.or_else(|| g.claimant(&requested)) else {
            let dec = Decision::Deny {
                rule: "unknown-tool".into(),
                reason: format!("no governed server exposes tool '{requested}'"),
            };
            self.audit(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&requested),
                "(unrouted)",
                started,
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        };
        // From here on the tool is the server's, as the pins, the policy and
        // the audit know it; the listed name is only how the client asked.
        let slot = &g.upstreams[idx];
        let server_id = slot.id.clone();

        let decision = g.policy.decide_tool(&server_id, &tool);
        if !decision.is_allow() {
            self.audit(
                g,
                who,
                &decision,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&decision)),
            ));
        }

        // Argument transforms (mutate, then validate): every `transform` rule
        // that matches, in config order, each over the arguments as the rules
        // before it left them. The admission rules below judge what they made,
        // and it is what the upstream gets. The tool's name is not theirs to
        // change. One that cannot apply denies the call under its own name.
        let mut args = if g.policy_rules.is_empty() {
            serde_json::Value::Null
        } else {
            msg.params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        };
        let transformed = if g.policy_rules.transforms() {
            g.policy_rules
                .transform(&who.agent, &server_id, &tool, &mut args)
        } else {
            Transformed::default()
        };
        for (rule, why) in &transformed.skipped {
            eprintln!(
                "mcpdef: transform rule '{rule}' skipped for '{tool}' on '{server_id}': {why}"
            );
        }
        // Each record of the call from here names the rules that fired, never
        // what they changed.
        let attrs = || Attrs {
            transforms: transformed.fired.clone(),
            ..Attrs::default()
        };
        if let Some(dec) = &transformed.refused {
            self.audit_with(
                g,
                who,
                dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(dec)),
            ));
        }

        // Policy-as-code gate: the rule engine (per-agent / per-argument,
        // first-match-wins) can deny a call the allowlist permitted — e.g. block a
        // destructive tool when an argument names a production target. Evaluated
        // over the caller, server, tool, and the tool-call arguments as the
        // transforms left them. No-op when no rules are configured.
        if !g.policy_rules.is_empty() {
            let pdec = g.policy_rules.evaluate(&PolicyContext {
                agent: &who.agent,
                server: server_id.as_str(),
                target: Target::Tool(tool.as_str()),
                args: &args,
            });
            if !pdec.is_allow() {
                self.audit_with(
                    g,
                    who,
                    &pdec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                    attrs(),
                )
                .await;
                return Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef denied: {}", deny_reason(&pdec)),
                ));
            }
        }

        // RBAC gate (authenticated callers only): the subject must hold a role
        // that grants (server, tool). Layered over the allowlist.
        let grants = g
            .rbac
            .as_ref()
            .and_then(|rbac| Some((rbac, who.grants(rbac)?)));
        let rbac_denied = match grants {
            Some((rbac, grants)) => match rbac.decide(grants.into_iter(), &server_id, &tool) {
                Decision::Allow => None,
                deny => Some(deny),
            },
            None => None,
        };
        if let Some(dec) = rbac_denied {
            self.audit_with(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Rug-pull gate: a tool whose definition drifted from its pin is denied
        // even if the allowlist permits it — the server changed it post-approval.
        if slot.drifted.contains(&tool) {
            let dec = Decision::Deny {
                rule: "rug-pull".into(),
                reason: format!(
                    "tool '{tool}' on '{server_id}' changed since it was pinned (possible rug-pull); re-approve with `mcpdef pin`"
                ),
            };
            self.audit_with(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Injection gate: a tool whose description tripped the rule pack at connect
        // (tool poisoning) is denied even if the allowlist permits it — the
        // description-side analog of the rug-pull gate.
        if slot.poisoned.contains(&tool) {
            let dec = Decision::Deny {
                rule: "injection".into(),
                reason: format!(
                    "tool '{tool}' on '{server_id}' has an injection-flagged description; refused"
                ),
            };
            self.audit_with(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // `x-mcp-header` gate: a tool whose annotations break the revision's
        // rules is not served. A call to it could only go out with headers
        // its server did not ask for, or without ones it did.
        if let Some(dec) = slot
            .conn
            .as_ref()
            .and_then(|up| up.mirroring.refusal(&server_id, &tool))
        {
            self.audit_with(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Availability gate (AFTER authorization): cap the rate of calls that
        // would actually dispatch upstream. Placed here — not before the allowlist /
        // RBAC / rug-pull gates — so a flood of *denied* calls can't drain the
        // per-tool/global buckets and starve authorized callers. (The gates above
        // are cheap in-memory checks; the expensive upstream dispatch is still
        // rate-bounded.) Over-limit is a `rate-limited` deny + audit — the stdio
        // analog of a `429`. The buckets' lock is held for the check alone.
        let limited = self.inner.rate_limiter.load().as_ref().and_then(|rl| {
            match lock(rl).check(&server_id, &tool, Instant::now()) {
                RateDecision::Limited(scope) => Some(scope),
                RateDecision::Allow => None,
            }
        });
        if let Some(scope) = limited {
            let dec = Decision::Deny {
                rule: "rate-limited".into(),
                reason: format!(
                    "{} rate limit exceeded for '{tool}' — retry shortly",
                    scope.as_str()
                ),
            };
            self.audit_with(
                g,
                who,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
                attrs(),
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Allowed: forward to the owning upstream, bounded by the per-call timeout.
        // One that is down fails the call at once. A retry's `inputResponses`
        // and `requestState` go with the rest of the params.
        let offered = wire::input_capabilities(&msg);
        let outcome = match &slot.conn {
            Some(up) => {
                let mut params = msg.params.clone();
                if let Some(params) = params.as_mut().and_then(|p| p.as_object_mut()) {
                    if requested != tool {
                        params.insert("name".into(), serde_json::Value::from(tool.as_str()));
                    }
                    if transformed.changed {
                        // The result pass judges the call by them too.
                        let sent = if g.policy_rules.transforms_results() {
                            args.clone()
                        } else {
                            std::mem::take(&mut args)
                        };
                        params.insert("arguments".into(), sent);
                    }
                }
                let mut req = Message::request(id.clone(), method::TOOLS_CALL, params);
                up.stamp_offering(&mut req, &self.inner.client_info, &offered);
                let timeout = g.upstream_timeout;
                up.handle
                    .call(req, timeout)
                    .await
                    .inspect(|_| slot.answered(up))
                    .map_err(|error| slot.failure(&error, &tool, timeout))
            }
            // It never opened, so there is nothing to send the call to.
            None => Err(slot.down(None)),
        };
        let mut resp = match outcome {
            Ok(resp) => resp,
            Err(dec) => {
                self.audit_with(
                    g,
                    who,
                    &dec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                    attrs(),
                )
                .await;
                return Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef error: {}", deny_reason(&dec)),
                ));
            }
        };

        // Only a final result is edited: an interim one carries what the
        // server needs back. An edit of its structure keeps to the tool's
        // `outputSchema`, looked up only when something may edit it.
        let complete = !resp.result.as_ref().is_some_and(wire::input_required);
        let edits = complete
            && (g.policy_rules.transforms_results()
                || g.inspect.as_deref().is_some_and(Scanner::redacts));
        let schema = slot
            .conn
            .as_deref()
            .filter(|_| edits)
            .and_then(|up| {
                up.tools.iter().find(|t| {
                    t.get("name").and_then(serde_json::Value::as_str) == Some(tool.as_str())
                })
            })
            .and_then(|t| t.get("outputSchema"));

        // Result transforms, before inspect: every `transform` rule with
        // result edits that matches the call, as the upstream got it, in
        // config order. One that cannot apply denies the result under its
        // own name.
        let mut fired = transformed.fired.clone();
        if complete && g.policy_rules.transforms_results() {
            if let Some(result) = resp.result.as_mut() {
                let ctx = PolicyContext {
                    agent: &who.agent,
                    server: server_id.as_str(),
                    target: Target::Tool(tool.as_str()),
                    args: &args,
                };
                let done = g.policy_rules.transform_result(&ctx, result, schema);
                for (rule, why) in &done.skipped {
                    eprintln!(
                        "mcpdef: transform rule '{rule}' skipped for the result of '{tool}' \
                         on '{server_id}': {why}"
                    );
                }
                for rule in done.fired {
                    if !fired.contains(&rule) {
                        fired.push(rule);
                    }
                }
                if let Some(dec) = done.refused {
                    let attrs = Attrs {
                        transforms: fired,
                        ..Attrs::default()
                    };
                    self.audit_with(
                        g,
                        who,
                        &dec,
                        Some(method::TOOLS_CALL),
                        Some(&tool),
                        &server_id,
                        started,
                        attrs,
                    )
                    .await;
                    return Ok(Message::tool_error_result(
                        id,
                        format!("MCPdef denied: {}", deny_reason(&dec)),
                    ));
                }
            }
        }
        // Each record from here names the rules that fired on the arguments,
        // then those that fired on the result.
        let attrs = || Attrs {
            transforms: fired.clone(),
            ..Attrs::default()
        };

        // Inspect the RESULT for injected instructions / exfiltrated secrets
        // before it flows back to the model. Enforce refuses it (a tool
        // error, audited as the finding's rule); redact rewrites its secrets
        // in place and refuses the rest; warn logs and passes it through.
        let mut redacted = false;
        let inspected = inspect_result(g, &mut resp, schema, complete);
        self.note_inspected(g, &inspected, &resp, "tool-result", &server_id, &tool);
        match inspected {
            Inspected::Clean => {}
            Inspected::Warned(f) => eprintln!(
                "mcpdef: inspect (warn) — result of '{tool}' on '{server_id}': {}",
                f.reason("result")
            ),
            Inspected::Redacted(rules) => {
                eprintln!(
                    "mcpdef: inspect (redact) — result of '{tool}' on '{server_id}': redacted \
                     what {} found",
                    rules.join(", ")
                );
                redacted = true;
            }
            Inspected::Blocked(f, why) => {
                let dec = Decision::Deny {
                    rule: f.category.rule().to_string(),
                    reason: format!(
                        "tool '{tool}' on '{server_id}': {}",
                        blocked(&f, why.as_deref(), "result")
                    ),
                };
                self.audit_with(
                    g,
                    who,
                    &dec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                    attrs(),
                )
                .await;
                return Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef blocked: {}", deny_reason(&dec)),
                ));
            }
        }
        // Not the answer yet: the server needs something from the client, who
        // asks again with it.
        match input::interim(&resp, era, &offered) {
            input::Interim::Final => {}
            input::Interim::Relay => {
                self.audit_with(
                    g,
                    who,
                    &decision,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                    input::relayed(attrs()),
                )
                .await;
                return Ok(resp);
            }
            input::Interim::Refuse(why) => {
                let dec = Decision::Deny {
                    rule: input::INPUT_REQUIRED.into(),
                    reason: format!("tool '{tool}' on '{server_id}' {why}"),
                };
                self.audit_with(
                    g,
                    who,
                    &dec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                    attrs(),
                )
                .await;
                return Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef denied: {}", deny_reason(&dec)),
                ));
            }
        }
        // A link to a resource is read from the server that gave it.
        self.remember_links(g, &server_id, &resp);
        let attrs = Attrs {
            rule: redacted.then(|| SECRET_REDACTED.to_string()),
            ..attrs()
        };
        self.audit_with(
            g,
            who,
            &decision,
            Some(method::TOOLS_CALL),
            Some(&tool),
            &server_id,
            started,
            attrs,
        )
        .await;
        Ok(resp)
    }

    /// The gates a `resources/read`, a `prompts/get` or a
    /// `completion/complete` meets after its server's allowlist, in the order
    /// `tools/call` meets them: the policy rules, RBAC for an authenticated
    /// caller, then the rate limit, which comes after authorization so a flood
    /// of denied requests drains no bucket. The first to deny says why.
    #[allow(clippy::too_many_arguments)]
    fn gate(
        &self,
        g: &Governance,
        who: &Who<'_>,
        server: &str,
        target: Target<'_>,
        args: &serde_json::Value,
        bucket: Bucket,
    ) -> Option<Decision> {
        if !g.policy_rules.is_empty() {
            let dec = g.policy_rules.evaluate(&PolicyContext {
                agent: &who.agent,
                server,
                target,
                args,
            });
            if !dec.is_allow() {
                return Some(dec);
            }
        }
        let grants = g
            .rbac
            .as_ref()
            .and_then(|rbac| Some((rbac, who.grants(rbac)?)));
        if let Some((rbac, grants)) = grants {
            let subjects = grants.into_iter();
            let dec = match target {
                Target::Tool(tool) => rbac.decide(subjects, server, tool),
                Target::Resource(uri) => rbac.decide_resource(subjects, server, uri),
                Target::Prompt(name) => rbac.decide_prompt(subjects, server, name),
                Target::Template(template) => rbac.decide_template(subjects, server, template),
            };
            if !dec.is_allow() {
                return Some(dec);
            }
        }
        let limited = self.inner.rate_limiter.load().as_ref().and_then(|rl| {
            let mut rl = lock(rl);
            let now = Instant::now();
            let decision = match bucket {
                Bucket::Reads => rl.check_read(server, now),
                Bucket::Prompts => rl.check_prompt(server, now),
                Bucket::Completions => rl.check_completion(server, now),
            };
            match decision {
                RateDecision::Limited(scope) => Some(scope),
                RateDecision::Allow => None,
            }
        });
        limited.map(|scope| Decision::Deny {
            rule: "rate-limited".into(),
            reason: format!(
                "{} rate limit exceeded for '{server}' — retry shortly",
                scope.as_str()
            ),
        })
    }

    /// Refuse a request for a method MCPdef does not serve, with `-32601`, and
    /// audit it under `method-not-found`: a client probing for what the
    /// gateway lets through leaves a record. Nothing reaches an upstream.
    async fn refuse(
        &self,
        g: &Governance,
        id: Id,
        method: &str,
        who: &Who<'_>,
        why: &str,
    ) -> Message {
        let started = Instant::now();
        let method = clip(method, METHOD_KEPT);
        let dec = Decision::Deny {
            rule: "method-not-found".into(),
            reason: format!("method '{method}' {why}"),
        };
        self.audit(g, who, &dec, Some(method), None, "(unrouted)", started)
            .await;
        Message::error(
            id,
            wire::error_code::METHOD_NOT_FOUND,
            format!("MCPdef denied: {}", deny_reason(&dec)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        method: Option<&str>,
        tool: Option<&str>,
        server: &str,
        started: Instant,
    ) {
        self.audit_with(
            g,
            who,
            decision,
            method,
            tool,
            server,
            started,
            Attrs::default(),
        )
        .await;
    }

    /// [`audit`](Self::audit), with the record's optional members, such as the
    /// URI a `resources/read` named.
    #[allow(clippy::too_many_arguments)]
    async fn audit_with(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        method: Option<&str>,
        tool: Option<&str>,
        server: &str,
        started: Instant,
        attrs: Attrs,
    ) {
        let latency_ms = started.elapsed().as_millis() as u64;
        // Only the governed `tools/call` hot path counts toward mcpdef_tools_calls_total —
        // the pin/rug-pull `connect`-time inspection, reads, prompt gets, completions and
        // refused methods are audited too, but labeling them as tool calls would inflate
        // a counter clients read as exactly that.
        if let (Some(metrics), Some(method::TOOLS_CALL)) = (&g.metrics, method) {
            let (decision_label, rule) = match decision {
                Decision::Allow => ("allow", ""),
                Decision::Deny { rule, .. } => ("deny", rule.as_str()),
            };
            // An "unknown-tool" deny's tool name is caller-controlled and never revisited
            // (the audit ledger keeps it in full; `Metrics` keeps every distinct label
            // tuple forever) — collapse it to a fixed label so a flood of made-up tool
            // names can't grow the Prometheus series set without bound.
            let tool_label = if rule == "unknown-tool" {
                "(unknown)"
            } else {
                tool.unwrap_or("-")
            };
            metrics.record_call(server, tool_label, decision_label, rule, latency_ms);
        }
        let mut attrs = attrs;
        if attrs.actor.is_none() {
            attrs.actor = who.actor.clone();
        }
        if attrs.peer.is_none() {
            attrs.peer = who.peer.clone();
        }
        let entry = Entry {
            agent: who.agent.clone(),
            server: server.to_string(),
            method: method.map(str::to_string),
            tool: tool.map(str::to_string),
            decision: decision.clone(),
            latency_ms,
            attrs,
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// Record an upstream going down, coming back, or connected without its
    /// certificate checked, as a record of its own (`kind = "upstream"`): the
    /// event is the `method`. A downed upstream's rule is `upstream-down`, and
    /// an unchecked connection's is `tls-verify-disabled`, on an allowed
    /// record. Why it went down is logged, not recorded: an error message can
    /// carry what the ledger must not, such as a URL's credentials.
    async fn audit_upstream(&self, server: &str, event: UpstreamEvent) {
        let (method, decision, rule) = match event {
            UpstreamEvent::Down => (
                "down",
                Decision::Deny {
                    rule: "upstream-down".into(),
                    reason: String::new(),
                },
                None,
            ),
            UpstreamEvent::Up => ("up", Decision::Allow, None),
            UpstreamEvent::Unverified => (
                "connect",
                Decision::Allow,
                Some("tls-verify-disabled".to_string()),
            ),
        };
        let entry = Entry {
            agent: GATEWAY_AGENT.to_string(),
            server: server.to_string(),
            method: Some(method.to_string()),
            tool: None,
            decision,
            latency_ms: 0,
            attrs: Attrs {
                kind: Kind::Upstream,
                rule,
                ..Attrs::default()
            },
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// Record a reload: applied when `refused` is `None`, or refused under that
    /// rule. `trigger` names what asked for it; `from` and `to` are the digests
    /// of the configuration in effect before it and of the one it read.
    pub(crate) async fn audit_reload(
        &self,
        trigger: &str,
        peer: Option<&str>,
        refused: Option<&str>,
        from: String,
        to: String,
        took: Duration,
    ) {
        let decision = match refused {
            None => Decision::Allow,
            Some(rule) => Decision::Deny {
                rule: rule.to_string(),
                reason: String::new(),
            },
        };
        let entry = Entry {
            agent: GATEWAY_AGENT.to_string(),
            server: "(config)".to_string(),
            method: Some("reload".to_string()),
            tool: None,
            decision,
            latency_ms: u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
            attrs: Attrs {
                kind: Kind::Reload,
                actor: Some(trigger.to_string()),
                peer: peer.map(str::to_string),
                config_from: Some(from),
                config_to: Some(to),
                ..Attrs::default()
            },
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// Record an action taken through the admin API: `action` on `target`
    /// (an upstream, or `(config)` or `(console)` when it acts on no one
    /// upstream), and on `tool` when it acts on one, by `actor` calling from
    /// `peer`; done when `refused` is `None`, or refused under that rule.
    pub async fn audit_admin(
        &self,
        actor: &str,
        peer: &str,
        action: &str,
        target: &str,
        tool: Option<&str>,
        refused: Option<&str>,
    ) {
        let decision = match refused {
            None => Decision::Allow,
            Some(rule) => Decision::Deny {
                rule: rule.to_string(),
                reason: String::new(),
            },
        };
        let entry = Entry {
            agent: GATEWAY_AGENT.to_string(),
            server: target.to_string(),
            method: Some(action.to_string()),
            tool: tool.map(str::to_string),
            decision,
            latency_ms: 0,
            attrs: Attrs {
                kind: Kind::Admin,
                actor: Some(actor.to_string()),
                peer: Some(peer.to_string()),
                ..Attrs::default()
            },
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// Record a request to the admin API made with the break-glass token,
    /// before it is served: `asked` is its method and path. Every one is
    /// recorded, whatever it asks, so that the token's use cannot go unseen.
    pub async fn audit_break_glass(&self, peer: &str, asked: &str) {
        let entry = Entry {
            agent: GATEWAY_AGENT.to_string(),
            server: "(console)".to_string(),
            method: Some("break-glass".to_string()),
            tool: None,
            decision: Decision::Allow,
            latency_ms: 0,
            attrs: Attrs {
                kind: Kind::Admin,
                uri: Some(asked.to_string()),
                actor: Some(crate::admin::guard::BREAK_GLASS.to_string()),
                peer: Some(peer.to_string()),
                ..Attrs::default()
            },
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// The audit head hash after the last write (for diagnostics).
    pub fn audit_head(&self) -> String {
        self.inner.ledger.head()
    }

    /// How many records the ledger holds and the head they end in, read
    /// together.
    pub fn audit_written(&self) -> (u64, String) {
        self.inner.ledger.written()
    }

    /// What wakes a reader of the ledger's file each time records are
    /// appended.
    pub fn audit_appends(&self) -> mcpdef_audit::Appends {
        self.inner.ledger.appends()
    }

    /// Number of configured upstreams, up or not.
    pub fn upstream_count(&self) -> usize {
        self.inner.governance.load().upstreams.len()
    }
}

/// What joins a prefix to a tool's name: `<prefix>__<name>`.
pub const TOOL_PREFIX_SEPARATOR: &str = "__";
/// Listed names longer than this are warned about: some clients cut or
/// refuse a long tool name once they add a prefix of their own.
pub const LISTED_NAME_WARN: usize = 50;

/// The name `tools/list` gives `tool` of a server whose prefix is `prefix`,
/// `None` when tools are listed as their servers name them.
pub(crate) fn listed_tool_name(prefix: Option<&str>, tool: &str) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}{TOOL_PREFIX_SEPARATOR}{tool}"),
        None => tool.to_string(),
    }
}

/// The warning for a listed name longer than [`LISTED_NAME_WARN`].
pub(crate) fn long_name(server: &str, tool: &str, listed: &str) -> String {
    format!(
        "tool '{tool}' of '{server}' is listed as '{listed}', {} characters: some clients cut \
         or refuse a name longer than {LISTED_NAME_WARN} once they add a prefix of their own",
        listed.chars().count()
    )
}

/// Which of a server's rate-limit buckets a request spends: a tool call
/// spends its tool's, so it never comes through [`Gateway::gate`].
#[derive(Clone, Copy)]
enum Bucket {
    Reads,
    Prompts,
    Completions,
}

/// Why a method the gateway does not serve is refused.
const NOT_SERVED: &str = "is not one MCPdef serves: it answers or routes initialize, ping, \
     server/discover, tools/*, resources/*, prompts/* and completion/complete";
/// Why a resource subscription is refused.
const SUBSCRIPTIONS_REFUSED: &str =
    "is not served: MCPdef relays no resource subscriptions, having no stream to send updates on";
/// How much of a refused method's name the ledger keeps.
const METHOD_KEPT: usize = 128;
/// How much of a refused URI or a template the ledger keeps.
const URI_KEPT: usize = 2048;

/// At most `max` bytes of `text`, cut at a character boundary: what the ledger
/// keeps of a string a caller chose.
fn clip(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The rule an allowed record names when inspect redacted secrets in what it
/// passed on.
const SECRET_REDACTED: &str = "secret-redacted";

/// What inspect makes of a result.
enum Inspected {
    /// Nothing found, or inspect is off.
    Clean,
    /// Found in warn mode: passed on, and logged.
    Warned(Finding),
    /// Its secrets redacted in place, in redact mode: the rules that found
    /// them.
    Redacted(Vec<&'static str>),
    /// Refused: the finding, and, for a secret redact mode could not redact,
    /// why.
    Blocked(Finding, Option<String>),
}

/// Inspect `resp`'s result for injected instructions and exfiltrated
/// secrets: a no-op when inspect is off.
///
/// In redact mode, the secrets in a `redactable` result, a final one rather
/// than an interim one whose state the upstream needs back, are redacted in
/// place, each string on its own, keeping to `schema`, the tool's
/// `outputSchema`. Anything else found, or a secret it cannot redact, blocks,
/// as it does in enforce mode. Otherwise the serialized result is scanned, so
/// a finding anywhere in the structure, not just `content[].text`, counts.
fn inspect_result(
    g: &Governance,
    resp: &mut Message,
    schema: Option<&serde_json::Value>,
    redactable: bool,
) -> Inspected {
    let Some(scanner) = g.inspect.as_deref() else {
        return Inspected::Clean;
    };
    let Some(result) = resp.result.as_mut() else {
        return Inspected::Clean;
    };
    if scanner.redacts() && redactable {
        let detect = |text: &str| -> Vec<Detected> {
            scanner
                .find_all(text)
                .into_iter()
                .map(|m| Detected {
                    secret: m.category == Category::Secret,
                    range: m.range,
                    rule: m.rule_id,
                })
                .collect()
        };
        return match redact_result(result, schema, &detect) {
            Ok(rules) if rules.is_empty() => Inspected::Clean,
            Ok(rules) => Inspected::Redacted(rules),
            Err(Unredacted::Unsafe(rule)) => Inspected::Blocked(
                Finding {
                    category: Category::Injection,
                    rule_id: rule,
                },
                None,
            ),
            Err(Unredacted::Kept(rule, why)) => Inspected::Blocked(
                Finding {
                    category: Category::Secret,
                    rule_id: rule,
                },
                Some(why),
            ),
        };
    }
    match scanner.scan(&result.to_string()) {
        None => Inspected::Clean,
        Some(f) if scanner.blocks() => Inspected::Blocked(f, None),
        Some(f) => Inspected::Warned(f),
    }
}

/// What a refusal of `surface` says of `finding`, and, when redaction was
/// tried, why it could not be made.
fn blocked(finding: &Finding, unredacted: Option<&str>, surface: &str) -> String {
    match unredacted {
        None => finding.reason(surface),
        Some(why) => format!(
            "{}, which MCPdef could not redact: {why}",
            finding.reason(surface)
        ),
    }
}

/// The gateway's locks guard plain data, written in short steps with no
/// `.await` inside. A panic mid-step leaves nothing half-done that the next
/// call could trip on, so a poisoned lock is used as it stands.
fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn deny_reason(d: &Decision) -> String {
    match d {
        Decision::Deny { reason, .. } => reason.clone(),
        Decision::Allow => "allowed".to_string(),
    }
}

/// How to connect one upstream, beyond its transport: the rest of what its
/// `[[server]]` entry says.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamOptions {
    /// Which MCP revision it speaks (`spec`).
    pub spec: SpecSetting,
    /// The most calls that may wait on it at once (`max_inflight`).
    pub max_inflight: usize,
    /// Declare it down once this many calls in a row fail or time out, so
    /// calls to it fail at once until it is started again. `None` never does.
    pub trip_after: Option<u32>,
    /// Its certificate is not checked (`insecure_skip_verify`), so each
    /// connection opened to it is audited as such.
    pub tls_verify_disabled: bool,
    /// It is sent credentials (`[server.auth]`), so how they fare is shown.
    pub credentials: bool,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        UpstreamOptions {
            spec: SpecSetting::default(),
            max_inflight: DEFAULT_MAX_INFLIGHT,
            trip_after: None,
            tls_verify_disabled: false,
            credentials: false,
        }
    }
}

/// The most inspect findings the gateway keeps for the console.
pub const FINDINGS_KEPT: usize = 256;
/// The most characters of an injection's matched words a finding keeps.
const MATCHED_KEPT: usize = 120;

/// What inspect found, as the console shows it: where, by which rule, and
/// what became of it. Never the text it was found in, so never a secret;
/// for an injection, the words that matched, which are the attack.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct InspectFinding {
    pub ts_unix_ms: u64,
    /// `injection` or `secret`.
    pub category: &'static str,
    /// The pack's rule that matched, such as `ignore-previous-instructions`
    /// or `aws-access-key`; `custom-injection` and `custom-secret` for the
    /// operator's own.
    pub rule: &'static str,
    /// Where it was found: `tool-description` (when a connection opens or
    /// its tools change), `tool-result`, `resource`, `prompt` or
    /// `completion`.
    pub surface: &'static str,
    pub server: String,
    /// The tool, the prompt or the completion's target, or the resource's
    /// URI, its secrets masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `blocked`, `redacted` or `warned`.
    pub outcome: &'static str,
    /// For an injection, the words that matched, as the text had them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
}

impl InspectFinding {
    fn new(
        finding: &Finding,
        surface: &'static str,
        server: &str,
        target: Option<String>,
        outcome: &'static str,
        matched: Option<String>,
    ) -> InspectFinding {
        InspectFinding {
            ts_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            category: match finding.category {
                Category::Injection => "injection",
                Category::Secret => "secret",
            },
            rule: finding.rule_id,
            surface,
            server: server.to_string(),
            target: target.map(|t| crate::redact::redact_url(&t).into_owned()),
            outcome,
            matched,
        }
    }
}

/// The words of `text` that `finding`, an injection's, matched; `None` for a
/// secret's, which a finding never keeps.
fn matched_words(scanner: &Scanner, text: &str, finding: &Finding) -> Option<String> {
    if finding.category != Category::Injection {
        return None;
    }
    let found = scanner
        .find_all(text)
        .into_iter()
        .find(|m| m.category == Category::Injection && m.rule_id == finding.rule_id)?;
    Some(text[found.range].chars().take(MATCHED_KEPT).collect())
}

/// A tool an upstream's connection offers, and what became of it, as
/// [`Gateway::server_tools`] reports it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ToolState {
    /// As its server names it.
    pub name: String,
    /// As `tools/list` names it: with its server's prefix under
    /// `tool_namespace = "prefix"`.
    pub listed_as: String,
    /// Why `tools/list` does not show it, `None` when it does: `allowlist`
    /// (the server's allowlist or profile), `drift` (its definition changed
    /// since it was pinned), `inspect` (its definition tripped the scanner),
    /// `x-mcp-header` (annotations no client may honour) or `collision`
    /// (another server's tool by that name is listed).
    pub hidden: Option<&'static str>,
    /// `off` with no pin store, else `pinned` or `drift`.
    pub pin: &'static str,
    /// The hex SHA-256 of the definition its connection offers now, over the
    /// fields a pin governs: approving its drift names it, so that only the
    /// definition looked at is taken as its pin.
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What one upstream adds to `tools/list`, as [`Gateway::tool_costs`]
/// reports it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ToolCost {
    #[serde(skip)]
    pub id: String,
    /// How many tools its connection lists: none until it opens.
    pub offered: usize,
    /// How many of them `tools/list` shows: what the allowlist, the active
    /// profile, the pins and the scanner leave of them, less a name listed
    /// from another server.
    pub listed: usize,
    /// The bytes those take up in a `tools/list` answer: each entry as it is
    /// sent, compact, with the name it is listed by and its `_meta`. The
    /// commas between entries are not counted.
    pub bytes: usize,
}

impl ToolCost {
    /// `bytes` ÷ 4, rounded: the estimate of the tokens they cost. The real
    /// count depends on the model.
    pub fn tokens(bytes: usize) -> usize {
        (bytes + 2) / 4
    }
}

/// A freshly opened upstream: its connection, and what its tools were judged.
struct Opened {
    upstream: Arc<Upstream>,
    drifted: Arc<HashSet<String>>,
    poisoned: Arc<HashSet<String>>,
    /// Its notifications, from the moment its handle took the transport over.
    /// Once it is in place, [`Gateway::watch_tools`] listens on them.
    notices: broadcast::Receiver<Message>,
    /// It said its tools changed while its opening listed them.
    changed: bool,
}

/// What an opening learned of an upstream.
struct Listed {
    /// The revision it speaks.
    spec: UpstreamSpec,
    /// Every page of its tools.
    tools: Vec<serde_json::Value>,
    /// It said its tools changed while they were being listed. The opening
    /// reads that word but does not act on it, and the list may be older than
    /// the word, or its pages may straddle the change: once the upstream is in
    /// place, its tools are listed again.
    changed: bool,
    /// What it said it offers.
    offers: Offers,
}

impl Opened {
    /// Put it in `slot`. Its opening was answered, so if it sends
    /// credentials, the upstream took them.
    fn fill(&self, slot: &mut Slot) {
        slot.answered(&self.upstream);
        slot.conn = Some(Arc::clone(&self.upstream));
        slot.drifted = Arc::clone(&self.drifted);
        slot.poisoned = Arc::clone(&self.poisoned);
    }
}

/// How long an opening may take, and what to add when saying it took longer.
struct Budget {
    limit: Option<Duration>,
    note: String,
}

impl Budget {
    /// The budget under `upstream_timeout`.
    ///
    /// `spec = "auto"` opens with an era probe first, and that probe carries
    /// its own bound because *silence* is one of its answers. Its budget goes
    /// on top of the operator's rather than out of it: the two measure
    /// different things, and carving the probe out of a per-call timeout
    /// would let that knob decide which era a slow server is judged to speak.
    /// A timeout shorter than the probe used to fire before the fallback
    /// could run at all, failing startup on an upstream that opens fine
    /// pinned — and naming a number the operator set for something else.
    fn of(upstream_timeout: Option<Duration>, spec: SpecSetting) -> Self {
        match (upstream_timeout, spec.pinned()) {
            (Some(t), None) => Budget {
                limit: Some(t + PROBE_TIMEOUT),
                note: format!(
                    " (`upstream_timeout_ms` plus {}ms for the `spec = \"auto\"` probe)",
                    PROBE_TIMEOUT.as_millis()
                ),
            },
            (limit, _) => Budget {
                limit,
                note: String::new(),
            },
        }
    }
}

/// Run an upstream's opening within its budget.
async fn open_within(
    id: &str,
    transport: &mut dyn Transport,
    spec: SpecSetting,
    client: &serde_json::Value,
    budget: &Budget,
) -> Result<Listed> {
    // Bound the opening by the per-call upstream timeout, so a wedged upstream
    // fails its start instead of hanging it.
    let open = open_upstream(id, transport, spec, client);
    match budget.limit {
        Some(limit) => tokio::time::timeout(limit, open).await.map_err(|_| {
            anyhow!(
                "upstream '{id}' did not finish opening within {}ms{}",
                limit.as_millis(),
                budget.note
            )
        })?,
        None => open.await,
    }
}

/// What MCPdef calls itself to a modern upstream.
///
/// One definition, because it goes out on every request a modern server sees and
/// `list_tools_speaking` must send the same thing the gateway does.
fn client_info() -> serde_json::Value {
    serde_json::json!({ "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") })
}

/// List an upstream's tools in whatever era its `spec` names.
///
/// What `mcpdef pin` and `mcpdef diff-tools` need: the same opening the gateway
/// performs, without building a gateway around it. They used to call
/// [`handshake_list`] directly, which sends `initialize` — a method a 2026-07-28
/// server does not have, so pinning or diffing a modern upstream failed.
pub async fn list_tools_speaking(
    id: &str,
    transport: &mut dyn Transport,
    spec: SpecSetting,
) -> Result<Vec<serde_json::Value>> {
    open_upstream(id, transport, spec, &client_info())
        .await
        .map(|listed| listed.tools)
}

/// A JSON-RPC error in reply to an opening request means the upstream did not
/// open — so say so, with what it said.
///
/// Without this a rejected handshake was *silent*: `handshake_list` discarded the
/// `initialize` reply, `tools/list` then failed too, and `unwrap_or_default`
/// turned that into an empty tool list. The gateway came up advertising nothing
/// from that server and told nobody why, which surfaces much later as "the tool
/// isn't there" rather than as the wire mismatch it is.
fn reject_error(reply: &Message, what: &str) -> Result<()> {
    let Some(err) = reply.error.as_ref() else {
        return Ok(());
    };
    let code = err
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let message = err
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("no message");
    Err(anyhow!("this upstream rejected {what} ({code}: {message})"))
}

/// How long to wait for a `server/discover` reply before concluding an upstream
/// has never heard of it.
///
/// A deliberate constant rather than a knob. It answers a different question from
/// `upstream_timeout` — "how long until I conclude this server is legacy", not
/// "how long may a tool call take" — and that one defaults to waiting forever,
/// which would hang `spec = "auto"` against a server that silently ignores an
/// unknown method instead of answering `-32601` as JSON-RPC requires.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What an `spec = "auto"` probe learned — and what it consumed learning it.
///
/// The probe sends `initialize`, so on the legacy path it is already *holding
/// the handshake reply*. That reply travels forward rather than being dropped:
/// a second `initialize` on an already-initialized session is an error in
/// 2025-11-25 implementations, so re-running the handshake would break the very
/// upstreams the probe just identified.
enum Opening {
    /// A 2025-11-25 (or older) server, with the `initialize` reply it gave.
    Legacy { hello: Message },
    /// A server that refused `initialize` the way only a modern one does.
    /// *Which* modern revision is `server/discover`'s answer, read by the
    /// caller.
    Modern,
}

/// Work out which era an upstream speaks, for `spec = "auto"`.
///
/// Ask for `initialize`. It is the only message that is legal-first in every
/// era, and its *absence* is what defines the modern one (SEP-2575 removed it),
/// so asking for it is the most direct form of the question — and the one probe
/// that sends nothing a 2024-11-05 server would consider out of order.
///
/// On HTTP that matters twice over. `HttpClient`'s first send also selects the
/// binding — Streamable HTTP versus the deprecated 2024-11-05 SSE bridge — and
/// that negotiation is one-shot. Probing with `initialize` means the era probe
/// **is** the opening request rather than a second negotiation competing for it:
///
/// | Upstream | Answer | Binding | Era |
/// |---|---|---|---|
/// | 2026-07-28 Streamable | `404` + a modern JSON-RPC error | Streamable | modern |
/// | 2025-11-25 Streamable | `200` + a result | Streamable | legacy, handshake done |
/// | 2024-11-05 SSE bridge | `404`, no MCP body | bridge | legacy, handshake done |
///
/// The era is a property of the server, not of a request, so it is resolved once
/// here and kept for the life of the connection.
async fn probe_opening(id: &str, transport: &mut dyn Transport) -> Result<Opening> {
    // Its own id, never `Id::Num(0)`. The probe gives up after `PROBE_TIMEOUT`
    // but the upstream may answer later, and a late reply read as the answer to
    // a different opening request fails startup with a diagnosis about the wrong
    // one. `recv_response` skips ids it did not ask for, so a distinct id makes
    // a late reply harmless.
    let probe_id = Id::Str("mcpdef-era-probe".into());
    // One bound over the whole exchange, send included. On stdio a send is a
    // pipe write and cannot block for long, but on HTTP it is where an
    // upstream's silence actually lands: the first send is what POSTs, and on a
    // bodyless 400/404/405 it then waits for the SSE `endpoint` event. Neither
    // carries a deadline of its own and the client sets no request timeout, so
    // bounding only the wait for a reply would promise a five-second probe and
    // deliver a hang — against exactly the upstream the bound exists for.
    let exchange = async {
        transport
            .send(Message::request(
                probe_id.clone(),
                method::INITIALIZE,
                Some(initialize_params()),
            ))
            .await?;
        recv_response(transport, &probe_id).await
    };

    match tokio::time::timeout(PROBE_TIMEOUT, exchange).await {
        Ok(Ok(reply)) => {
            if wire::initialize_proves_modern(&reply) {
                Ok(Opening::Modern)
            } else {
                Ok(Opening::Legacy { hello: reply })
            }
        }
        Ok(Err(e)) => Err(e).with_context(|| format!("probing upstream '{id}' with `initialize`")),
        // Silence is **not** an answer here, and that is the change from probing
        // with `server/discover`: every era implements `initialize`, so a server
        // that says nothing is not telling us it is old, it is failing to
        // answer. Guessing an era on that basis only moves the failure later,
        // onto a request whose error would name the wrong thing.
        Err(_) => bail!(
            "upstream '{id}' did not answer `initialize` within {}s, so which MCP revision it \
             speaks could not be determined. Pin its `spec` if it is simply slow to start.",
            PROBE_TIMEOUT.as_secs()
        ),
    }
}

/// Open an upstream in the era its `spec` names, and return its tool list.
///
/// Legacy is the handshake MCPdef has always run. Modern has no handshake to
/// run — the revision removed it — so this instead asks `server/discover`, which
/// every modern server must implement, and checks that the revision the config
/// claims is one the server actually lists. That check is the difference between
/// a clear failure at startup and a confusing one on the first tool call: a
/// legacy server answers `server/discover` with a method-not-found, and saying
/// so by name beats letting `tools/list` fail for reasons an operator has to
/// reverse-engineer.
async fn open_upstream(
    id: &str,
    transport: &mut dyn Transport,
    setting: SpecSetting,
    client: &serde_json::Value,
) -> Result<Listed> {
    // A pin opens the way the config says. `auto` asks first — and the asking is
    // an `initialize`, so on the legacy path the probe hands back the handshake
    // reply it already has rather than leaving a second one to be sent.
    let (spec, hello) = match setting.pinned() {
        Some(spec) => (spec, None),
        None => match probe_opening(id, transport).await? {
            Opening::Legacy { hello } => (UpstreamSpec::V20251125, Some(hello)),
            Opening::Modern => (UpstreamSpec::V20260728, None),
        },
    };

    if spec.era() == WireModel::Legacy {
        let hello = match hello {
            Some(hello) => hello,
            None => initialize(transport).await?,
        };
        let offers = Offers::of(hello.result.as_ref());
        let (tools, changed) = finish_handshake(transport, hello).await?;
        return Ok(Listed {
            spec,
            tools,
            changed,
            offers,
        });
    }

    let mut discover = Message::request(Id::Num(0), method::SERVER_DISCOVER, None);
    wire::stamp_request(&mut discover, spec.version(), client);
    transport.send(discover).await?;
    let reply = recv_response(transport, &Id::Num(0)).await?;

    reject_error(&reply, "`server/discover`").map_err(|e| {
        anyhow!(
            "{e}, so it is probably not a {} server — set its `spec` to the revision it does \
             speak",
            spec.version()
        )
    })?;

    let supported: Vec<&str> = reply
        .result
        .as_ref()
        .and_then(|r| r.get("supportedVersions"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    if !supported.is_empty() && !supported.contains(&spec.version()) {
        return Err(if setting.pinned().is_some() {
            anyhow!(
                "this upstream is configured as {} but reports speaking {supported:?}. Set its \
                 `spec` to one of those.",
                spec.version()
            )
        } else {
            // Probed, and the two answers contradict each other: it refused
            // `initialize`, which only a {SPEC_2026_07_28}-or-later server does,
            // yet its own `server/discover` does not list that revision. Saying
            // so beats picking one of them and being wrong quietly.
            anyhow!(
                "upstream '{id}' refused `initialize`, so it is a {} server or newer, but its \
                 `server/discover` lists only {supported:?}. Those cannot both be true — pin \
                 its `spec` to the revision it really speaks.",
                wire::SPEC_2026_07_28
            )
        });
    }

    let offers = Offers::of(reply.result.as_ref());
    let (tools, changed) = list_tools(transport, |list| {
        wire::stamp_request(list, spec.version(), client);
    })
    .await?;
    Ok(Listed {
        spec,
        tools,
        changed,
        offers,
    })
}

/// Run the MCP lifecycle handshake (initialize → notifications/initialized) and
/// return every page of the upstream's `tools/list`: how an upstream whose
/// `spec` pins the 2025-11-25 revision opens. `mcpdef pin` and
/// `mcpdef diff-tools` reach it through [`list_tools_speaking`].
pub async fn handshake_list(transport: &mut dyn Transport) -> Result<Vec<serde_json::Value>> {
    handshake(transport).await.map(|(tools, _)| tools)
}

/// [`handshake_list`], and whether the upstream said its tools changed while
/// they were listed.
async fn handshake(transport: &mut dyn Transport) -> Result<(Vec<serde_json::Value>, bool)> {
    let hello = initialize(transport).await?;
    finish_handshake(transport, hello).await
}

/// Send `initialize`, and return the reply, which [`finish_handshake`] takes.
async fn initialize(transport: &mut dyn Transport) -> Result<Message> {
    transport
        .send(Message::request(
            Id::Num(0),
            method::INITIALIZE,
            Some(initialize_params()),
        ))
        .await?;
    let hello = recv_response(transport, &Id::Num(0)).await?;
    reject_error(&hello, "the `initialize` handshake").map_err(|e| {
        anyhow!(
            "{e}. A server with no `initialize` is speaking {} or later; set its `spec` to that.",
            wire::SPEC_2026_07_28
        )
    })?;
    Ok(hello)
}

/// The `initialize` params, in one place.
///
/// [`handshake_list`] and the `spec = "auto"` probe must send the *same*
/// `initialize`, because on the probed path the one is standing in for the
/// other. Two literals would drift.
fn initialize_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": wire::SPEC_2025_11_25,
        "capabilities": {},
        "clientInfo": { "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// Finish the legacy handshake from an `initialize` reply already in hand.
///
/// Split out of [`handshake_list`] for `spec = "auto"`, whose probe *is* the
/// `initialize` — so the reply exists before the era is known. Sending a second
/// `initialize` instead would hit an already-initialized session, which
/// 2025-11-25 implementations reject; that is the whole reason [`Opening`]
/// carries the reply forward rather than dropping it.
async fn finish_handshake(
    transport: &mut dyn Transport,
    hello: Message,
) -> Result<(Vec<serde_json::Value>, bool)> {
    reject_error(&hello, "the `initialize` handshake")?;

    transport
        .send(Message::notification(method::INITIALIZED, None))
        .await?;

    list_tools(transport, |_| {}).await
}

/// Every page of an opening upstream's `tools/list`, each request stamped by
/// `stamp`, and whether the upstream said its tools changed while they were
/// listed.
///
/// Pages are followed as the resource and prompt lists follow them, up to
/// [`MAX_PAGES`](lists::MAX_PAGES) pages and
/// [`MAX_ENTRIES`](lists::MAX_ENTRIES) tools. A page refused or never answered
/// fails the opening, as the first always has. The pages are asked as ids `1`
/// onwards, below the ids the upstream's handle numbers its calls from.
async fn list_tools(
    transport: &mut dyn Transport,
    stamp: impl Fn(&mut Message),
) -> Result<(Vec<serde_json::Value>, bool)> {
    let mut tools = Vec::new();
    let mut changed = false;
    let mut cursor = None;
    for page in (1..).take(lists::MAX_PAGES) {
        let id = Id::Num(page);
        let params = cursor
            .take()
            .map(|cursor| serde_json::json!({ "cursor": cursor }));
        let mut list = Message::request(id.clone(), method::TOOLS_LIST, params);
        stamp(&mut list);
        transport.send(list).await?;
        let reply = recv_noting(transport, &id, &mut changed).await?;
        reject_error(&reply, "`tools/list`")?;
        let result = reply.result.unwrap_or_default();
        if let Some(page) = result.get("tools").and_then(|t| t.as_array()) {
            let room = lists::MAX_ENTRIES - tools.len();
            tools.extend(page.iter().take(room).cloned());
        }
        match lists::next_cursor(&result) {
            Some(next) if tools.len() < lists::MAX_ENTRIES => cursor = Some(next),
            _ => break,
        }
    }
    Ok((tools, changed))
}

/// Read from a transport until the response matching `id` arrives (skipping
/// notifications / unrelated frames). Errors if the peer closes first.
///
/// Only the opening uses this: it sends one request at a time, so any other
/// response here is stale and dropped. Calls after the opening go through the
/// [`UpstreamHandle`], which routes each reply to its caller by id.
async fn recv_response(t: &mut dyn Transport, id: &Id) -> Result<Message> {
    let mut changed = false;
    recv_noting(t, id, &mut changed).await
}

/// [`recv_response`], setting `changed` when a notification it skips says the
/// upstream's tools changed.
async fn recv_noting(t: &mut dyn Transport, id: &Id, changed: &mut bool) -> Result<Message> {
    loop {
        match t.recv().await? {
            Some(m) => {
                if m.is_response() && m.id.as_ref() == Some(id) {
                    return Ok(m);
                }
                // Anything else is skipped, but word that the tools changed
                // is noted.
                *changed |= m.method() == Some(method::TOOLS_LIST_CHANGED);
            }
            None => return Err(anyhow!("upstream closed before responding to {id:?}")),
        }
    }
}
