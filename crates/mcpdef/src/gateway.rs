// SPDX-License-Identifier: Apache-2.0
//! The Phase-1 gateway proxy loop: front one or more upstream MCP servers,
//! apply the static tool allowlist to `tools/call`, and append every governed
//! call to the tamper-evident audit ledger.
//!
//! Scope (per ROADMAP Phase 1): `tools/*` is the governed primitive. `initialize`
//! and `tools/list` are answered by the gateway (it *is* the server the client
//! talks to); `tools/list` aggregates the upstreams' tools and hides any the
//! allowlist denies. Other requests pass through to the primary upstream. Auth,
//! the policy-as-code engine, and the WASM sandbox are later phases that slot in
//! at the same call sites.

use crate::metrics::Metrics;
use anyhow::{anyhow, Result};
use mcpdef_audit::{Entry, Ledger};
use mcpdef_auth::Principal;
use mcpdef_core::{method, Decision, Id, Message};
use mcpdef_inspect::{Finding, Scanner};
use mcpdef_pin::{tool_hash, PinCheck, PinStore};
use mcpdef_policy::{Policy, PolicyContext, PolicyRules, Rbac};
use mcpdef_ratelimit::{RateDecision, RateLimiter};
use mcpdef_transport::Transport;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The pin-store key for one governed tool.
fn pin_key(server: &str, tool: &str) -> String {
    format!("{server}/{tool}")
}

/// An initialized upstream connection plus the local id counter used to
/// correlate the gateway's forwarded requests with the upstream's responses.
struct Upstream {
    id: String,
    transport: Box<dyn Transport>,
    next_id: i64,
    /// Tool definitions from the upstream's `tools/list` (cached at connect),
    /// used to aggregate `tools/list` and route `tools/call`.
    tools: Vec<serde_json::Value>,
}

/// The gateway: a policy, an audit ledger, and the set of upstreams (config
/// order; the first is the primary used for non-tool pass-through).
pub struct Gateway {
    policy: Policy,
    ledger: Ledger,
    agent: String,
    upstreams: Vec<Upstream>,
    /// tool name -> index into `upstreams` (first server to expose it wins).
    routes: HashMap<String, usize>,
    /// The tool-def pin store, if pinning is enabled (`[gateway] pins`).
    pin_store: Option<PinStore>,
    /// Where to persist the store (TOFU additions) after connect.
    pin_path: Option<PathBuf>,
    /// True if connect recorded new pins that should be written back.
    pins_dirty: bool,
    /// `server/tool` keys whose current definition drifted from its pin — a
    /// suspected rug-pull. These are hidden from `tools/list` and their
    /// `tools/call` is denied + audited.
    drifted: HashSet<String>,
    /// Inline injection / secret-exfil scanner (`[gateway.inspect]`); `None` = off.
    /// Descriptions are scanned at connect, tool-call results per call.
    inspect: Option<Scanner>,
    /// `server/tool` keys whose *description* tripped the injection rule pack at
    /// connect (tool poisoning). In enforce mode these are hidden from `tools/list`
    /// and their `tools/call` is denied — the description-side analog of `drifted`.
    poisoned: HashSet<String>,
    /// Token-bucket rate limiter for `tools/call`, if configured.
    rate_limiter: Option<RateLimiter>,
    /// Per-call upstream response timeout — a wedged upstream is failed (and
    /// audited) instead of hanging the gateway. `None` = wait indefinitely.
    upstream_timeout: Option<Duration>,
    /// Role-based access control layered over the allowlist for authenticated
    /// callers. `None` = no RBAC gate (the allowlist alone decides).
    rbac: Option<Rbac>,
    /// Policy-as-code rules (per-agent / per-argument allow/deny) evaluated after
    /// the allowlist passes. Empty = engine off.
    policy_rules: PolicyRules,
    /// Whether an `initialize`'s `clientInfo.name` may set the audit identity.
    /// True for a stdio gateway (one long-lived client — its name is a useful
    /// label). The HTTP listener sets this **false**: it serves many clients over
    /// one shared instance, so letting request content rename the shared identity
    /// would let one client's `initialize` mis-attribute another's audit records.
    capture_client_info: bool,
    /// Shared metrics registry for the OSS admin server; incremented at each
    /// audited decision. `None` = metrics off (nothing observing).
    metrics: Option<Arc<Metrics>>,
}

impl Gateway {
    pub fn new(policy: Policy, ledger: Ledger, agent: impl Into<String>) -> Self {
        Gateway {
            policy,
            ledger,
            agent: agent.into(),
            upstreams: Vec::new(),
            routes: HashMap::new(),
            pin_store: None,
            pin_path: None,
            pins_dirty: false,
            drifted: HashSet::new(),
            inspect: None,
            poisoned: HashSet::new(),
            rate_limiter: None,
            upstream_timeout: None,
            rbac: None,
            policy_rules: PolicyRules::default(),
            capture_client_info: true,
            metrics: None,
        }
    }

    /// Attach a shared [`Metrics`] registry so every audited decision is counted
    /// for the admin server / `/metrics`. A no-op observability-wise when unset.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Mark this gateway as serving many clients over one shared instance (the
    /// HTTP listener), so an `initialize`'s self-asserted `clientInfo.name` will
    /// **not** set the shared audit identity — preventing one client from
    /// mis-attributing another's audit records on the unauthenticated path.
    pub fn shared_across_clients(mut self) -> Self {
        self.capture_client_info = false;
        self
    }

    /// Layer RBAC over the allowlist: authenticated callers must hold a role that
    /// grants `(server, tool)`. A no-op (gate off) when `rbac` is empty/`None`.
    pub fn with_rbac(mut self, rbac: Option<Rbac>) -> Self {
        self.rbac = rbac.filter(|r| !r.is_empty());
        self
    }

    /// Layer the policy-as-code rule engine over the allowlist: after a `tools/call`
    /// passes the allowlist, the rules (per-agent / per-argument, first-match-wins)
    /// can deny it. A no-op when the rule set is empty.
    pub fn with_policy_rules(mut self, rules: PolicyRules) -> Self {
        self.policy_rules = rules;
        self
    }

    /// Enable token-bucket rate limiting on `tools/call`. `per_tool` / `global`
    /// are `(refill_per_sec, burst)`; either may be `None`. A no-op (limiter stays
    /// off) when both are `None`.
    pub fn with_rate_limit(
        mut self,
        per_tool: Option<(f64, f64)>,
        global: Option<(f64, f64)>,
    ) -> Self {
        self.rate_limiter = RateLimiter::new(per_tool, global, Instant::now());
        self
    }

    /// Fail a `tools/call` (and any forwarded request) whose upstream does not
    /// respond within `timeout`, instead of blocking the gateway.
    pub fn with_upstream_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.upstream_timeout = timeout;
        self
    }

    /// Enable tool-def pinning: tools are checked against `store` at connect
    /// (trust-on-first-use records unseen tools; a changed definition is flagged
    /// as drift), and TOFU additions are written back to `path` by
    /// [`persist_pins`](Gateway::persist_pins).
    pub fn with_pins(mut self, store: PinStore, path: impl Into<PathBuf>) -> Self {
        self.pin_store = Some(store);
        self.pin_path = Some(path.into());
        self
    }

    /// Enable inline injection / secret-exfil scanning (`[gateway.inspect]`). Tool
    /// descriptions are scanned at connect and tool-call results per call; a finding
    /// hides/denies the tool or refuses the result in enforce mode (logs only in
    /// warn). A no-op when `scanner` is `None` (mode off).
    pub fn with_inspect(mut self, scanner: Option<Scanner>) -> Self {
        self.inspect = scanner;
        self
    }

    /// Persist any trust-on-first-use pin additions made during connect. A no-op
    /// when pinning is off or nothing changed.
    pub fn persist_pins(&mut self) -> Result<()> {
        if self.pins_dirty {
            if let (Some(store), Some(path)) = (&self.pin_store, &self.pin_path) {
                store.save(path)?;
                self.pins_dirty = false;
            }
        }
        Ok(())
    }

    /// Number of tools flagged as drifted (rug-pull) across all upstreams.
    pub fn drift_count(&self) -> usize {
        self.drifted.len()
    }

    /// Connect an upstream: run the MCP lifecycle handshake (initialize →
    /// notifications/initialized), cache its `tools/list` for routing, and
    /// check each tool against the pin store (if pinning is enabled).
    pub async fn add_upstream(
        &mut self,
        id: impl Into<String>,
        mut transport: Box<dyn Transport>,
    ) -> Result<()> {
        let id = id.into();
        // Bound the connect handshake by the same per-call upstream timeout, so a
        // wedged upstream fails startup fast instead of hanging it indefinitely.
        let tools = match self.upstream_timeout {
            Some(timeout) => tokio::time::timeout(timeout, handshake_list(&mut *transport))
                .await
                .map_err(|_| {
                    anyhow!(
                        "upstream '{id}' did not complete its initialize handshake within {}ms",
                        timeout.as_millis()
                    )
                })??,
            None => handshake_list(&mut *transport).await?,
        };

        let idx = self.upstreams.len();
        for t in &tools {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                self.routes.entry(name.to_string()).or_insert(idx);
            }
        }
        self.pin_check(&id, &tools);
        self.inspect_check(&id, &tools).await;
        self.upstreams.push(Upstream {
            id,
            transport,
            next_id: 100,
            tools,
        });
        Ok(())
    }

    /// Classify each tool against the pin store (no-op if pinning is off):
    /// trust-on-first-use records an unseen tool; a changed governed definition
    /// is flagged as drift (a suspected rug-pull) so it is hidden + denied.
    fn pin_check(&mut self, server: &str, tools: &[serde_json::Value]) {
        if self.pin_store.is_none() {
            return;
        }
        let mut to_record: Vec<(String, String)> = Vec::new();
        let mut drift: Vec<String> = Vec::new();
        {
            let store = self.pin_store.as_ref().unwrap();
            for t in tools {
                if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                    let h = tool_hash(t);
                    match store.check(server, name, &h) {
                        PinCheck::Match => {}
                        PinCheck::New => to_record.push((name.to_string(), h)),
                        PinCheck::Drift => drift.push(pin_key(server, name)),
                    }
                }
            }
        }
        if !to_record.is_empty() {
            let store = self.pin_store.as_mut().unwrap();
            for (name, h) in to_record {
                store.record(server, &name, h);
            }
            self.pins_dirty = true;
        }
        for k in drift {
            self.drifted.insert(k);
        }
    }

    /// Scan each tool's definition against the injection rule pack at connect
    /// (no-op if inspect is off). A finding is audited under `tools/list`; in
    /// enforce mode the tool is marked `poisoned` (hidden + denied), the
    /// description-side analog of a rug-pull. Warn mode logs the finding only.
    async fn inspect_check(&mut self, server: &str, tools: &[serde_json::Value]) {
        // Collect findings under the immutable `&self.inspect` borrow, then release
        // it before auditing (which needs `&mut self`).
        let (blocks, hits): (bool, Vec<(String, Finding)>) = {
            let Some(scanner) = &self.inspect else {
                return;
            };
            let hits = tools
                .iter()
                .filter_map(|t| {
                    // Scan the whole serialized def (description, schema, annotations).
                    scanner.scan(&t.to_string()).map(|f| {
                        let name = t
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or_default()
                            .to_string();
                        (name, f)
                    })
                })
                .collect();
            (scanner.blocks(), hits)
        };
        if hits.is_empty() {
            return;
        }
        let started = Instant::now();
        let agent = self.agent.clone();
        for (name, f) in hits {
            if blocks {
                let dec = Decision::Deny {
                    rule: f.category.rule().to_string(),
                    reason: format!("tool '{name}' on '{server}': {}", f.reason("description")),
                };
                // Audited as a synthetic "connect" method, not `tools/list`: this
                // is a connect-time description scan, and no client `tools/list`
                // request occurred — mislabeling it would muddy audit correlation.
                self.audit(&agent, &dec, Some("connect"), Some(&name), server, started)
                    .await;
                self.poisoned.insert(pin_key(server, &name));
            } else {
                eprintln!(
                    "mcpdef: inspect (warn) — tool '{name}' on '{server}': {}",
                    f.reason("description")
                );
            }
        }
    }

    /// Scan a tool-call response for injection/secret patterns (no-op if inspect is
    /// off). Scans the serialized `result`, so a secret anywhere in the structure —
    /// not just `content[].text` — is caught.
    fn scan_result(&self, resp: &Message) -> Option<Finding> {
        let scanner = self.inspect.as_ref()?;
        let result = resp.result.as_ref()?;
        scanner.scan(&result.to_string())
    }

    /// Handle one downstream message from an unauthenticated transport (stdio).
    pub async fn handle(&mut self, msg: Message) -> Result<Option<Message>> {
        self.handle_authed(msg, None).await
    }

    /// Handle one downstream message, carrying the authenticated [`Principal`] when
    /// the transport validated one (the HTTP listener). The principal's subject is
    /// the audit identity, and its scopes/roles drive the RBAC gate. Returns the
    /// response to send back (`None` for notifications).
    pub async fn handle_authed(
        &mut self,
        msg: Message,
        principal: Option<&Principal>,
    ) -> Result<Option<Message>> {
        if msg.is_notification() || msg.is_response() {
            // Phase 1: lifecycle notifications are absorbed (the gateway already
            // initialized the upstreams); a stray client response is ignored.
            return Ok(None);
        }
        let Some(id) = msg.id.clone() else {
            return Ok(None);
        };
        // The audit identity for THIS request: an authenticated subject overrides
        // the (stdio) client identity captured at `initialize`. Computed per call
        // and threaded into `audit` — never stored on `self` — so one request's
        // identity can never bleed into the audit record of the next (the gateway
        // is long-lived and reused across every request behind the listener mutex).
        let agent = match principal {
            Some(p) => format!("sub:{}", p.subject),
            None => self.agent.clone(),
        };
        let method = msg.method().unwrap_or_default().to_string();

        match method.as_str() {
            method::INITIALIZE => Ok(Some(self.handle_initialize(id, &msg))),
            method::TOOLS_LIST => Ok(Some(self.handle_tools_list(id))),
            method::TOOLS_CALL => self
                .handle_tools_call(id, msg, principal, &agent)
                .await
                .map(Some),
            method::PING => Ok(Some(Message::result(id, serde_json::json!({})))),
            _ => self.forward_to_primary(id, msg, &agent).await.map(Some),
        }
    }

    fn handle_initialize(&mut self, id: Id, msg: &Message) -> Message {
        // Capture the client's self-asserted identity for the audit trail, if it
        // sent one — but only on a single-client (stdio) gateway. On the shared
        // HTTP listener this is disabled so one client can't rename the identity
        // used to audit another's calls (see `shared_across_clients`).
        if self.capture_client_info {
            if let Some(name) = msg
                .params
                .as_ref()
                .and_then(|p| p.get("clientInfo"))
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
            {
                self.agent = format!("agent:{name}");
            }
        }
        // The gateway is the server the client talks to.
        Message::result(
            id,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") }
            }),
        )
    }

    fn handle_tools_list(&self, id: Id) -> Message {
        // Aggregate upstream tools, hiding any the allowlist denies or that
        // drifted from their pin (a drifted tool is never offered to the client).
        let mut out = Vec::new();
        for up in &self.upstreams {
            for t in &up.tools {
                if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                    if self.policy.tool_is_exposed(&up.id, name)
                        && !self.drifted.contains(&pin_key(&up.id, name))
                        && !self.poisoned.contains(&pin_key(&up.id, name))
                    {
                        out.push(t.clone());
                    }
                }
            }
        }
        Message::result(id, serde_json::json!({ "tools": out }))
    }

    async fn handle_tools_call(
        &mut self,
        id: Id,
        msg: Message,
        principal: Option<&Principal>,
        agent: &str,
    ) -> Result<Message> {
        let started = Instant::now();
        let tool = msg.tool_name().unwrap_or_default().to_string();

        let Some(&idx) = self.routes.get(&tool) else {
            let dec = Decision::Deny {
                rule: "unknown-tool".into(),
                reason: format!("no governed server exposes tool '{tool}'"),
            };
            self.audit(
                agent,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                "(unrouted)",
                started,
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        };
        let server_id = self.upstreams[idx].id.clone();

        let decision = self.policy.decide_tool(&server_id, &tool);
        if !decision.is_allow() {
            self.audit(
                agent,
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

        // Policy-as-code gate: the rule engine (per-agent / per-argument,
        // first-match-wins) can deny a call the allowlist permitted — e.g. block a
        // destructive tool when an argument names a production target. Evaluated
        // over the caller, server, tool, and the tool-call arguments. No-op when no
        // rules are configured.
        if !self.policy_rules.is_empty() {
            let args = msg
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let pdec = self.policy_rules.evaluate(&PolicyContext {
                agent,
                server: server_id.as_str(),
                tool: tool.as_str(),
                args: &args,
            });
            if !pdec.is_allow() {
                self.audit(
                    agent,
                    &pdec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                )
                .await;
                return Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef denied: {}", deny_reason(&pdec)),
                ));
            }
        }

        // RBAC gate (authenticated callers only): the principal must hold a role
        // that grants (server, tool). Layered over the allowlist. Compute the
        // verdict before auditing so the `&self.rbac` borrow is released first.
        let rbac_denied = match (&self.rbac, principal) {
            (Some(rbac), Some(p)) => match rbac.decide(p.grants_subjects(), &server_id, &tool) {
                Decision::Allow => None,
                deny => Some(deny),
            },
            _ => None,
        };
        if let Some(dec) = rbac_denied {
            self.audit(
                agent,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Rug-pull gate: a tool whose definition drifted from its pin is denied
        // even if the allowlist permits it — the server changed it post-approval.
        if self.drifted.contains(&pin_key(&server_id, &tool)) {
            let dec = Decision::Deny {
                rule: "rug-pull".into(),
                reason: format!(
                    "tool '{tool}' on '{server_id}' changed since it was pinned (possible rug-pull); re-approve with `mcpdef pin`"
                ),
            };
            self.audit(
                agent,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
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
        if self.poisoned.contains(&pin_key(&server_id, &tool)) {
            let dec = Decision::Deny {
                rule: "injection".into(),
                reason: format!(
                    "tool '{tool}' on '{server_id}' has an injection-flagged description; refused"
                ),
            };
            self.audit(
                agent,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
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
        // analog of a `429`. The limiter borrow is dropped before auditing.
        let limited =
            self.rate_limiter
                .as_mut()
                .and_then(|rl| match rl.check(&tool, Instant::now()) {
                    RateDecision::Limited(scope) => Some(scope),
                    RateDecision::Allow => None,
                });
        if let Some(scope) = limited {
            let dec = Decision::Deny {
                rule: "rate-limited".into(),
                reason: format!(
                    "{} rate limit exceeded for '{tool}' — retry shortly",
                    scope.as_str()
                ),
            };
            self.audit(
                agent,
                &dec,
                Some(method::TOOLS_CALL),
                Some(&tool),
                &server_id,
                started,
            )
            .await;
            return Ok(Message::tool_error_result(
                id,
                format!("MCPdef denied: {}", deny_reason(&dec)),
            ));
        }

        // Allowed: forward to the owning upstream, bounded by the per-call timeout.
        let timeout = self.upstream_timeout;
        let resp_opt = {
            let up = &mut self.upstreams[idx];
            let local = Id::Num(up.next_id);
            up.next_id += 1;
            let req = Message::request(local.clone(), method::TOOLS_CALL, msg.params.clone());
            dispatch(&mut *up.transport, req, &local, timeout).await?
        };

        match resp_opt {
            Some(mut resp) => {
                // Scan the RESULT for injected instructions / exfiltrated secrets
                // before it flows back to the model. Enforce refuses it (a tool
                // error, audited as the finding's rule); warn logs and passes through.
                if let Some(f) = self.scan_result(&resp) {
                    if self.inspect.as_ref().is_some_and(Scanner::blocks) {
                        let dec = Decision::Deny {
                            rule: f.category.rule().to_string(),
                            reason: format!(
                                "tool '{tool}' on '{server_id}': {}",
                                f.reason("result")
                            ),
                        };
                        self.audit(
                            agent,
                            &dec,
                            Some(method::TOOLS_CALL),
                            Some(&tool),
                            &server_id,
                            started,
                        )
                        .await;
                        return Ok(Message::tool_error_result(
                            id,
                            format!("MCPdef blocked: {}", deny_reason(&dec)),
                        ));
                    }
                    eprintln!(
                        "mcpdef: inspect (warn) — result of '{tool}' on '{server_id}': {}",
                        f.reason("result")
                    );
                }
                resp.id = Some(id);
                self.audit(
                    agent,
                    &decision,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                )
                .await;
                Ok(resp)
            }
            None => {
                let dec = Decision::Deny {
                    rule: "upstream-timeout".into(),
                    reason: format!(
                        "upstream '{server_id}' did not respond to '{tool}' within {}ms",
                        timeout.map(|d| d.as_millis()).unwrap_or(0)
                    ),
                };
                self.audit(
                    agent,
                    &dec,
                    Some(method::TOOLS_CALL),
                    Some(&tool),
                    &server_id,
                    started,
                )
                .await;
                Ok(Message::tool_error_result(
                    id,
                    format!("MCPdef error: {}", deny_reason(&dec)),
                ))
            }
        }
    }

    async fn forward_to_primary(&mut self, id: Id, msg: Message, agent: &str) -> Result<Message> {
        let started = Instant::now();
        let method = msg.method().unwrap_or_default().to_string();
        if self.upstreams.is_empty() {
            return Ok(Message::error(id, -32601, "no upstream available"));
        }
        let server_id = self.upstreams[0].id.clone();
        let timeout = self.upstream_timeout;
        let resp_opt = {
            let up = &mut self.upstreams[0];
            let local = Id::Num(up.next_id);
            up.next_id += 1;
            let req = Message::request(local.clone(), method.as_str(), msg.params.clone());
            dispatch(&mut *up.transport, req, &local, timeout).await?
        };
        match resp_opt {
            Some(mut resp) => {
                resp.id = Some(id);
                self.audit(
                    agent,
                    &Decision::Allow,
                    Some(method.as_str()),
                    None,
                    &server_id,
                    started,
                )
                .await;
                Ok(resp)
            }
            None => {
                let dec = Decision::Deny {
                    rule: "upstream-timeout".into(),
                    reason: format!(
                        "upstream '{server_id}' did not respond to '{method}' within {}ms",
                        timeout.map(|d| d.as_millis()).unwrap_or(0)
                    ),
                };
                self.audit(
                    agent,
                    &dec,
                    Some(method.as_str()),
                    None,
                    &server_id,
                    started,
                )
                .await;
                Ok(Message::error(id, -32000, deny_reason(&dec)))
            }
        }
    }

    async fn audit(
        &mut self,
        agent: &str,
        decision: &Decision,
        method: Option<&str>,
        tool: Option<&str>,
        server: &str,
        started: Instant,
    ) {
        let latency_ms = started.elapsed().as_millis() as u64;
        // Only the governed `tools/call` hot path counts toward mcpdef_tools_calls_total —
        // the pin/rug-pull `connect`-time inspection and forward_to_primary's un-governed
        // relay of arbitrary methods (resources/*, prompts/*, …) are audited too, but
        // labeling them as tool calls would inflate a counter clients read as exactly that.
        if let (Some(metrics), Some(method::TOOLS_CALL)) = (&self.metrics, method) {
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
        let entry = Entry {
            agent: agent.to_string(),
            server: server.to_string(),
            method: method.map(str::to_string),
            tool: tool.map(str::to_string),
            decision: decision.clone(),
            latency_ms,
        };
        if let Err(e) = self.ledger.append(entry) {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }

    /// The current audit head hash (for diagnostics).
    pub fn audit_head(&self) -> &str {
        self.ledger.head()
    }

    /// Number of connected upstreams.
    pub fn upstream_count(&self) -> usize {
        self.upstreams.len()
    }
}

fn deny_reason(d: &Decision) -> String {
    match d {
        Decision::Deny { reason, .. } => reason.clone(),
        Decision::Allow => "allowed".to_string(),
    }
}

/// Send `req` to an upstream and await the response matching `local`, bounded by
/// `timeout`. `Ok(None)` means the upstream did not answer in time (the caller
/// turns that into an audited `upstream-timeout` error); send/transport errors
/// still propagate. Without a timeout it waits indefinitely (Phase-1 behavior).
async fn dispatch(
    transport: &mut dyn Transport,
    req: Message,
    local: &Id,
    timeout: Option<Duration>,
) -> Result<Option<Message>> {
    transport.send(req).await?;
    match timeout {
        Some(d) => match tokio::time::timeout(d, recv_response(transport, local)).await {
            Ok(r) => Ok(Some(r?)),
            Err(_) => Ok(None),
        },
        None => Ok(Some(recv_response(transport, local).await?)),
    }
}

/// Run the MCP lifecycle handshake (initialize → notifications/initialized) and
/// return the upstream's `tools/list` array. Shared by [`Gateway::add_upstream`]
/// and the `mcpdef pin` / `mcpdef diff-tools` commands (which only need the tool defs,
/// not a full gateway).
pub async fn handshake_list(transport: &mut dyn Transport) -> Result<Vec<serde_json::Value>> {
    transport
        .send(Message::request(
            Id::Num(0),
            method::INITIALIZE,
            Some(serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "mcpdef", "version": env!("CARGO_PKG_VERSION") }
            })),
        ))
        .await?;
    let _ = recv_response(transport, &Id::Num(0)).await?;

    transport
        .send(Message::notification(method::INITIALIZED, None))
        .await?;

    transport
        .send(Message::request(Id::Num(1), method::TOOLS_LIST, None))
        .await?;
    let list = recv_response(transport, &Id::Num(1)).await?;
    Ok(list
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Read from a transport until the response matching `id` arrives (skipping
/// notifications / unrelated frames). Errors if the peer closes first.
///
/// Phase 1 serializes upstream requests (one in flight per upstream), so a
/// non-matching *response* frame here is unexpected and dropped. When concurrent
/// multiplexing lands, this blocking scan must become a per-id response map so an
/// interleaved response for another caller is routed rather than discarded.
async fn recv_response(t: &mut dyn Transport, id: &Id) -> Result<Message> {
    loop {
        match t.recv().await? {
            Some(m) => {
                if m.is_response() && m.id.as_ref() == Some(id) {
                    return Ok(m);
                }
                // Phase 1: ignore notifications / mismatched ids.
            }
            None => return Err(anyhow!("upstream closed before responding to {id:?}")),
        }
    }
}
