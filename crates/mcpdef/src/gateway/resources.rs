//! Resources: what each server may expose is its `resources` allowlist, and
//! a read goes to the server that has the URI, never simply to the first.
//! Their lists are gathered with the others ([`super::lists`]).
//!
//! A read is judged on the URI in normal form ([`uri::normalize`]), and the
//! upstream is sent that form, so it receives exactly what was judged.
use super::caller::Who;
use super::input::{self, Interim};
use super::{
    blocked, clip, deny_reason, inspect_result, lock, Bucket, Gateway, Governance, Inspected,
    CACHE_SCOPE, CACHE_TTL_MS, SECRET_REDACTED, URI_KEPT,
};
use mcpdef_audit::Attrs;
use mcpdef_core::wire::{self, error_code, WireModel};
use mcpdef_core::{method, Decision, Id, Message};
use mcpdef_policy::uri::{self, Uri};
use mcpdef_policy::{PolicyContext, Target};
use serde_json::{Map, Value};
use std::time::Instant;

/// The error a read of a URI no server may serve gets: the spec's "resource
/// not found". To the client, a resource it may not read is not there.
const RESOURCE_NOT_FOUND: i64 = -32002;

impl Gateway {
    /// `resources/read`: the URI is put in normal form, routed to the server
    /// that has it, and judged by the gates a tool call passes, in their
    /// order: that server's allowlist, the policy rules, RBAC, the rate limit.
    /// It is sent in normal form, and what comes back is scanned. A refused
    /// URI, or one a gate denies, is denied as not found, and every read is
    /// audited with its URI.
    pub(super) async fn handle_resource_read(
        &self,
        g: &Governance,
        id: Id,
        msg: Message,
        who: &Who<'_>,
        era: WireModel,
    ) -> Message {
        let started = Instant::now();
        let Some(raw) = msg
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
        else {
            return Message::error(
                id,
                error_code::INVALID_PARAMS,
                "resources/read needs `params.uri`, a string",
            );
        };
        let uri = match uri::normalize(raw) {
            Ok(uri) => uri,
            Err(refused) => {
                let kept = clip(raw, URI_KEPT);
                let dec = Decision::Deny {
                    rule: "uri-refused".into(),
                    reason: format!("resource '{kept}' {refused}"),
                };
                self.audit_resource(g, who, &dec, "(unrouted)", kept, started)
                    .await;
                return denied(id, &dec);
            }
        };
        let Some(index) = self.route_resource(g, &uri) else {
            let dec = Decision::Deny {
                rule: "resource-not-allowed".into(),
                reason: format!("no server's resource allowlist takes '{uri}'"),
            };
            self.audit_resource(g, who, &dec, "(unrouted)", uri.as_str(), started)
                .await;
            return denied(id, &dec);
        };
        let slot = &g.upstreams[index];
        let decision = g.policy.decide_resource(&slot.id, &uri);
        if !decision.is_allow() {
            self.audit_resource(g, who, &decision, &slot.id, uri.as_str(), started)
                .await;
            return denied(id, &decision);
        }
        let gated = self.gate(
            g,
            who,
            &slot.id,
            Target::Resource(&uri),
            &Value::Null,
            Bucket::Reads,
        );
        if let Some(dec) = gated {
            self.audit_resource(g, who, &dec, &slot.id, uri.as_str(), started)
                .await;
            return denied(id, &dec);
        }

        // Sent as judged: the URI in normal form, whatever the client wrote.
        let offered = wire::input_capabilities(&msg);
        let mut params = msg.params.unwrap_or_else(|| Value::Object(Map::new()));
        if let Some(params) = params.as_object_mut() {
            params.insert("uri".into(), Value::from(uri.as_str()));
        }
        let outcome = match &slot.conn {
            Some(up) => {
                let mut req = Message::request(id.clone(), method::RESOURCES_READ, Some(params));
                up.stamp_offering(&mut req, &self.inner.client_info, &offered);
                let timeout = g.upstream_timeout;
                up.handle
                    .call(req, timeout)
                    .await
                    .inspect(|_| slot.answered(up))
                    .map_err(|error| slot.failure(&error, method::RESOURCES_READ, timeout))
            }
            None => Err(slot.down(None)),
        };
        match outcome {
            Ok(mut resp) => {
                // What a resource holds flows into the model's context as a
                // tool result does, so the `transform` rules' result edits,
                // and then inspect, take it as they take one. Only a final
                // result: an interim one carries no contents.
                let complete = !resp.result.as_ref().is_some_and(wire::input_required);
                let mut fired = Vec::new();
                if complete && g.policy_rules.transforms_results() {
                    if let Some(result) = resp.result.as_mut() {
                        let ctx = PolicyContext {
                            agent: &who.agent,
                            server: &slot.id,
                            target: Target::Resource(&uri),
                            args: &Value::Null,
                        };
                        let done = g.policy_rules.transform_result(&ctx, result, None);
                        for (rule, why) in &done.skipped {
                            eprintln!(
                                "mcpdef: transform rule '{rule}' skipped for resource '{uri}' \
                                 on '{}': {why}",
                                slot.id
                            );
                        }
                        fired = done.fired;
                        if let Some(dec) = done.refused {
                            let attrs = Attrs {
                                transforms: fired,
                                ..Attrs::default()
                            };
                            self.audit_read(g, who, &dec, &slot.id, uri.as_str(), started, attrs)
                                .await;
                            return denied(id, &dec);
                        }
                    }
                }
                let attrs = || Attrs {
                    transforms: fired.clone(),
                    ..Attrs::default()
                };
                let mut redacted = false;
                let inspected = inspect_result(g, &mut resp, None, complete);
                self.note_inspected(g, &inspected, &resp, "resource", &slot.id, uri.as_str());
                match inspected {
                    Inspected::Clean => {}
                    Inspected::Warned(f) => eprintln!(
                        "mcpdef: inspect (warn) — resource '{uri}' on '{}': {}",
                        slot.id,
                        f.reason("resource")
                    ),
                    Inspected::Redacted(rules) => {
                        eprintln!(
                            "mcpdef: inspect (redact) — resource '{uri}' on '{}': redacted what \
                             {} found",
                            slot.id,
                            rules.join(", ")
                        );
                        redacted = true;
                    }
                    Inspected::Blocked(f, why) => {
                        let dec = Decision::Deny {
                            rule: f.category.rule().to_string(),
                            reason: format!(
                                "resource '{uri}' on '{}': {}",
                                slot.id,
                                blocked(&f, why.as_deref(), "resource")
                            ),
                        };
                        self.audit_read(g, who, &dec, &slot.id, uri.as_str(), started, attrs())
                            .await;
                        return Message::error(
                            id,
                            RESOURCE_NOT_FOUND,
                            format!("MCPdef blocked: {}", deny_reason(&dec)),
                        );
                    }
                }
                // An interim result carries no contents, and no caching hints:
                // those are for a complete one.
                match input::interim(&resp, era, &offered) {
                    Interim::Final => {}
                    Interim::Relay => {
                        let attrs = Attrs {
                            uri: Some(uri.as_str().to_string()),
                            ..Attrs::default()
                        };
                        self.audit_with(
                            g,
                            who,
                            &decision,
                            Some(method::RESOURCES_READ),
                            None,
                            &slot.id,
                            started,
                            input::relayed(attrs),
                        )
                        .await;
                        return resp;
                    }
                    Interim::Refuse(why) => {
                        let dec = Decision::Deny {
                            rule: input::INPUT_REQUIRED.into(),
                            reason: format!("resource '{uri}' on '{}' {why}", slot.id),
                        };
                        self.audit_resource(g, who, &dec, &slot.id, uri.as_str(), started)
                            .await;
                        return Message::error(
                            id,
                            -32000,
                            format!("MCPdef denied: {}", deny_reason(&dec)),
                        );
                    }
                }
                let attrs = Attrs {
                    rule: redacted.then(|| SECRET_REDACTED.to_string()),
                    ..attrs()
                };
                self.audit_read(g, who, &decision, &slot.id, uri.as_str(), started, attrs)
                    .await;
                if era == WireModel::Modern {
                    if let Some(result) = resp.result.as_mut().and_then(Value::as_object_mut) {
                        result
                            .entry("resultType")
                            .or_insert_with(|| Value::from("complete"));
                        result.insert("ttlMs".into(), Value::from(CACHE_TTL_MS));
                        result.insert("cacheScope".into(), Value::from(CACHE_SCOPE));
                    }
                }
                resp
            }
            Err(dec) => {
                self.audit_resource(g, who, &dec, &slot.id, uri.as_str(), started)
                    .await;
                Message::error(id, -32000, format!("MCPdef error: {}", deny_reason(&dec)))
            }
        }
    }

    /// Which server a read of `uri` goes to: the one that listed it, else the
    /// one whose tool result linked it, else the first in config order whose
    /// allowlist takes it. A remembered server whose allowlist no longer takes
    /// the URI, after a reload, is passed over.
    fn route_resource(&self, g: &Governance, uri: &Uri) -> Option<usize> {
        let allows = |index: usize| {
            g.policy
                .resources(&g.upstreams[index].id)
                .is_some_and(|r| r.allows(uri))
        };
        let now = Instant::now();
        let remembered: Vec<String> = {
            let routes = lock(&self.inner.routes);
            [&routes.resources, &routes.links]
                .into_iter()
                .filter_map(|seen| seen.server(uri.as_str(), now))
                .map(str::to_string)
                .collect()
        };
        remembered
            .iter()
            .filter_map(|id| g.upstreams.iter().position(|slot| &slot.id == id))
            .find(|&index| allows(index))
            .or_else(|| (0..g.upstreams.len()).find(|&index| allows(index)))
    }

    /// Remember each `resource_link` a tool result from `server` carries, so
    /// that a read of it goes back to `server`: the spec lets such a link name
    /// a resource no list shows.
    pub(super) fn remember_links(&self, g: &Governance, server: &str, resp: &Message) {
        if g.policy.resources(server).is_none() {
            return;
        }
        let Some(content) = resp
            .result
            .as_ref()
            .and_then(|r| r.get("content"))
            .and_then(Value::as_array)
        else {
            return;
        };
        let now = Instant::now();
        let mut routes = lock(&self.inner.routes);
        for block in content {
            if block.get("type").and_then(Value::as_str) != Some("resource_link") {
                continue;
            }
            let Some(text) = block.get("uri").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(uri) = uri::normalize(text) {
                routes.links.remember(uri.as_str(), server, now);
            }
        }
    }

    /// Audit a `resources/read`, with the URI it named.
    async fn audit_resource(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        server: &str,
        uri: &str,
        started: Instant,
    ) {
        self.audit_read(g, who, decision, server, uri, started, Attrs::default())
            .await;
    }

    /// [`audit_resource`](Self::audit_resource), with the record's other
    /// optional members.
    #[allow(clippy::too_many_arguments)]
    async fn audit_read(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        server: &str,
        uri: &str,
        started: Instant,
        attrs: Attrs,
    ) {
        let attrs = Attrs {
            uri: Some(uri.to_string()),
            ..attrs
        };
        self.audit_with(
            g,
            who,
            decision,
            Some(method::RESOURCES_READ),
            None,
            server,
            started,
            attrs,
        )
        .await;
    }
}

/// The error a denied read gets.
fn denied(id: Id, decision: &Decision) -> Message {
    Message::error(
        id,
        RESOURCE_NOT_FOUND,
        format!("MCPdef denied: {}", deny_reason(decision)),
    )
}
