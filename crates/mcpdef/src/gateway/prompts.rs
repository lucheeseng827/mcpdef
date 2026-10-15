//! Prompts: what each server may expose is its `prompts` allowlist, and a
//! `prompts/get` goes to the server that has the prompt, never simply to the
//! first. Their list is gathered with the others ([`super::lists`]).
//!
//! A prompt's messages flow into the model's context as a tool result does,
//! and a prompt template is written by the server, so what a get returns is
//! inspected as a tool result is.
use super::caller::Who;
use super::input::{self, Interim};
use super::{
    blocked, deny_reason, inspect_result, lock, Bucket, Gateway, Governance, Inspected,
    SECRET_REDACTED,
};
use mcpdef_audit::Attrs;
use mcpdef_core::wire::{self, error_code, WireModel};
use mcpdef_core::{method, Decision, Id, Message};
use mcpdef_policy::Target;
use serde_json::Value;
use std::time::Instant;

impl Gateway {
    /// `prompts/get`: routed by name to the server that has the prompt, and
    /// judged by the gates a tool call passes, in their order: that server's
    /// allowlist, the policy rules (on the name and the arguments), RBAC and
    /// the rate limit. What comes back is scanned. A prompt a gate denies is
    /// answered as an unknown name, and every get is audited with its name.
    pub(super) async fn handle_prompt_get(
        &self,
        g: &Governance,
        id: Id,
        msg: Message,
        who: &Who<'_>,
        era: WireModel,
    ) -> Message {
        let started = Instant::now();
        let Some(name) = msg
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Message::error(
                id,
                error_code::INVALID_PARAMS,
                "prompts/get needs `params.name`, a string",
            );
        };
        let Some(index) = self.route_prompt(g, &name) else {
            let dec = Decision::Deny {
                rule: "prompt-not-allowed".into(),
                reason: format!("no server's prompt allowlist takes '{name}'"),
            };
            self.audit_prompt(g, who, &dec, "(unrouted)", &name, started)
                .await;
            return denied(id, &dec);
        };
        let slot = &g.upstreams[index];
        let decision = g.policy.decide_prompt(&slot.id, &name);
        if !decision.is_allow() {
            self.audit_prompt(g, who, &decision, &slot.id, &name, started)
                .await;
            return denied(id, &decision);
        }
        let args = msg
            .params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        let gated = self.gate(
            g,
            who,
            &slot.id,
            Target::Prompt(&name),
            &args,
            Bucket::Prompts,
        );
        if let Some(dec) = gated {
            self.audit_prompt(g, who, &dec, &slot.id, &name, started)
                .await;
            return denied(id, &dec);
        }

        let offered = wire::input_capabilities(&msg);
        let outcome = match &slot.conn {
            Some(up) => {
                let mut req = Message::request(id.clone(), method::PROMPTS_GET, msg.params);
                up.stamp_offering(&mut req, &self.inner.client_info, &offered);
                let timeout = g.upstream_timeout;
                up.handle
                    .call(req, timeout)
                    .await
                    .inspect(|_| slot.answered(up))
                    .map_err(|error| slot.failure(&error, method::PROMPTS_GET, timeout))
            }
            None => Err(slot.down(None)),
        };
        match outcome {
            Ok(mut resp) => {
                let complete = !resp.result.as_ref().is_some_and(wire::input_required);
                let mut redacted = false;
                let inspected = inspect_result(g, &mut resp, None, complete);
                self.note_inspected(g, &inspected, &resp, "prompt", &slot.id, &name);
                match inspected {
                    Inspected::Clean => {}
                    Inspected::Warned(f) => eprintln!(
                        "mcpdef: inspect (warn) — prompt '{name}' on '{}': {}",
                        slot.id,
                        f.reason("prompt")
                    ),
                    Inspected::Redacted(rules) => {
                        eprintln!(
                            "mcpdef: inspect (redact) — prompt '{name}' on '{}': redacted what \
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
                                "prompt '{name}' on '{}': {}",
                                slot.id,
                                blocked(&f, why.as_deref(), "prompt")
                            ),
                        };
                        self.audit_prompt(g, who, &dec, &slot.id, &name, started)
                            .await;
                        return Message::error(
                            id,
                            error_code::INVALID_PARAMS,
                            format!("MCPdef blocked: {}", deny_reason(&dec)),
                        );
                    }
                }
                match input::interim(&resp, era, &offered) {
                    Interim::Final => {}
                    Interim::Relay => {
                        self.audit_with(
                            g,
                            who,
                            &decision,
                            Some(method::PROMPTS_GET),
                            Some(&name),
                            &slot.id,
                            started,
                            input::relayed(Attrs::default()),
                        )
                        .await;
                        return resp;
                    }
                    Interim::Refuse(why) => {
                        let dec = Decision::Deny {
                            rule: input::INPUT_REQUIRED.into(),
                            reason: format!("prompt '{name}' on '{}' {why}", slot.id),
                        };
                        self.audit_prompt(g, who, &dec, &slot.id, &name, started)
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
                    ..Attrs::default()
                };
                self.audit_with(
                    g,
                    who,
                    &decision,
                    Some(method::PROMPTS_GET),
                    Some(&name),
                    &slot.id,
                    started,
                    attrs,
                )
                .await;
                if era == WireModel::Modern {
                    if let Some(result) = resp.result.as_mut().and_then(Value::as_object_mut) {
                        result
                            .entry("resultType")
                            .or_insert_with(|| Value::from("complete"));
                    }
                }
                resp
            }
            Err(dec) => {
                self.audit_prompt(g, who, &dec, &slot.id, &name, started)
                    .await;
                Message::error(id, -32000, format!("MCPdef error: {}", deny_reason(&dec)))
            }
        }
    }

    /// Which server a get of `name` goes to: the one that listed it, else the
    /// first in config order whose allowlist takes it. A remembered server
    /// whose allowlist no longer takes the name, after a reload, is passed
    /// over.
    pub(super) fn route_prompt(&self, g: &Governance, name: &str) -> Option<usize> {
        let shows = |index: usize| g.policy.shows_prompt(&g.upstreams[index].id, name);
        let listed = lock(&self.inner.routes)
            .prompts
            .server(name, Instant::now())
            .map(str::to_string);
        listed
            .and_then(|id| g.upstreams.iter().position(|slot| slot.id == id))
            .filter(|&index| shows(index))
            .or_else(|| (0..g.upstreams.len()).find(|&index| shows(index)))
    }

    /// Audit a `prompts/get`, with the prompt's name where a tool call's
    /// record has the tool's.
    async fn audit_prompt(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        server: &str,
        name: &str,
        started: Instant,
    ) {
        self.audit(
            g,
            who,
            decision,
            Some(method::PROMPTS_GET),
            Some(name),
            server,
            started,
        )
        .await;
    }
}

/// The error a denied get gets: the spec's answer to a prompt name it does not
/// know. To the client, a prompt it may not get is not there.
fn denied(id: Id, decision: &Decision) -> Message {
    Message::error(
        id,
        error_code::INVALID_PARAMS,
        format!("MCPdef denied: {}", deny_reason(decision)),
    )
}
