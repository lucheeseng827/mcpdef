//! `completion/complete`: suggestions for the arguments of a prompt or a
//! resource template, from the server that has the prompt or the template.
//!
//! A suggestion can say what a server holds, so the spec asks that
//! completions be access-controlled and rate-limited. A prompt's completion
//! is judged as a get of the prompt; a template's by the template allowlist,
//! the rules that name no kind, and RBAC, which needs a role granting some
//! resource on that server. Each URI a completion suggests is judged again
//! when it is read. What comes back is inspected, since a suggestion can carry
//! a secret as a result can.
use super::caller::Who;
use super::{
    blocked, clip, deny_reason, inspect_result, lock, Bucket, Gateway, Governance, Inspected,
    SECRET_REDACTED, URI_KEPT,
};
use mcpdef_audit::Attrs;
use mcpdef_core::wire::{error_code, WireModel};
use mcpdef_core::{method, Decision, Id, Message};
use mcpdef_policy::Target;
use serde_json::Value;
use std::time::Instant;

/// What a completion is for.
enum Completing {
    /// A prompt's arguments: `ref/prompt`, by name.
    Prompt(String),
    /// A resource template's: `ref/resource`, whose `uri` is a template or a
    /// URI, as the server writes it.
    Template(String),
}

impl Completing {
    fn target(&self) -> Target<'_> {
        match self {
            Completing::Prompt(name) => Target::Prompt(name),
            Completing::Template(template) => Target::Template(template),
        }
    }
}

impl Gateway {
    /// `completion/complete`: routed to the server that has what `ref` names,
    /// judged, forwarded as the client wrote it, and scanned. A denied one is
    /// answered as an invalid reference, and every one is audited with the
    /// prompt's name or the template.
    pub(super) async fn handle_completion(
        &self,
        g: &Governance,
        id: Id,
        msg: Message,
        who: &Who<'_>,
        era: WireModel,
    ) -> Message {
        let started = Instant::now();
        let reference = msg.params.as_ref().and_then(|p| p.get("ref"));
        let text = |key: &str| {
            reference
                .and_then(|r| r.get(key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let completing = match reference
            .and_then(|r| r.get("type"))
            .and_then(Value::as_str)
        {
            Some("ref/prompt") => text("name").map(Completing::Prompt),
            Some("ref/resource") => text("uri").map(Completing::Template),
            _ => None,
        };
        let Some(completing) = completing else {
            return Message::error(
                id,
                error_code::INVALID_PARAMS,
                "completion/complete needs `params.ref`: a `ref/prompt` with a `name`, or a \
                 `ref/resource` with a `uri`",
            );
        };

        let routed = match &completing {
            Completing::Prompt(name) => self.route_prompt(g, name),
            Completing::Template(template) => self.route_template(g, template),
        };
        let Some(index) = routed else {
            let dec = match &completing {
                Completing::Prompt(name) => Decision::Deny {
                    rule: "prompt-not-allowed".into(),
                    reason: format!("no server's prompt allowlist takes '{name}'"),
                },
                Completing::Template(template) => Decision::Deny {
                    rule: "template-not-allowed".into(),
                    reason: format!(
                        "no server's template allowlist takes '{}'",
                        clip(template, URI_KEPT)
                    ),
                },
            };
            self.audit_completion(g, who, &dec, "(unrouted)", &completing, started)
                .await;
            return denied(id, &dec);
        };
        let slot = &g.upstreams[index];
        let decision = match &completing {
            Completing::Prompt(name) => g.policy.decide_prompt(&slot.id, name),
            Completing::Template(template) => g.policy.decide_template(&slot.id, template),
        };
        if !decision.is_allow() {
            self.audit_completion(g, who, &decision, &slot.id, &completing, started)
                .await;
            return denied(id, &decision);
        }
        // The arguments resolved so far are the ones the rules judge.
        let args = msg
            .params
            .as_ref()
            .and_then(|p| p.get("context"))
            .and_then(|c| c.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        let gated = self.gate(
            g,
            who,
            &slot.id,
            completing.target(),
            &args,
            Bucket::Completions,
        );
        if let Some(dec) = gated {
            self.audit_completion(g, who, &dec, &slot.id, &completing, started)
                .await;
            return denied(id, &dec);
        }

        let outcome = match &slot.conn {
            Some(up) => {
                let mut req = Message::request(id.clone(), method::COMPLETION_COMPLETE, msg.params);
                up.stamp(&mut req, &self.inner.client_info);
                let timeout = g.upstream_timeout;
                up.handle
                    .call(req, timeout)
                    .await
                    .inspect(|_| slot.answered(up))
                    .map_err(|error| slot.failure(&error, method::COMPLETION_COMPLETE, timeout))
            }
            None => Err(slot.down(None)),
        };
        match outcome {
            Ok(mut resp) => {
                // A completion is never interim, so its secrets are always
                // redacted in redact mode.
                let what = |finding: &str| {
                    format!(
                        "completion of '{}' on '{}': {finding}",
                        completing.target().name(),
                        slot.id
                    )
                };
                let mut redacted = false;
                let inspected = inspect_result(g, &mut resp, None, true);
                self.note_inspected(
                    g,
                    &inspected,
                    &resp,
                    "completion",
                    &slot.id,
                    completing.target().name(),
                );
                match inspected {
                    Inspected::Clean => {}
                    Inspected::Warned(f) => {
                        eprintln!("mcpdef: inspect (warn) — {}", what(&f.reason("completion")))
                    }
                    Inspected::Redacted(rules) => {
                        let found = format!("redacted what {} found", rules.join(", "));
                        eprintln!("mcpdef: inspect (redact) — {}", what(&found));
                        redacted = true;
                    }
                    Inspected::Blocked(f, why) => {
                        let dec = Decision::Deny {
                            rule: f.category.rule().to_string(),
                            reason: what(&blocked(&f, why.as_deref(), "completion")),
                        };
                        self.audit_completion(g, who, &dec, &slot.id, &completing, started)
                            .await;
                        return Message::error(
                            id,
                            error_code::INVALID_PARAMS,
                            format!("MCPdef blocked: {}", deny_reason(&dec)),
                        );
                    }
                }
                let rule = redacted.then_some(SECRET_REDACTED);
                self.audit_completion_with(g, who, &decision, &slot.id, &completing, started, rule)
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
                self.audit_completion(g, who, &dec, &slot.id, &completing, started)
                    .await;
                Message::error(id, -32000, format!("MCPdef error: {}", deny_reason(&dec)))
            }
        }
    }

    /// Which server a completion of `template` goes to: the one that listed
    /// it, else the first in config order whose `resource_templates` shows
    /// it.
    fn route_template(&self, g: &Governance, template: &str) -> Option<usize> {
        let shows = |index: usize| {
            g.policy
                .resources(&g.upstreams[index].id)
                .is_some_and(|r| r.shows_template(template))
        };
        let listed = lock(&self.inner.routes)
            .templates
            .server(template, Instant::now())
            .map(str::to_string);
        listed
            .and_then(|id| g.upstreams.iter().position(|slot| slot.id == id))
            .filter(|&index| shows(index))
            .or_else(|| (0..g.upstreams.len()).find(|&index| shows(index)))
    }

    /// Audit a completion, with its prompt's name where a get's record has
    /// it, or its template where a read's has the URI.
    async fn audit_completion(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        server: &str,
        completing: &Completing,
        started: Instant,
    ) {
        self.audit_completion_with(g, who, decision, server, completing, started, None)
            .await;
    }

    /// [`audit_completion`](Self::audit_completion), naming `rule` as the
    /// rule behind an allowed record.
    #[allow(clippy::too_many_arguments)]
    async fn audit_completion_with(
        &self,
        g: &Governance,
        who: &Who<'_>,
        decision: &Decision,
        server: &str,
        completing: &Completing,
        started: Instant,
        rule: Option<&str>,
    ) {
        let (tool, uri) = match completing {
            Completing::Prompt(name) => (Some(name.as_str()), None),
            Completing::Template(template) => (None, Some(clip(template, URI_KEPT).to_string())),
        };
        let attrs = Attrs {
            uri,
            rule: rule.map(str::to_string),
            ..Attrs::default()
        };
        self.audit_with(
            g,
            who,
            decision,
            Some(method::COMPLETION_COMPLETE),
            tool,
            server,
            started,
            attrs,
        )
        .await;
    }
}

/// The error a denied completion gets: the spec's answer to a reference the
/// server does not know.
fn denied(id: Id, decision: &Decision) -> Message {
    Message::error(
        id,
        error_code::INVALID_PARAMS,
        format!("MCPdef denied: {}", deny_reason(decision)),
    )
}
