//! Filter mode: a request that a proxy routes to its server itself, judged
//! before it goes by the gates it would meet in the path, those that a
//! request alone can be judged by, and recorded as the gateway records its
//! own decisions.
//!
//! What the proxy routes never passes through the gateway, so nothing that
//! the gateway judges by a server's answers is here: the pins, which hold a
//! tool's definition as `tools/list` gave it, inspect, the transforms of
//! results, and the lists it filters. Nor can the gateway change a request it
//! does not send: a call whose arguments a transform rule would change is
//! refused, and so is a read of a URI that is not in normal form, since the
//! server would read a URI other than the one judged.
use super::caller::{Caller, Who};
use super::{clip, lock, read, Bucket, Gateway, Governance, URI_KEPT};
use mcpdef_audit::Attrs;
use mcpdef_core::{method, wire, Decision, Message};
use mcpdef_policy::uri;
use mcpdef_policy::{PolicyContext, Target, Transformed};
use mcpdef_ratelimit::RateDecision;
use serde_json::Value;
use std::time::Instant;

/// The server a refused request names in its record when its path names
/// none.
const UNROUTED: &str = "(unrouted)";

/// What the gateway makes of a request a proxy asks about.
#[derive(Debug, Clone, PartialEq)]
pub enum Authorization {
    /// Not one it judges: a list, a ping, a notification, a response, a
    /// method no gate covers. It may pass, and nothing is recorded.
    Unjudged,
    /// It may pass. `seq` is its record, once written.
    Allowed { seq: Option<u64> },
    /// It may not, for `decision`'s rule and reason. `seq` is its record,
    /// once written; a request too malformed to name what it asks for has
    /// none, as in the path.
    Denied {
        decision: Decision,
        seq: Option<u64>,
    },
}

/// What a request asks for, as the gates judge it.
enum Asked<'m> {
    /// A `tools/call` of `tool` with `args`.
    Call { tool: &'m str, args: Value },
    /// A `resources/read` or `resources/subscribe` of `uri`.
    Read { method: &'static str, uri: &'m str },
    /// A `prompts/get` of `name` with `args`.
    Prompt { name: &'m str, args: Value },
    /// A `completion/complete` of a prompt's arguments.
    CompletePrompt { name: &'m str, args: Value },
    /// A `completion/complete` of a resource template's.
    CompleteTemplate { template: &'m str, args: Value },
}

impl Gateway {
    /// Judge `msg`, a request a proxy routes itself to `server`, by the
    /// gates it would meet in the path, and record the decision as asked by
    /// `asker`. `server` is `None` when the request's path names no server:
    /// a request the gates would judge is then refused, and recorded.
    pub async fn authorize(
        &self,
        server: Option<&str>,
        msg: &Message,
        caller: &Caller,
        asker: &str,
    ) -> Authorization {
        if !msg.is_request() {
            return Authorization::Unjudged;
        }
        let asked = match asked(msg) {
            Ok(Some(asked)) => asked,
            Ok(None) => return Authorization::Unjudged,
            Err(why) => {
                return Authorization::Denied {
                    decision: Decision::Deny {
                        rule: "invalid-request".into(),
                        reason: why.to_string(),
                    },
                    seq: None,
                }
            }
        };
        let started = Instant::now();
        let governance = self.inner.governance.load_full();
        let g = &*governance;
        let mut who = Who::of(caller, || read(&self.inner.agent).clone());
        if let Some(trace) = wire::traceparent(msg).and_then(mcpdef_audit::otlp::traceparent) {
            who.trace = Some(trace);
        }
        let (decision, transforms) = match server {
            Some(server) => self.judge(g, &who, server, &asked),
            None => (
                Decision::Deny {
                    rule: "unknown-route".into(),
                    reason: "the request's path is under no server's filter_path".into(),
                },
                Vec::new(),
            ),
        };
        let (method, named, uri) = match &asked {
            Asked::Call { tool, .. } => (method::TOOLS_CALL, Some(*tool), None),
            Asked::Read { method, uri } => (*method, None, Some(clip(uri, URI_KEPT))),
            Asked::Prompt { name, .. } => (method::PROMPTS_GET, Some(*name), None),
            Asked::CompletePrompt { name, .. } => (method::COMPLETION_COMPLETE, Some(*name), None),
            Asked::CompleteTemplate { template, .. } => (
                method::COMPLETION_COMPLETE,
                None,
                Some(clip(template, URI_KEPT)),
            ),
        };
        let attrs = Attrs {
            uri: uri.map(str::to_string),
            transforms,
            hook: Some(asker.to_string()),
            ..Attrs::default()
        };
        let seq = self
            .audit_with(
                g,
                &who,
                &decision,
                Some(method),
                named,
                server.unwrap_or(UNROUTED),
                started,
                attrs,
            )
            .await;
        match decision {
            Decision::Allow => Authorization::Allowed { seq },
            decision => Authorization::Denied { decision, seq },
        }
    }

    /// The decision the gates make of `asked`, a request to `server`, and
    /// the transform rules that fired on its arguments: the order and the
    /// rules of the path's.
    fn judge(
        &self,
        g: &Governance,
        who: &Who<'_>,
        server: &str,
        asked: &Asked<'_>,
    ) -> (Decision, Vec<String>) {
        match asked {
            Asked::Call { tool, args } => self.judge_call(g, who, server, tool, args.clone()),
            Asked::Read { uri: raw, .. } => {
                let uri = match uri::normalize(raw) {
                    Ok(uri) => uri,
                    Err(refused) => {
                        let reason = format!("resource '{}' {refused}", clip(raw, URI_KEPT));
                        return (deny("uri-refused", reason), Vec::new());
                    }
                };
                if uri.as_str() != *raw {
                    let reason = format!(
                        "resource '{}' is not in normal form, '{}': the server would read \
                         another URI than the one judged",
                        clip(raw, URI_KEPT),
                        clip(uri.as_str(), URI_KEPT)
                    );
                    return (deny("uri-refused", reason), Vec::new());
                }
                let decision = g.policy.decide_resource(server, &uri);
                let gated = match decision.is_allow() {
                    true => self.gate(
                        g,
                        who,
                        server,
                        Target::Resource(&uri),
                        &Value::Null,
                        Bucket::Reads,
                    ),
                    false => Some(decision),
                };
                (gated.unwrap_or(Decision::Allow), Vec::new())
            }
            Asked::Prompt { name, args } => {
                let decision = g.policy.decide_prompt(server, name);
                let gated = match decision.is_allow() {
                    true => self.gate(g, who, server, Target::Prompt(name), args, Bucket::Prompts),
                    false => Some(decision),
                };
                (gated.unwrap_or(Decision::Allow), Vec::new())
            }
            Asked::CompletePrompt { name, args } => {
                let decision = g.policy.decide_prompt(server, name);
                let gated = match decision.is_allow() {
                    true => self.gate(
                        g,
                        who,
                        server,
                        Target::Prompt(name),
                        args,
                        Bucket::Completions,
                    ),
                    false => Some(decision),
                };
                (gated.unwrap_or(Decision::Allow), Vec::new())
            }
            Asked::CompleteTemplate { template, args } => {
                let decision = g.policy.decide_template(server, template);
                let gated = match decision.is_allow() {
                    true => self.gate(
                        g,
                        who,
                        server,
                        Target::Template(template),
                        args,
                        Bucket::Completions,
                    ),
                    false => Some(decision),
                };
                (gated.unwrap_or(Decision::Allow), Vec::new())
            }
        }
    }

    /// A `tools/call`'s gates, as `handle_tools_call` meets them: the
    /// server's allowlist, the argument transforms, the policy rules, RBAC
    /// and the rate limit. The pins, inspect and the `x-mcp-header` check
    /// need the server's tool definitions, which filter mode never sees.
    fn judge_call(
        &self,
        g: &Governance,
        who: &Who<'_>,
        server: &str,
        tool: &str,
        mut args: Value,
    ) -> (Decision, Vec<String>) {
        let decision = g.policy.decide_tool(server, tool);
        if !decision.is_allow() {
            return (decision, Vec::new());
        }
        let transformed = match g.policy_rules.transforms() {
            true => g
                .policy_rules
                .transform(&who.agent, server, tool, &mut args),
            false => Transformed::default(),
        };
        for (rule, why) in &transformed.skipped {
            eprintln!("mcpdef: transform rule '{rule}' skipped for '{tool}' on '{server}': {why}");
        }
        let fired = transformed.fired;
        if let Some(refused) = transformed.refused {
            return (refused, fired);
        }
        if transformed.changed {
            // A proxy's check can let a request through or stop it, not change it.
            let rule = fired.last().cloned().unwrap_or_default();
            let reason = format!(
                "transform rule '{rule}' changes the arguments of '{tool}' on '{server}', which \
                 a proxy's check cannot do: put the gateway in the path for it"
            );
            return (Decision::Deny { rule, reason }, fired);
        }
        if !g.policy_rules.is_empty() {
            let decision = g.policy_rules.evaluate(&PolicyContext {
                agent: &who.agent,
                server,
                target: Target::Tool(tool),
                args: &args,
            });
            if !decision.is_allow() {
                return (decision, fired);
            }
        }
        let grants = g
            .rbac
            .as_ref()
            .and_then(|rbac| Some((rbac, who.grants(rbac)?)));
        if let Some((rbac, grants)) = grants {
            let decision = rbac.decide(grants.into_iter(), server, tool);
            if !decision.is_allow() {
                return (decision, fired);
            }
        }
        let limited = self.inner.rate_limiter.load().as_ref().and_then(|rl| {
            match lock(rl).check(server, tool, Instant::now()) {
                RateDecision::Limited(scope) => Some(scope),
                RateDecision::Allow => None,
            }
        });
        if let Some(scope) = limited {
            let reason = format!(
                "{} rate limit exceeded for '{tool}' — retry shortly",
                scope.as_str()
            );
            return (deny("rate-limited", reason), fired);
        }
        (Decision::Allow, fired)
    }
}

/// A denial by `rule`.
fn deny(rule: &str, reason: String) -> Decision {
    Decision::Deny {
        rule: rule.to_string(),
        reason,
    }
}

/// What `msg` asks for, if it is a request the gates judge; `Err` with why
/// when it is one of those and does not say what it asks for.
fn asked(msg: &Message) -> Result<Option<Asked<'_>>, &'static str> {
    let params = msg.params.as_ref();
    let text = |key: &str| params.and_then(|p| p.get(key)).and_then(Value::as_str);
    let value = |key: &str| {
        params
            .and_then(|p| p.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let asked = match msg.method().unwrap_or_default() {
        method::TOOLS_CALL => Asked::Call {
            tool: text("name").ok_or("tools/call needs `params.name`, a string")?,
            args: value("arguments"),
        },
        method::RESOURCES_READ => Asked::Read {
            method: method::RESOURCES_READ,
            uri: text("uri").ok_or("resources/read needs `params.uri`, a string")?,
        },
        // A subscription delivers what a read would.
        method::RESOURCES_SUBSCRIBE => Asked::Read {
            method: method::RESOURCES_SUBSCRIBE,
            uri: text("uri").ok_or("resources/subscribe needs `params.uri`, a string")?,
        },
        method::PROMPTS_GET => Asked::Prompt {
            name: text("name").ok_or("prompts/get needs `params.name`, a string")?,
            args: value("arguments"),
        },
        method::COMPLETION_COMPLETE => {
            let reference = params.and_then(|p| p.get("ref"));
            let of = |key: &str| reference.and_then(|r| r.get(key)).and_then(Value::as_str);
            // The arguments resolved so far are the ones the rules judge.
            let args = params
                .and_then(|p| p.get("context"))
                .and_then(|c| c.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            let missing = "completion/complete needs `params.ref`: a `ref/prompt` with a \
                           `name`, or a `ref/resource` with a `uri`";
            match of("type") {
                Some("ref/prompt") => Asked::CompletePrompt {
                    name: of("name").ok_or(missing)?,
                    args,
                },
                Some("ref/resource") => Asked::CompleteTemplate {
                    template: of("uri").ok_or(missing)?,
                    args,
                },
                _ => return Err(missing),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(asked))
}
