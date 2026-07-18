// SPDX-License-Identifier: Apache-2.0
//! The **policy-as-code** rule engine (Phase 3): a richer gate than the static
//! allowlist, evaluated *after* it. Where the allowlist decides on the tool name
//! alone, a policy rule matches on the **caller** (agent), the **server**, the
//! **tool** (all globs), and the tool-call **arguments** (per-field predicates) —
//! so a policy can express "deny `delete_*` on `github` when `args.name` is a
//! `prod-*` repo" or "only `agent:ci-*` may call `deploy`".
//!
//! Rules are evaluated top-to-bottom, **first match wins**, so a specific `allow`
//! exception can precede a broad `deny`. If no rule matches, the call is allowed
//! (the deny-by-default allowlist already gated it — this engine only *adds*
//! restrictions and their exceptions). A `Deny` carries the rule's `name` as the
//! audit `rule`, so every policy denial is attributable to the line that caused it.

use crate::glob_match;
use mcpdef_core::Decision;
use serde_json::Value;

/// A rule's outcome when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// A predicate over one tool-call argument, addressed by a dotted `path` into the
/// arguments object (e.g. `"name"` or `"target.env"`; object keys only).
#[derive(Debug, Clone)]
pub struct ArgMatch {
    pub path: String,
    pub op: ArgOp,
}

/// How an [`ArgMatch`] compares the value at its path. Scalars (string / number /
/// bool) are compared by their string form; a missing value or a non-scalar
/// (array / object / null) never matches `Equals`/`Glob`/`Contains`.
#[derive(Debug, Clone)]
pub enum ArgOp {
    /// The path resolves to a present, non-null value.
    Exists,
    /// The scalar value equals this string exactly.
    Equals(String),
    /// The scalar value matches this glob (`prod-*`, `*-secret`).
    Glob(String),
    /// The scalar value contains this substring.
    Contains(String),
}

impl ArgMatch {
    fn matches(&self, args: &Value) -> bool {
        let val = resolve_path(args, &self.path);
        match &self.op {
            ArgOp::Exists => matches!(val, Some(v) if !v.is_null()),
            ArgOp::Equals(s) => scalar_str(val) == Some(s.clone()),
            ArgOp::Glob(g) => scalar_str(val).is_some_and(|v| glob_match(g, &v)),
            ArgOp::Contains(sub) => scalar_str(val).is_some_and(|v| v.contains(sub)),
        }
    }
}

/// One policy rule: match conditions (all `Some`/non-empty conditions must hold —
/// an AND) plus the [`Effect`] when they do. A `None` condition matches anything.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The rule id — becomes the audit `rule` on a deny.
    pub name: String,
    pub effect: Effect,
    /// Agent/principal globs; `None` = any caller.
    pub agents: Option<Vec<String>>,
    /// Server globs; `None` = any server.
    pub servers: Option<Vec<String>>,
    /// Tool globs; `None` = any tool.
    pub tools: Option<Vec<String>>,
    /// Argument predicates; all must match (empty = no arg constraint).
    pub args: Vec<ArgMatch>,
}

impl Rule {
    fn matches(&self, ctx: &PolicyContext) -> bool {
        glob_any(&self.agents, ctx.agent)
            && glob_any(&self.servers, ctx.server)
            && glob_any(&self.tools, ctx.tool)
            && self.args.iter().all(|a| a.matches(ctx.args))
    }
}

/// The request under evaluation: who is calling what, with which arguments.
pub struct PolicyContext<'a> {
    pub agent: &'a str,
    pub server: &'a str,
    pub tool: &'a str,
    /// The tool-call `arguments` object (or `Value::Null` when none).
    pub args: &'a Value,
}

/// An ordered set of [`Rule`]s evaluated first-match-wins over a [`PolicyContext`].
#[derive(Debug, Clone, Default)]
pub struct PolicyRules {
    rules: Vec<Rule>,
}

impl PolicyRules {
    pub fn new(rules: Vec<Rule>) -> Self {
        PolicyRules { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate `ctx` against the rules in order. The first matching rule decides;
    /// no match is [`Decision::Allow`] (the allowlist already gated the call).
    pub fn evaluate(&self, ctx: &PolicyContext) -> Decision {
        for r in &self.rules {
            if r.matches(ctx) {
                return match r.effect {
                    Effect::Allow => Decision::Allow,
                    Effect::Deny => Decision::Deny {
                        rule: r.name.clone(),
                        reason: format!(
                            "policy rule '{}' denied '{}' on '{}'",
                            r.name, ctx.tool, ctx.server
                        ),
                    },
                };
            }
        }
        Decision::Allow
    }
}

/// `true` if `pats` is `None` (matches anything) or any glob in it matches `s`.
/// An explicit `Some([])` matches nothing (an empty set of allowed patterns) — but
/// the config layer rejects empty condition lists in `Config::validate()`, so a
/// `[[policy]]` rule can only produce `None` (any) or a non-empty list.
fn glob_any(pats: &Option<Vec<String>>, s: &str) -> bool {
    match pats {
        None => true,
        Some(v) => v.iter().any(|p| glob_match(p, s)),
    }
}

/// Walk a dotted `path` (object keys only) into `v`.
fn resolve_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// The string form of a scalar JSON value; `None` for missing / array / object /
/// null (which are not matchable by the string predicates).
fn scalar_str(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(name: &str, effect: Effect) -> Rule {
        Rule {
            name: name.into(),
            effect,
            agents: None,
            servers: None,
            tools: None,
            args: vec![],
        }
    }

    fn ctx<'a>(
        agent: &'a str,
        server: &'a str,
        tool: &'a str,
        args: &'a Value,
    ) -> PolicyContext<'a> {
        PolicyContext {
            agent,
            server,
            tool,
            args,
        }
    }

    #[test]
    fn no_rules_allows() {
        let p = PolicyRules::default();
        assert!(p.evaluate(&ctx("a", "s", "t", &Value::Null)).is_allow());
    }

    #[test]
    fn deny_on_tool_and_arg_glob() {
        // Deny delete_* on github when args.name is a prod-* repo.
        let r = Rule {
            servers: Some(vec!["github".into()]),
            tools: Some(vec!["delete_*".into()]),
            args: vec![ArgMatch {
                path: "name".into(),
                op: ArgOp::Glob("prod-*".into()),
            }],
            ..rule("no-delete-prod", Effect::Deny)
        };
        let p = PolicyRules::new(vec![r]);

        let prod = json!({ "name": "prod-secrets" });
        match p.evaluate(&ctx("agent:ci", "github", "delete_repo", &prod)) {
            Decision::Deny { rule, .. } => assert_eq!(rule, "no-delete-prod"),
            other => panic!("expected deny, got {other:?}"),
        }
        // A non-prod repo does not match the arg predicate → allowed.
        let dev = json!({ "name": "dev-sandbox" });
        assert!(p
            .evaluate(&ctx("agent:ci", "github", "delete_repo", &dev))
            .is_allow());
        // A different tool does not match → allowed.
        assert!(p
            .evaluate(&ctx("agent:ci", "github", "list_issues", &prod))
            .is_allow());
    }

    #[test]
    fn first_match_wins_allow_exception_before_deny() {
        // Allow admin to deploy; deny everyone else. Order matters.
        let allow_admin = Rule {
            agents: Some(vec!["agent:admin".into()]),
            tools: Some(vec!["deploy".into()]),
            ..rule("admin-may-deploy", Effect::Allow)
        };
        let deny_deploy = Rule {
            tools: Some(vec!["deploy".into()]),
            ..rule("no-deploy", Effect::Deny)
        };
        let p = PolicyRules::new(vec![allow_admin, deny_deploy]);

        assert!(p
            .evaluate(&ctx("agent:admin", "k8s", "deploy", &Value::Null))
            .is_allow());
        match p.evaluate(&ctx("agent:ci", "k8s", "deploy", &Value::Null)) {
            Decision::Deny { rule, .. } => assert_eq!(rule, "no-deploy"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn agent_glob_scopes_a_rule() {
        let r = Rule {
            agents: Some(vec!["agent:ci-*".into()]),
            tools: Some(vec!["publish".into()]),
            ..rule("ci-cannot-publish", Effect::Deny)
        };
        let p = PolicyRules::new(vec![r]);
        assert!(!p
            .evaluate(&ctx("agent:ci-bot", "npm", "publish", &Value::Null))
            .is_allow());
        // A human agent is not matched by the agent glob → allowed.
        assert!(p
            .evaluate(&ctx("agent:alice", "npm", "publish", &Value::Null))
            .is_allow());
    }

    #[test]
    fn arg_ops_equals_exists_contains_and_scalars() {
        let args = json!({ "force": true, "path": "/etc/passwd", "count": 5 });
        // Equals against a bool (stringified).
        let force = Rule {
            args: vec![ArgMatch {
                path: "force".into(),
                op: ArgOp::Equals("true".into()),
            }],
            ..rule("no-force", Effect::Deny)
        };
        assert!(!PolicyRules::new(vec![force])
            .evaluate(&ctx("a", "s", "rm", &args))
            .is_allow());
        // Contains on a string path.
        let etc = Rule {
            args: vec![ArgMatch {
                path: "path".into(),
                op: ArgOp::Contains("/etc/".into()),
            }],
            ..rule("no-etc", Effect::Deny)
        };
        assert!(!PolicyRules::new(vec![etc])
            .evaluate(&ctx("a", "s", "read", &args))
            .is_allow());
        // Exists on a present number; and a missing path never matches.
        let has_count = Rule {
            args: vec![ArgMatch {
                path: "count".into(),
                op: ArgOp::Exists,
            }],
            ..rule("has-count", Effect::Deny)
        };
        assert!(!PolicyRules::new(vec![has_count.clone()])
            .evaluate(&ctx("a", "s", "x", &args))
            .is_allow());
        let missing = Rule {
            args: vec![ArgMatch {
                path: "nope".into(),
                op: ArgOp::Exists,
            }],
            ..rule("has-nope", Effect::Deny)
        };
        assert!(PolicyRules::new(vec![missing])
            .evaluate(&ctx("a", "s", "x", &args))
            .is_allow());
    }

    #[test]
    fn dotted_path_into_nested_object() {
        let args = json!({ "target": { "env": "production" } });
        let r = Rule {
            args: vec![ArgMatch {
                path: "target.env".into(),
                op: ArgOp::Equals("production".into()),
            }],
            ..rule("no-prod-env", Effect::Deny)
        };
        assert!(!PolicyRules::new(vec![r])
            .evaluate(&ctx("a", "s", "deploy", &args))
            .is_allow());
    }
}
