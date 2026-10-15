// SPDX-License-Identifier: Apache-2.0
//! The **policy-as-code** rule engine (Phase 3): a richer gate than the static
//! allowlist, evaluated *after* it. Where the allowlist decides on the tool name
//! alone, a policy rule matches on the **caller** (agent), the **server**, the
//! **tool** (all globs), and the tool-call **arguments** (per-field predicates) —
//! so a policy can express "deny `delete_*` on `github` when `args.name` is a
//! `prod-*` repo" or "only `agent:ci-*` may call `deploy`".
//!
//! The same rules judge a `resources/read`, by its **URI** (`uris`, URI
//! patterns), and a `prompts/get`, by the prompt's **name** (`prompts`) and its
//! arguments. A rule that names tools is about tool calls, one that names URIs
//! about reads, and one that names prompts about prompt gets; a rule that names
//! none of them is about all three. A read has no arguments, so a rule with
//! argument predicates matches no read. A completion of a resource template
//! names no one URI, so only a rule that names none of them judges it; a
//! completion of a prompt is judged as a get of the prompt.
//!
//! Rules are evaluated top-to-bottom, **first match wins**, so a specific `allow`
//! exception can precede a broad `deny`. If no rule matches, the call is allowed
//! (the deny-by-default allowlist already gated it — this engine only *adds*
//! restrictions and their exceptions). A `Deny` carries the rule's `name` as the
//! audit `rule`, so every policy denial is attributable to the line that caused it.
//!
//! A `transform` rule is not admission: it rewrites a tool call's arguments, in
//! a pass of its own before it ([`PolicyRules::transform`]), and a result, a
//! tool call's or a read's, in a pass after the upstream answers
//! ([`PolicyRules::transform_result`]). [`PolicyRules::evaluate`] passes over
//! it.

use crate::glob::UriGlob;
use crate::glob_match;
use crate::result::{self, Detector};
use crate::transform::{OnError, Transform, Transformed};
use crate::uri::Uri;
use mcpdef_core::Decision;
use serde_json::Value;
use std::sync::Arc;

/// A rule's outcome when it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
    /// Rewrite a tool call's arguments, before admission judges them, and a
    /// result, before inspect sees it.
    Transform(Transform),
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
    /// Tool globs; `None` = any tool. A rule that sets them matches tool calls
    /// only.
    pub tools: Option<Vec<String>>,
    /// URI patterns; `None` = any URI. A rule that sets them matches resource
    /// reads only.
    pub uris: Option<Vec<UriGlob>>,
    /// Prompt-name globs; `None` = any prompt. A rule that sets them matches
    /// prompt gets only.
    pub prompts: Option<Vec<String>>,
    /// Argument predicates; all must match (empty = no arg constraint). Every
    /// operator needs a value, and a read has no arguments, so a rule that
    /// sets them matches no read.
    pub args: Vec<ArgMatch>,
}

impl Rule {
    fn matches(&self, ctx: &PolicyContext) -> bool {
        // A rule that names what it is about matches that kind of request
        // only; one that names none of them matches every kind.
        let target = match ctx.target {
            Target::Tool(tool) => {
                self.uris.is_none() && self.prompts.is_none() && glob_any(&self.tools, tool)
            }
            Target::Resource(uri) => {
                self.tools.is_none()
                    && self.prompts.is_none()
                    && self
                        .uris
                        .as_ref()
                        .is_none_or(|globs| globs.iter().any(|g| g.matches(uri)))
            }
            Target::Prompt(prompt) => {
                self.tools.is_none() && self.uris.is_none() && glob_any(&self.prompts, prompt)
            }
            // A template names no one URI for `uris` to match.
            Target::Template(_) => {
                self.tools.is_none() && self.uris.is_none() && self.prompts.is_none()
            }
        };
        target
            && glob_any(&self.agents, ctx.agent)
            && glob_any(&self.servers, ctx.server)
            && self.args.iter().all(|a| a.matches(ctx.args))
    }
}

/// What a request is about: the one thing a rule's `tools`, `uris` or
/// `prompts` can name.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// A `tools/call` of this tool.
    Tool(&'a str),
    /// A `resources/read` of this URI, in normal form.
    Resource(&'a Uri),
    /// A `prompts/get` of this prompt.
    Prompt(&'a str),
    /// A `completion/complete` for this resource template, as the server
    /// writes it (`file:///{path}`).
    Template(&'a str),
}

impl Target<'_> {
    /// What a denial names: the tool, the URI, the prompt or the template.
    pub fn name(&self) -> &str {
        match self {
            Target::Tool(name) | Target::Prompt(name) | Target::Template(name) => name,
            Target::Resource(uri) => uri.as_str(),
        }
    }
}

/// The request under evaluation: who is asking for what, with which arguments.
pub struct PolicyContext<'a> {
    pub agent: &'a str,
    pub server: &'a str,
    /// What the request is about.
    pub target: Target<'a>,
    /// The request's `arguments` object, a tool call's or a prompt get's
    /// (`Value::Null` when none, and always for a read).
    pub args: &'a Value,
}

/// An ordered set of [`Rule`]s evaluated first-match-wins over a [`PolicyContext`].
#[derive(Debug, Clone, Default)]
pub struct PolicyRules {
    rules: Vec<Rule>,
    /// Whether any of them edits a tool call's arguments, and whether any
    /// edits a result, so a call pays for a pass only when there is one.
    edits_args: bool,
    edits_results: bool,
    /// What finds the secrets a result's `redact` replaces.
    secrets: Option<Secrets>,
}

/// A secret detector, shared.
#[derive(Clone)]
struct Secrets(Arc<Detector>);

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(..)")
    }
}

impl PolicyRules {
    pub fn new(rules: Vec<Rule>) -> Self {
        let edits = |of: fn(&Transform) -> bool| {
            rules.iter().any(|r| match &r.effect {
                Effect::Transform(transform) => of(transform),
                _ => false,
            })
        };
        let edits_args = edits(|t| !t.edits.is_empty());
        let edits_results = edits(|t| !t.result.is_empty());
        PolicyRules {
            rules,
            edits_args,
            edits_results,
            secrets: None,
        }
    }

    /// Find the secrets a result's `redact` replaces with `detect`. Without
    /// one, a `redact` cannot apply.
    pub fn with_secrets(mut self, detect: Arc<Detector>) -> Self {
        self.secrets = Some(Secrets(detect));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate `ctx` against the rules in order. The first matching rule decides;
    /// no match is [`Decision::Allow`] (the allowlist already gated the call).
    /// A `transform` rule decides nothing: it ran before admission.
    pub fn evaluate(&self, ctx: &PolicyContext) -> Decision {
        for r in &self.rules {
            let deny = match r.effect {
                Effect::Allow => false,
                Effect::Deny => true,
                Effect::Transform(_) => continue,
            };
            if r.matches(ctx) {
                if !deny {
                    return Decision::Allow;
                }
                return Decision::Deny {
                    rule: r.name.clone(),
                    reason: format!(
                        "policy rule '{}' denied '{}' on '{}'",
                        r.name,
                        ctx.target.name(),
                        ctx.server
                    ),
                };
            }
        }
        Decision::Allow
    }

    /// Whether any rule edits a tool call's arguments.
    pub fn transforms(&self) -> bool {
        self.edits_args
    }

    /// Whether any rule edits a result.
    pub fn transforms_results(&self) -> bool {
        self.edits_results
    }

    /// Run the `transform` rules over the `args` of a call of `tool` on
    /// `server` by `agent`. Each rule that matches the arguments as the rules
    /// before it left them makes its edits, in config order. One whose edits
    /// cannot apply denies the call under its name and stops the pass, or,
    /// when it skips, leaves the arguments as it found them.
    pub fn transform(
        &self,
        agent: &str,
        server: &str,
        tool: &str,
        args: &mut Value,
    ) -> Transformed {
        let mut done = Transformed::default();
        for rule in &self.rules {
            let Effect::Transform(transform) = &rule.effect else {
                continue;
            };
            if transform.edits.is_empty() {
                continue;
            }
            let ctx = PolicyContext {
                agent,
                server,
                target: Target::Tool(tool),
                args,
            };
            if !rule.matches(&ctx) {
                continue;
            }
            // A rule that skips keeps nothing of a try that failed; the
            // arguments of a call that is denied go nowhere.
            let applied = match transform.on_error {
                OnError::Deny => transform.apply(args),
                OnError::Skip => {
                    let mut edited = args.clone();
                    transform.apply(&mut edited).inspect(|_| *args = edited)
                }
            };
            match applied {
                Ok(changed) => {
                    done.changed |= changed;
                    done.fired.push(rule.name.clone());
                }
                Err(why) if transform.on_error == OnError::Skip => {
                    done.skipped.push((rule.name.clone(), why));
                }
                Err(why) => {
                    done.refused = Some(Decision::Deny {
                        rule: rule.name.clone(),
                        reason: format!(
                            "transform rule '{}' could not apply to '{tool}' on '{server}': {why}",
                            rule.name
                        ),
                    });
                    return done;
                }
            }
        }
        done
    }

    /// Run the `transform` rules over `result`, the upstream's answer to the
    /// request `ctx` describes: a tool call, judged by its arguments as the
    /// upstream got them, or a read. Each rule that matches makes its result
    /// edits, in config order, to what the rules before it left, keeping to
    /// `schema`, the tool's `outputSchema`. One whose edits cannot apply
    /// denies the result under its name and stops the pass, or, when it
    /// skips, leaves the result as it found it.
    pub fn transform_result(
        &self,
        ctx: &PolicyContext,
        result: &mut Value,
        schema: Option<&Value>,
    ) -> Transformed {
        let mut done = Transformed::default();
        let detect = self
            .secrets
            .as_ref()
            .map(|s| &*s.0 as &dyn Fn(&str) -> Vec<result::Detected>);
        for rule in &self.rules {
            let Effect::Transform(transform) = &rule.effect else {
                continue;
            };
            if transform.result.is_empty() || !rule.matches(ctx) {
                continue;
            }
            let edits = &transform.result;
            // As for arguments: a rule that skips keeps nothing of a try that
            // failed, and a result that is denied goes nowhere.
            let applied = match transform.on_error {
                OnError::Deny => result::apply(edits, &rule.name, result, schema, detect),
                OnError::Skip => {
                    let mut edited = result.clone();
                    result::apply(edits, &rule.name, &mut edited, schema, detect)
                        .inspect(|_| *result = edited)
                }
            };
            match applied {
                Ok(changed) => {
                    done.changed |= changed;
                    done.fired.push(rule.name.clone());
                }
                Err(why) if transform.on_error == OnError::Skip => {
                    done.skipped.push((rule.name.clone(), why));
                }
                Err(why) => {
                    done.refused = Some(Decision::Deny {
                        rule: rule.name.clone(),
                        reason: format!(
                            "transform rule '{}' could not apply to the result of '{}' on '{}': {why}",
                            rule.name,
                            ctx.target.name(),
                            ctx.server
                        ),
                    });
                    return done;
                }
            }
        }
        done
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
            uris: None,
            prompts: None,
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
            target: Target::Tool(tool),
            args,
        }
    }

    fn read<'a>(agent: &'a str, server: &'a str, uri: &'a Uri) -> PolicyContext<'a> {
        PolicyContext {
            agent,
            server,
            target: Target::Resource(uri),
            args: &Value::Null,
        }
    }

    fn get<'a>(
        agent: &'a str,
        server: &'a str,
        prompt: &'a str,
        args: &'a Value,
    ) -> PolicyContext<'a> {
        PolicyContext {
            agent,
            server,
            target: Target::Prompt(prompt),
            args,
        }
    }

    fn uris(patterns: &[&str]) -> Option<Vec<UriGlob>> {
        Some(patterns.iter().map(|p| UriGlob::new(p).unwrap()).collect())
    }

    #[test]
    fn a_uris_rule_judges_reads_and_a_tools_rule_tool_calls() {
        let secret = Rule {
            uris: uris(&["file:///srv/secret/**"]),
            ..rule("no-secret-files", Effect::Deny)
        };
        let deletes = Rule {
            tools: Some(vec!["delete_*".into()]),
            ..rule("no-deletes", Effect::Deny)
        };
        let p = PolicyRules::new(vec![secret, deletes]);
        let inside = crate::uri::normalize("file:///srv/secret/key").unwrap();
        let outside = crate::uri::normalize("file:///srv/docs/a").unwrap();
        match p.evaluate(&read("a", "fs", &inside)) {
            Decision::Deny { rule, reason } => {
                assert_eq!(rule, "no-secret-files");
                assert_eq!(
                    reason,
                    "policy rule 'no-secret-files' denied 'file:///srv/secret/key' on 'fs'"
                );
            }
            Decision::Allow => panic!("a read of a denied URI was allowed"),
        }
        assert!(p.evaluate(&read("a", "fs", &outside)).is_allow());
        // A tool rule is not about reads, even one whose glob would match "".
        let any_tool = Rule {
            tools: Some(vec!["*".into()]),
            ..rule("no-tools", Effect::Deny)
        };
        let p2 = PolicyRules::new(vec![any_tool]);
        assert!(p2.evaluate(&read("a", "fs", &outside)).is_allow());
        // And a URI rule is not about tool calls.
        assert!(p
            .evaluate(&ctx("a", "fs", "read_file", &Value::Null))
            .is_allow());
        assert!(!p
            .evaluate(&ctx("a", "fs", "delete_file", &Value::Null))
            .is_allow());
    }

    #[test]
    fn a_rule_naming_neither_tools_nor_uris_judges_both() {
        let ci = Rule {
            agents: Some(vec!["agent:ci-*".into()]),
            ..rule("no-ci", Effect::Deny)
        };
        let p = PolicyRules::new(vec![ci]);
        let uri = crate::uri::normalize("file:///srv/docs/a").unwrap();
        assert!(!p.evaluate(&read("agent:ci-1", "fs", &uri)).is_allow());
        assert!(!p
            .evaluate(&ctx("agent:ci-1", "fs", "read_file", &Value::Null))
            .is_allow());
        assert!(p.evaluate(&read("agent:dev", "fs", &uri)).is_allow());
    }

    #[test]
    fn a_prompts_rule_judges_prompt_gets_and_no_other_rule_does() {
        let reviews = Rule {
            prompts: Some(vec!["review_*".into()]),
            ..rule("no-reviews", Effect::Deny)
        };
        let p = PolicyRules::new(vec![reviews]);
        match p.evaluate(&get("a", "docs", "review_code", &Value::Null)) {
            Decision::Deny { rule, reason } => {
                assert_eq!(rule, "no-reviews");
                assert_eq!(
                    reason,
                    "policy rule 'no-reviews' denied 'review_code' on 'docs'"
                );
            }
            Decision::Allow => panic!("a get of a denied prompt was allowed"),
        }
        assert!(p
            .evaluate(&get("a", "docs", "summarize", &Value::Null))
            .is_allow());
        // A tool of the same name is not a prompt, and a read is neither.
        assert!(p
            .evaluate(&ctx("a", "docs", "review_code", &Value::Null))
            .is_allow());
        let uri = crate::uri::normalize("file:///review_code").unwrap();
        assert!(p.evaluate(&read("a", "docs", &uri)).is_allow());
        // Nor is a prompt a tool, or a URI.
        let tools = Rule {
            tools: Some(vec!["review_*".into()]),
            ..rule("no-review-tools", Effect::Deny)
        };
        let uris_rule = Rule {
            uris: uris(&["**"]),
            ..rule("no-reads", Effect::Deny)
        };
        let p2 = PolicyRules::new(vec![tools, uris_rule]);
        assert!(p2
            .evaluate(&get("a", "docs", "review_code", &Value::Null))
            .is_allow());
        // And a rule that names none of them judges a prompt get too.
        let ci = Rule {
            agents: Some(vec!["agent:ci-*".into()]),
            ..rule("no-ci", Effect::Deny)
        };
        let p3 = PolicyRules::new(vec![ci]);
        assert!(!p3
            .evaluate(&get("agent:ci-1", "docs", "summarize", &Value::Null))
            .is_allow());
    }

    #[test]
    fn only_a_rule_naming_no_kind_judges_a_template() {
        let template = |agent| PolicyContext {
            agent,
            server: "fs",
            target: Target::Template("file:///{path}"),
            args: &Value::Null,
        };
        let kinds = [
            Rule {
                tools: Some(vec!["*".into()]),
                ..rule("tools", Effect::Deny)
            },
            Rule {
                uris: uris(&["**"]),
                ..rule("uris", Effect::Deny)
            },
            Rule {
                prompts: Some(vec!["*".into()]),
                ..rule("prompts", Effect::Deny)
            },
        ];
        assert!(PolicyRules::new(kinds.to_vec())
            .evaluate(&template("a"))
            .is_allow());
        let ci = Rule {
            agents: Some(vec!["agent:ci-*".into()]),
            ..rule("no-ci", Effect::Deny)
        };
        match PolicyRules::new(vec![ci]).evaluate(&template("agent:ci-1")) {
            Decision::Deny { rule, reason } => {
                assert_eq!(rule, "no-ci");
                assert_eq!(
                    reason,
                    "policy rule 'no-ci' denied 'file:///{path}' on 'fs'"
                );
            }
            Decision::Allow => panic!("an agents-only deny let a completion through"),
        }
    }

    #[test]
    fn argument_predicates_judge_a_prompts_arguments() {
        let prod = Rule {
            prompts: Some(vec!["release_notes".into()]),
            args: vec![ArgMatch {
                path: "env".into(),
                op: ArgOp::Equals("prod".into()),
            }],
            ..rule("no-prod-notes", Effect::Deny)
        };
        let p = PolicyRules::new(vec![prod]);
        let for_prod = json!({ "env": "prod" });
        let for_dev = json!({ "env": "dev" });
        assert!(!p
            .evaluate(&get("a", "docs", "release_notes", &for_prod))
            .is_allow());
        assert!(p
            .evaluate(&get("a", "docs", "release_notes", &for_dev))
            .is_allow());
        assert!(p
            .evaluate(&get("a", "docs", "release_notes", &Value::Null))
            .is_allow());
    }

    #[test]
    fn a_rule_with_argument_predicates_matches_no_read() {
        // Every operator needs a value at its path, and a read has none: not
        // even the JSON null a tool call's missing arguments are held as.
        let ops = [
            ArgOp::Exists,
            ArgOp::Equals("null".into()),
            ArgOp::Glob("*".into()),
            ArgOp::Contains(String::new()),
        ];
        let uri = crate::uri::normalize("file:///srv/docs/a").unwrap();
        for op in ops {
            let by_arg = Rule {
                args: vec![ArgMatch {
                    path: "name".into(),
                    op,
                }],
                ..rule("by-arg", Effect::Deny)
            };
            let p = PolicyRules::new(vec![by_arg]);
            assert!(p.evaluate(&read("a", "fs", &uri)).is_allow());
            assert!(!p
                .evaluate(&ctx("a", "fs", "t", &json!({ "name": "null" })))
                .is_allow());
        }
    }

    #[test]
    fn an_allow_exception_for_a_uri_precedes_a_broad_deny() {
        let readme = Rule {
            uris: uris(&["file:///srv/secret/README.md"]),
            ..rule("readme-ok", Effect::Allow)
        };
        let secret = Rule {
            uris: uris(&["file:///srv/secret/**"]),
            ..rule("no-secret-files", Effect::Deny)
        };
        let p = PolicyRules::new(vec![readme, secret]);
        let readme = crate::uri::normalize("file:///srv/secret/README.md").unwrap();
        let key = crate::uri::normalize("file:///srv/secret/key").unwrap();
        assert!(p.evaluate(&read("a", "fs", &readme)).is_allow());
        assert!(!p.evaluate(&read("a", "fs", &key)).is_allow());
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

    /// A `*` inside a rule's globs, in its conditions and in an `args` glob.
    /// These used to match nothing, so a deny rule written this way never fired.
    #[test]
    fn stars_inside_rule_globs_match() {
        let r = Rule {
            agents: Some(vec!["agent:*-bot".into()]),
            servers: Some(vec!["k8s-*-eu".into()]),
            tools: Some(vec!["*admin*".into()]),
            args: vec![ArgMatch {
                path: "cluster".into(),
                op: ArgOp::Glob("*prod*".into()),
            }],
            ..rule("no-admin-on-prod", Effect::Deny)
        };
        let p = PolicyRules::new(vec![r]);
        let prod = json!({ "cluster": "eu-prod-1" });
        match p.evaluate(&ctx("agent:ci-bot", "k8s-west-eu", "set_admin_role", &prod)) {
            Decision::Deny { rule, .. } => assert_eq!(rule, "no-admin-on-prod"),
            other => panic!("expected deny, got {other:?}"),
        }
        let dev = json!({ "cluster": "eu-dev-1" });
        assert!(p
            .evaluate(&ctx("agent:ci-bot", "k8s-west-eu", "set_admin_role", &dev))
            .is_allow());
        assert!(p
            .evaluate(&ctx("agent:ci-bot", "k8s-west-eu", "list_pods", &prod))
            .is_allow());
    }

    use crate::transform::{ArgEdit, EditOp};

    /// A transform rule named `name` that makes `edits`, and denies when one
    /// cannot apply.
    fn transform(name: &str, edits: Vec<(&str, EditOp)>) -> Rule {
        rule(
            name,
            Effect::Transform(Transform {
                edits: edits
                    .into_iter()
                    .map(|(path, op)| ArgEdit {
                        path: path.into(),
                        op,
                    })
                    .collect(),
                result: Vec::new(),
                on_error: OnError::Deny,
            }),
        )
    }

    fn skipping(mut r: Rule) -> Rule {
        if let Effect::Transform(t) = &mut r.effect {
            t.on_error = OnError::Skip;
        }
        r
    }

    fn max(n: i64) -> EditOp {
        EditOp::Clamp {
            min: None,
            max: Some(n.into()),
        }
    }

    /// The pass over `args` for a call of `tool` on `github` by `agent:ci`.
    fn pass(rules: &PolicyRules, tool: &str, mut args: Value) -> (Value, Transformed) {
        let done = rules.transform("agent:ci", "github", tool, &mut args);
        (args, done)
    }

    #[test]
    fn transform_rules_run_in_order_each_over_what_the_last_left() {
        let staging = transform("to-staging", vec![("env", EditOp::Set(json!("staging")))]);
        // Matches only once `env` is `staging`: after the rule above.
        let mark = Rule {
            args: vec![ArgMatch {
                path: "env".into(),
                op: ArgOp::Equals("staging".into()),
            }],
            ..transform("mark-staging", vec![("marked", EditOp::Set(json!(true)))])
        };
        let rules = PolicyRules::new(vec![staging.clone(), mark.clone()]);
        let (args, done) = pass(&rules, "deploy", json!({ "env": "prod" }));
        assert_eq!(args, json!({ "env": "staging", "marked": true }));
        assert_eq!(done.fired, ["to-staging", "mark-staging"]);
        assert!(done.changed && done.refused.is_none() && done.skipped.is_empty());

        // The other way round, the second has not run when the first looks.
        let rules = PolicyRules::new(vec![mark, staging]);
        let (args, done) = pass(&rules, "deploy", json!({ "env": "prod" }));
        assert_eq!(args, json!({ "env": "staging" }));
        assert_eq!(done.fired, ["to-staging"]);
    }

    #[test]
    fn a_transform_rule_matches_as_any_rule_does() {
        let cap = Rule {
            agents: Some(vec!["agent:ci".into()]),
            servers: Some(vec!["github".into()]),
            tools: Some(vec!["list_*".into()]),
            ..transform("cap", vec![("per_page", max(100))])
        };
        let rules = PolicyRules::new(vec![cap]);
        let (args, done) = pass(&rules, "list_issues", json!({ "per_page": 500 }));
        assert_eq!(
            (args, done.fired),
            (json!({ "per_page": 100 }), vec!["cap".to_string()])
        );
        // Another tool, another server, another caller: it does not fire.
        let (args, done) = pass(&rules, "create_issue", json!({ "per_page": 500 }));
        assert_eq!((args, done.fired.len()), (json!({ "per_page": 500 }), 0));
        let mut args = json!({ "per_page": 500 });
        assert!(rules
            .transform("agent:ci", "gitlab", "list_issues", &mut args)
            .fired
            .is_empty());
        assert!(rules
            .transform("agent:human", "github", "list_issues", &mut args)
            .fired
            .is_empty());
        assert_eq!(args, json!({ "per_page": 500 }));
    }

    #[test]
    fn a_rule_fires_when_it_matches_whether_or_not_it_changes_a_value() {
        let rules = PolicyRules::new(vec![transform("cap", vec![("per_page", max(100))])]);
        let (args, done) = pass(&rules, "list_issues", json!({ "per_page": 30 }));
        assert_eq!(args, json!({ "per_page": 30 }));
        assert_eq!(done.fired, ["cap"]);
        assert!(!done.changed);
    }

    #[test]
    fn a_rule_that_changes_nothing_keeps_the_change_one_before_it_made() {
        let rules = PolicyRules::new(vec![
            transform("cap", vec![("per_page", max(100))]),
            // Fires, and finds nothing to change.
            transform("sorted", vec![("sort", EditOp::Default(json!("created")))]),
        ]);
        let (args, done) = pass(
            &rules,
            "list_issues",
            json!({ "per_page": 500, "sort": "updated" }),
        );
        assert_eq!(args, json!({ "per_page": 100, "sort": "updated" }));
        assert_eq!(done.fired, ["cap", "sorted"]);
        assert!(done.changed);
    }

    #[test]
    fn a_rule_that_cannot_apply_denies_the_call_under_its_name() {
        let rules = PolicyRules::new(vec![
            transform("first", vec![("seen", EditOp::Set(json!(true)))]),
            transform("cap", vec![("per_page", max(100))]),
            transform("never", vec![("late", EditOp::Set(json!(true)))]),
        ]);
        let (_, done) = pass(&rules, "list_issues", json!({ "per_page": "500" }));
        assert_eq!(done.fired, ["first"]);
        assert_eq!(
            done.refused,
            Some(Decision::Deny {
                rule: "cap".into(),
                reason: "transform rule 'cap' could not apply to 'list_issues' on 'github': \
                         `per_page` is a string, not a number"
                    .into(),
            })
        );
    }

    #[test]
    fn a_rule_that_skips_keeps_nothing_of_its_try() {
        let rules = PolicyRules::new(vec![
            skipping(transform(
                "half",
                vec![("seen", EditOp::Set(json!(true))), ("per_page", max(100))],
            )),
            transform("after", vec![("late", EditOp::Set(json!(true)))]),
        ]);
        let (args, done) = pass(&rules, "list_issues", json!({ "per_page": "500" }));
        // `seen` was set, then the clamp failed: the rule leaves nothing.
        assert_eq!(args, json!({ "per_page": "500", "late": true }));
        assert_eq!(done.fired, ["after"]);
        assert_eq!(
            done.skipped,
            [(
                "half".to_string(),
                "`per_page` is a string, not a number".to_string()
            )]
        );
        assert!(done.refused.is_none());
    }

    #[test]
    fn admission_passes_over_transform_rules() {
        // A transform that matches everything, ahead of a deny.
        let everything = transform("mark", vec![("marked", EditOp::Set(json!(true)))]);
        let no_deploy = Rule {
            tools: Some(vec!["deploy".into()]),
            ..rule("no-deploy", Effect::Deny)
        };
        let rules = PolicyRules::new(vec![everything.clone(), no_deploy]);
        let args = json!({});
        assert!(!rules
            .evaluate(&ctx("agent:ci", "github", "deploy", &args))
            .is_allow());
        // Nor does a transform rule on its own decide anything.
        let alone = PolicyRules::new(vec![everything]);
        assert!(alone.transforms());
        assert_eq!(
            alone.evaluate(&ctx("agent:ci", "github", "deploy", &args)),
            Decision::Allow
        );
        assert!(!PolicyRules::new(vec![rule("x", Effect::Deny)]).transforms());
        assert!(!PolicyRules::default().transforms());
    }
}
