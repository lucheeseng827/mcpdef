// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-policy` — the governance gates layered in front of an upstream tool call:
//!
//! * [`Policy`] — a static, **deny-by-default** tool allowlist per server (glob
//!   allow/deny + a gateway-wide active profile). The fast first gate.
//! * [`Rbac`] — role→grant checks for authenticated callers (Phase 2).
//! * [`PolicyRules`] — the **policy-as-code** engine (Phase 3, in [`rules`]):
//!   per-agent / per-argument `allow`/`deny` rules evaluated *after* the allowlist,
//!   first-match-wins. This is the richer evaluator the allowlist was always the
//!   stub for; the [`Decision`] type and the gateway call site are unchanged.
//!   Its `transform` rules rewrite a tool call's arguments before admission
//!   judges them ([`Transform`]).
//!
//! Every gate matches with the one engine in [`glob`]: names by its names
//! dialect, and resource URIs, put in normal form by [`uri`], by its URI
//! dialect.
//!
//! Transforms of a call's result are the remaining Phase-3 step.

use mcpdef_core::Decision;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod glob;
mod result;
mod rules;
mod transform;
pub mod uri;
use glob::UriGlob;
pub use result::{redact_result, Detected, Detector, ResultEdit, Unredacted};
pub use rules::{ArgMatch, ArgOp, Effect, PolicyContext, PolicyRules, Rule, Target};
pub use transform::{ArgEdit, EditOp, OnError, Transform, Transformed};
use uri::Uri;

/// The allow/deny rules for one server — also the shape of a reusable **named
/// profile** (see `mcpdef.toml` `[profile.<name>]`), which is just a `ServerPolicy`
/// a server can reference or the gateway can apply globally.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerPolicy {
    /// If `Some`, only tools matching one of these patterns are permitted
    /// (deny-by-default). If `None`, every tool passes the allow gate (still
    /// subject to `deny`). Entries are **globs** (`get_*`, `*_ro`), so a profile
    /// can scope a whole family of tools with one line.
    #[serde(default)]
    pub allow_tools: Option<Vec<String>>,
    /// Glob denies (e.g. `delete_*`), evaluated *before* the allow gate — a deny
    /// match always wins.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl ServerPolicy {
    /// `None` if `tool` is permitted by this policy; `Some((rule, reason))` if it
    /// is denied. Deny globs win over the allowlist; both sides are globs.
    pub fn deny_reason(&self, tool: &str) -> Option<(&'static str, String)> {
        for pattern in &self.deny {
            if glob_match(pattern, tool) {
                return Some((
                    "deny-glob",
                    format!("tool '{tool}' matches deny pattern '{pattern}'"),
                ));
            }
        }
        if let Some(allow) = &self.allow_tools {
            if !allow.iter().any(|p| glob_match(p, tool)) {
                return Some((
                    "not-on-allowlist",
                    format!("tool '{tool}' is not on the allowlist"),
                ));
            }
        }
        None
    }
}

/// What one server may expose of its resources: the URIs a `resources/read`
/// may name, and the URI templates `resources/templates/list` may show.
///
/// Both empty exposes nothing, and that is what a server with no `resources`
/// list gets. Unlike tools, where no allowlist exposes every tool, resources
/// are data (files, rows, documents), so none is exposed until one is named.
#[derive(Debug, Clone, Default)]
pub struct ResourcePolicy {
    /// URI globs, in the URI dialect: a read is allowed only for a URI one of
    /// them matches, once in normal form.
    pub uris: Vec<UriGlob>,
    /// Template globs, in the names dialect, matched against each template as
    /// the server writes it (`file:///{path}`). Showing a template allows no
    /// read: the URI a client fills it in to must still match `uris`.
    pub templates: Vec<String>,
}

impl ResourcePolicy {
    /// Whether it exposes nothing at all.
    pub fn is_empty(&self) -> bool {
        self.uris.is_empty() && self.templates.is_empty()
    }

    /// Whether a read of `uri`, in normal form, is allowed.
    pub fn allows(&self, uri: &Uri) -> bool {
        self.uris.iter().any(|glob| glob.matches(uri))
    }

    /// Whether `template` may be shown.
    pub fn shows_template(&self, template: &str) -> bool {
        self.templates
            .iter()
            .any(|pattern| glob_match(pattern, template))
    }
}

/// The set of per-server allowlists, plus an optional gateway-wide **active
/// profile**. A server with no entry is *not governed* and is denied
/// (fail-closed) — you cannot call through MCPdef to a server it was never told
/// about.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    servers: HashMap<String, ServerPolicy>,
    /// An optional gateway-wide profile layered on top of every server's policy:
    /// a tool is exposed only if it passes **both** the server's rules and this
    /// active profile. This is how a gateway is scoped to e.g. a read-only tool
    /// set — cutting the tool surface (and the prompt-context tax) an agent sees,
    /// the #1 multi-server pain. `None` means no extra filter.
    active: Option<ServerPolicy>,
    /// Each server's resource allowlists. A server with no entry exposes no
    /// resource.
    resources: HashMap<String, ResourcePolicy>,
    /// Each server's prompt allowlist, as name globs. A server with no entry,
    /// or an empty one, exposes no prompt.
    prompts: HashMap<String, Vec<String>>,
}

impl Policy {
    pub fn new() -> Self {
        Policy::default()
    }

    pub fn from_map(servers: HashMap<String, ServerPolicy>) -> Self {
        Policy {
            servers,
            active: None,
            resources: HashMap::new(),
            prompts: HashMap::new(),
        }
    }

    /// Layer a gateway-wide active profile over every server's policy.
    pub fn with_active(mut self, active: Option<ServerPolicy>) -> Self {
        self.active = active;
        self
    }

    pub fn insert(&mut self, server: impl Into<String>, policy: ServerPolicy) {
        self.servers.insert(server.into(), policy);
    }

    pub fn is_governed(&self, server: &str) -> bool {
        self.servers.contains_key(server)
    }

    /// Decide a `tools/call` for `tool` on `server`. Deny-by-default: an unknown
    /// server, an off-allowlist tool, a deny-glob match, or a tool outside the
    /// active profile all return [`Decision::Deny`] with a machine-readable
    /// `rule` and a human `reason`.
    pub fn decide_tool(&self, server: &str, tool: &str) -> Decision {
        let Some(sp) = self.servers.get(server) else {
            return Decision::Deny {
                rule: "unknown-server".into(),
                reason: format!("server '{server}' is not governed by MCPdef"),
            };
        };

        if let Some((rule, reason)) = sp.deny_reason(tool) {
            return Decision::Deny {
                rule: rule.into(),
                reason: format!("{reason} for '{server}'"),
            };
        }

        // The gateway-wide active profile is an additional gate: a tool the
        // server would allow can still be hidden if the active profile excludes it.
        if let Some(active) = &self.active {
            if active.deny_reason(tool).is_some() {
                return Decision::Deny {
                    rule: "not-in-active-profile".into(),
                    reason: format!("tool '{tool}' is not in the gateway's active profile"),
                };
            }
        }

        Decision::Allow
    }

    /// Whether `tool` on `server` is exposed (used to filter an aggregated
    /// `tools/list` so denied tools never appear to the client).
    pub fn tool_is_exposed(&self, server: &str, tool: &str) -> bool {
        self.decide_tool(server, tool).is_allow()
    }

    /// Whether `server`'s allowlist names `tool` itself, not through a pattern.
    ///
    /// Says which server a tool belongs to when the server has not listed its
    /// tools, as when it never started. A pattern, or no allowlist, claims no
    /// tool: `get_*` or allow-all would claim names that belong elsewhere.
    pub fn lists_tool(&self, server: &str, tool: &str) -> bool {
        self.servers
            .get(server)
            .and_then(|sp| sp.allow_tools.as_ref())
            .is_some_and(|allow| allow.iter().any(|entry| entry == tool))
    }

    /// Say what `server` may expose of its resources.
    pub fn insert_resources(&mut self, server: impl Into<String>, resources: ResourcePolicy) {
        self.resources.insert(server.into(), resources);
    }

    /// What `server` may expose of its resources: nothing, if it has no entry.
    pub fn resources(&self, server: &str) -> Option<&ResourcePolicy> {
        self.resources.get(server).filter(|r| !r.is_empty())
    }

    /// Whether any governed server exposes a resource or a template, and so
    /// whether the gateway offers resources at all.
    pub fn exposes_resources(&self) -> bool {
        self.resources
            .iter()
            .any(|(server, r)| self.is_governed(server) && !r.is_empty())
    }

    /// Whether any governed server shows a resource template, and so whether
    /// there is one to ask completions of.
    pub fn exposes_templates(&self) -> bool {
        self.resources
            .iter()
            .any(|(server, r)| self.is_governed(server) && !r.templates.is_empty())
    }

    /// Decide a `resources/read` of `uri`, in normal form, on `server`.
    /// Deny-by-default: an unknown server, or a URI none of its `resources`
    /// globs matches, is denied.
    pub fn decide_resource(&self, server: &str, uri: &Uri) -> Decision {
        if !self.is_governed(server) {
            return Decision::Deny {
                rule: "unknown-server".into(),
                reason: format!("server '{server}' is not governed by MCPdef"),
            };
        }
        if self.resources(server).is_some_and(|r| r.allows(uri)) {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "resource-not-allowed".into(),
            reason: format!("resource '{uri}' is not on the resource allowlist of '{server}'"),
        }
    }

    /// Decide a `completion/complete` for the resource template `template` on
    /// `server`: allowed if its `resource_templates` shows the template.
    pub fn decide_template(&self, server: &str, template: &str) -> Decision {
        if !self.is_governed(server) {
            return Decision::Deny {
                rule: "unknown-server".into(),
                reason: format!("server '{server}' is not governed by MCPdef"),
            };
        }
        if self
            .resources(server)
            .is_some_and(|r| r.shows_template(template))
        {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "template-not-allowed".into(),
            reason: format!(
                "resource template '{template}' is not on the template allowlist of '{server}'"
            ),
        }
    }

    /// Say which prompts `server` may expose, as name globs.
    pub fn insert_prompts(&mut self, server: impl Into<String>, prompts: Vec<String>) {
        self.prompts.insert(server.into(), prompts);
    }

    /// The name globs of the prompts `server` may expose: `None` when it
    /// exposes none.
    pub fn prompts(&self, server: &str) -> Option<&[String]> {
        self.prompts
            .get(server)
            .map(Vec::as_slice)
            .filter(|globs| !globs.is_empty())
    }

    /// Whether `server` may expose the prompt `name`.
    pub fn shows_prompt(&self, server: &str, name: &str) -> bool {
        self.prompts(server)
            .is_some_and(|globs| globs.iter().any(|glob| glob_match(glob, name)))
    }

    /// Whether any governed server exposes a prompt, and so whether the
    /// gateway offers prompts at all.
    pub fn exposes_prompts(&self) -> bool {
        self.prompts
            .iter()
            .any(|(server, globs)| self.is_governed(server) && !globs.is_empty())
    }

    /// Decide a `prompts/get` of `name` on `server`. Deny-by-default: an
    /// unknown server, or a name none of its `prompts` globs matches, is
    /// denied.
    pub fn decide_prompt(&self, server: &str, name: &str) -> Decision {
        if !self.is_governed(server) {
            return Decision::Deny {
                rule: "unknown-server".into(),
                reason: format!("server '{server}' is not governed by MCPdef"),
            };
        }
        if self.shows_prompt(server, name) {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "prompt-not-allowed".into(),
            reason: format!("prompt '{name}' is not on the prompt allowlist of '{server}'"),
        }
    }
}

/// Role-based access control layered **over** the allowlist: once a call passes
/// the static allowlist, an authenticated caller must also hold a role that
/// grants `(server, tool)`. This is the coarse identity gate (Phase 2); the
/// fine, arg-level logic is the future policy-as-code engine (Phase 3).
///
/// A role is a set of `(server-glob, tool-glob)` grants. A caller "holds" a role
/// when the role's name appears among the caller's **scopes ∪ roles** claims, so
/// an IdP can drive grants by issuing scopes/roles — no per-user config in MCPdef.
#[derive(Debug, Clone, Default)]
pub struct Rbac {
    roles: HashMap<String, Vec<(String, String)>>,
    /// Each role's `(server-glob, URI pattern)` grants, for `resources/read`.
    resource_roles: HashMap<String, Vec<(String, UriGlob)>>,
    /// Each role's `(server-glob, prompt-glob)` grants, for `prompts/get`.
    prompt_roles: HashMap<String, Vec<(String, String)>>,
    /// The roles client certificates hold: each `(identity-glob, roles)`.
    cert_map: Vec<(String, Vec<String>)>,
}

impl Rbac {
    pub fn new() -> Self {
        Rbac::default()
    }

    /// Define a role from `(server-glob, tool-glob)` grants.
    pub fn insert_role(&mut self, name: impl Into<String>, grants: Vec<(String, String)>) {
        self.roles.insert(name.into(), grants);
    }

    /// Give a role `(server-glob, URI pattern)` grants for resource reads.
    pub fn insert_resource_grants(
        &mut self,
        name: impl Into<String>,
        grants: Vec<(String, UriGlob)>,
    ) {
        self.resource_roles.insert(name.into(), grants);
    }

    /// Give a role `(server-glob, prompt-glob)` grants for prompt gets.
    pub fn insert_prompt_grants(&mut self, name: impl Into<String>, grants: Vec<(String, String)>) {
        self.prompt_roles.insert(name.into(), grants);
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty() && self.resource_roles.is_empty() && self.prompt_roles.is_empty()
    }

    /// Give a client certificate whose identity `pattern` matches, exactly
    /// or as a glob, the roles `roles`.
    pub fn map_certificates(&mut self, pattern: impl Into<String>, roles: Vec<String>) {
        self.cert_map.push((pattern.into(), roles));
    }

    /// The roles a client certificate whose identity is `identity` holds:
    /// those of every mapping it matches. None if it matches none: a
    /// certificate is never given a role by default.
    pub fn certificate_roles<'a>(&'a self, identity: &'a str) -> impl Iterator<Item = &'a str> {
        self.cert_map
            .iter()
            .filter(move |(pattern, _)| glob_match(pattern, identity))
            .flat_map(|(_, roles)| roles.iter().map(String::as_str))
    }

    /// Decide whether a caller holding `subjects` may ask for completions of the
    /// resource template `template` on `server`. A template names no one URI
    /// for a grant to match, so a role that grants any resource on `server`
    /// is enough; each URI a completion suggests is judged when it is read.
    pub fn decide_template<'a>(
        &self,
        subjects: impl Iterator<Item = &'a str>,
        server: &str,
        template: &str,
    ) -> Decision {
        let granted = subjects
            .filter_map(|subject| self.resource_roles.get(subject))
            .any(|grants| {
                grants
                    .iter()
                    .any(|(server_glob, _)| glob_match(server_glob, server))
            });
        if granted {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "rbac".into(),
            reason: format!("no role grants a resource on '{server}' to complete '{template}'"),
        }
    }

    /// Decide whether a caller holding `subjects` may get the prompt `name` on
    /// `server`. Deny-by-default, as for tools: allowed only if some held role
    /// grants a matching `(server-glob, prompt-glob)`.
    pub fn decide_prompt<'a>(
        &self,
        subjects: impl Iterator<Item = &'a str>,
        server: &str,
        name: &str,
    ) -> Decision {
        if granted(&self.prompt_roles, subjects, server, name) {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "rbac".into(),
            reason: format!("no role grants prompt '{name}' on '{server}'"),
        }
    }

    /// Decide whether a caller holding `subjects` may read `uri`, in normal
    /// form, on `server`. Deny-by-default, as for tools: allowed only if some
    /// held role grants a matching `(server-glob, URI pattern)`.
    pub fn decide_resource<'a>(
        &self,
        subjects: impl Iterator<Item = &'a str>,
        server: &str,
        uri: &Uri,
    ) -> Decision {
        for subject in subjects {
            if let Some(grants) = self.resource_roles.get(subject) {
                if grants.iter().any(|(server_glob, uri_glob)| {
                    glob_match(server_glob, server) && uri_glob.matches(uri)
                }) {
                    return Decision::Allow;
                }
            }
        }
        Decision::Deny {
            rule: "rbac".into(),
            reason: format!("no role grants '{uri}' on '{server}'"),
        }
    }

    /// Decide whether a caller holding `subjects` (its scopes ∪ roles) may call
    /// `tool` on `server`. Deny-by-default: allowed only if some held role grants
    /// a matching `(server-glob, tool-glob)`.
    pub fn decide<'a>(
        &self,
        subjects: impl Iterator<Item = &'a str>,
        server: &str,
        tool: &str,
    ) -> Decision {
        if granted(&self.roles, subjects, server, tool) {
            return Decision::Allow;
        }
        Decision::Deny {
            rule: "rbac".into(),
            reason: format!("no role grants '{tool}' on '{server}'"),
        }
    }
}

/// Whether a role among `subjects` holds a `(server-glob, name-glob)` grant
/// matching `server` and `name`.
fn granted<'a>(
    roles: &HashMap<String, Vec<(String, String)>>,
    subjects: impl Iterator<Item = &'a str>,
    server: &str,
    name: &str,
) -> bool {
    subjects
        .filter_map(|subject| roles.get(subject))
        .any(|grants| {
            grants.iter().any(|(server_glob, name_glob)| {
                glob_match(server_glob, server) && glob_match(name_glob, name)
            })
        })
}

/// The names dialect of the one glob engine, under the name its callers
/// here have always used: see [`glob::names`].
pub(crate) use glob::names as glob_match;

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        let mut p = Policy::new();
        p.insert(
            "github",
            ServerPolicy {
                allow_tools: Some(vec!["list_issues".into(), "get_file_contents".into()]),
                deny: vec!["delete_*".into()],
            },
        );
        p.insert(
            "files",
            ServerPolicy {
                allow_tools: None, // all tools allowed except denies
                deny: vec!["*_secret".into()],
            },
        );
        p
    }

    #[test]
    fn allows_listed_tool() {
        assert!(policy().decide_tool("github", "list_issues").is_allow());
    }

    #[test]
    fn denies_off_allowlist_tool() {
        match policy().decide_tool("github", "create_issue") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "not-on-allowlist"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn deny_glob_beats_allowlist() {
        // even if a delete_* tool were allow-listed, the deny glob wins
        let mut p = Policy::new();
        p.insert(
            "github",
            ServerPolicy {
                allow_tools: Some(vec!["delete_repo".into()]),
                deny: vec!["delete_*".into()],
            },
        );
        match p.decide_tool("github", "delete_repo") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "deny-glob"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn unknown_server_is_denied() {
        match policy().decide_tool("rogue", "anything") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "unknown-server"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn leading_star_suffix_glob() {
        match policy().decide_tool("files", "read_secret") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "deny-glob"),
            other => panic!("expected deny, got {other:?}"),
        }
        assert!(policy().decide_tool("files", "read_file").is_allow());
    }

    #[test]
    fn allowlist_entries_are_globs() {
        // A profile-style allowlist scopes a whole family with one pattern.
        let mut p = Policy::new();
        p.insert(
            "gh",
            ServerPolicy {
                allow_tools: Some(vec!["get_*".into(), "list_*".into()]),
                deny: vec![],
            },
        );
        assert!(p.decide_tool("gh", "get_file").is_allow());
        assert!(p.decide_tool("gh", "list_issues").is_allow());
        match p.decide_tool("gh", "create_issue") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "not-on-allowlist"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn rbac_grants_by_role_with_globs() {
        let mut rbac = Rbac::new();
        rbac.insert_role(
            "reader",
            vec![
                ("github".into(), "get_*".into()),
                ("*".into(), "search".into()),
            ],
        );
        rbac.insert_role("admin", vec![("*".into(), "*".into())]);

        // reader holds get_* on github and search anywhere…
        assert!(rbac
            .decide(["reader"].into_iter(), "github", "get_file")
            .is_allow());
        assert!(rbac
            .decide(["reader"].into_iter(), "db", "search")
            .is_allow());
        // …but not delete on github.
        match rbac.decide(["reader"].into_iter(), "github", "delete_repo") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "rbac"),
            other => panic!("expected rbac deny, got {other:?}"),
        }
        // admin holds everything; a caller with no matching role is denied.
        assert!(rbac
            .decide(["admin"].into_iter(), "github", "delete_repo")
            .is_allow());
        assert!(!rbac
            .decide(["nobody"].into_iter(), "github", "get_file")
            .is_allow());
        // multiple subjects (scopes ∪ roles): any matching role grants.
        assert!(rbac
            .decide(["other", "reader"].into_iter(), "github", "get_x")
            .is_allow());
    }

    #[test]
    fn active_profile_filters_on_top_of_server_policy() {
        // The server itself allows everything, but a read-only active profile is
        // layered over the gateway, so only get_*/list_* survive.
        let mut servers = std::collections::HashMap::new();
        servers.insert(
            "gh".to_string(),
            ServerPolicy {
                allow_tools: None, // server allows all
                deny: vec![],
            },
        );
        let readonly = ServerPolicy {
            allow_tools: Some(vec!["get_*".into(), "list_*".into()]),
            deny: vec![],
        };
        let p = Policy::from_map(servers).with_active(Some(readonly));

        assert!(p.decide_tool("gh", "get_file").is_allow());
        match p.decide_tool("gh", "create_issue") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "not-in-active-profile"),
            other => panic!("expected active-profile deny, got {other:?}"),
        }
        // A server-level deny still wins over (and short-circuits) the active gate.
        let mut servers2 = std::collections::HashMap::new();
        servers2.insert(
            "gh".to_string(),
            ServerPolicy {
                allow_tools: None,
                deny: vec!["get_secrets".into()],
            },
        );
        let p2 = Policy::from_map(servers2).with_active(Some(ServerPolicy {
            allow_tools: Some(vec!["get_*".into()]),
            deny: vec![],
        }));
        match p2.decide_tool("gh", "get_secrets") {
            Decision::Deny { rule, .. } => assert_eq!(rule, "deny-glob"),
            other => panic!("expected server deny-glob, got {other:?}"),
        }
    }

    #[test]
    fn a_star_at_both_ends_matches_anywhere_in_the_name() {
        for name in ["delete_file", "rm_delete_all", "delete", "undelete"] {
            assert!(glob_match("*delete*", name), "{name}");
        }
        for name in ["remove_file", "Delete_file", "delet", ""] {
            assert!(!glob_match("*delete*", name), "{name}");
        }
    }

    #[test]
    fn a_middle_star_matches_any_run_including_none() {
        assert!(glob_match("get_*_info", "get_user_info"));
        assert!(glob_match("get_*_info", "get_a_b_info"));
        assert!(glob_match("get_*_info", "get__info"));
        // The fixed pieces are anchored and may not overlap.
        for name in ["get_info", "get_user_info_x", "xget_user_info", "get_user"] {
            assert!(!glob_match("get_*_info", name), "{name}");
        }
    }

    #[test]
    fn several_stars_match_their_pieces_in_order() {
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(glob_match("a*b*c", "abcbc"));
        assert!(!glob_match("a*b*c", "ac"));
        assert!(!glob_match("a*b*c", "acb"));
        assert!(glob_match("*_*_*", "x_y_z"));
        assert!(!glob_match("*_*_*", "x_y"));
        // Adjacent stars are one star.
        assert!(glob_match("a**b", "ab"));
        assert!(glob_match("**", "anything"));
    }

    #[test]
    fn a_lone_star_matches_everything_and_an_empty_pattern_only_nothing() {
        for name in ["", "x", "delete_repo", "ツール"] {
            assert!(glob_match("*", name), "{name:?}");
        }
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(!glob_match("a*", ""));
        assert!(!glob_match("*a", ""));
    }

    #[test]
    fn exact_prefix_and_suffix_patterns_match_as_before() {
        assert!(glob_match("list_issues", "list_issues"));
        assert!(!glob_match("list_issues", "list_issues2"));
        assert!(glob_match("delete_*", "delete_repo"));
        assert!(!glob_match("delete_*", "undelete_repo"));
        assert!(glob_match("*_secret", "db_secret"));
        assert!(!glob_match("*_secret", "db_secret_ro"));
    }

    #[test]
    fn non_ascii_names_match_by_character() {
        assert!(glob_match("ツ*ル", "ツール"));
        assert!(glob_match("*ü*", "grün"));
        assert!(glob_match("données_*", "données_clients"));
        assert!(glob_match("*é", "café"));
        // `é` and `©` share their last UTF-8 byte; only a whole `é` may match.
        assert!(!glob_match("*é", "a©"));
        assert!(!glob_match("*é*", "a©b"));
    }

    #[test]
    fn question_marks_and_brackets_match_only_themselves() {
        assert!(glob_match("get_?", "get_?"));
        assert!(!glob_match("get_?", "get_x"));
        assert!(glob_match("[ab]*", "[ab]_tool"));
        assert!(!glob_match("[ab]*", "a_tool"));
    }

    /// Every pattern and name up to four characters, over an alphabet with
    /// multi-byte characters and the would-be metacharacters, against a
    /// character-by-character reference.
    #[test]
    fn agrees_with_a_reference_matcher_on_every_short_input() {
        fn reference(pattern: &str, name: &str) -> bool {
            let p: Vec<char> = pattern.chars().collect();
            let s: Vec<char> = name.chars().collect();
            // m[i][j]: the first i pattern characters match the first j name ones.
            let mut m = vec![vec![false; s.len() + 1]; p.len() + 1];
            m[0][0] = true;
            for i in 1..=p.len() {
                for j in 0..=s.len() {
                    m[i][j] = if p[i - 1] == '*' {
                        m[i - 1][j] || (j > 0 && m[i][j - 1])
                    } else {
                        j > 0 && m[i - 1][j - 1] && p[i - 1] == s[j - 1]
                    };
                }
            }
            m[p.len()][s.len()]
        }
        let alphabet = ['a', 'é', '©', '?', '*'];
        let mut all = vec![String::new()];
        let mut longest = vec![String::new()];
        for _ in 0..4 {
            longest = longest
                .iter()
                .flat_map(|s| {
                    alphabet.iter().map(move |c| {
                        let mut t = s.clone();
                        t.push(*c);
                        t
                    })
                })
                .collect();
            all.extend(longest.iter().cloned());
        }
        for pattern in &all {
            for name in &all {
                assert_eq!(
                    glob_match(pattern, name),
                    reference(pattern, name),
                    "pattern {pattern:?} against {name:?}"
                );
            }
        }
    }

    /// The fail-open this matcher fixes: a server with no allowlist and a deny
    /// pattern starred at both ends denied nothing.
    #[test]
    fn a_deny_starred_at_both_ends_denies_without_an_allowlist() {
        let mut p = Policy::new();
        p.insert(
            "fs",
            ServerPolicy {
                allow_tools: None,
                deny: vec!["*delete*".into()],
            },
        );
        for tool in ["delete_file", "rm_delete_all", "delete"] {
            match p.decide_tool("fs", tool) {
                Decision::Deny { rule, .. } => assert_eq!(rule, "deny-glob", "{tool}"),
                other => panic!("{tool}: expected deny-glob, got {other:?}"),
            }
        }
        assert!(p.decide_tool("fs", "read_file").is_allow());
    }

    #[test]
    fn only_a_literal_allowlist_entry_claims_a_tool() {
        let mut p = Policy::new();
        let allow = |tools: &[&str]| ServerPolicy {
            allow_tools: Some(tools.iter().map(|t| t.to_string()).collect()),
            deny: vec![],
        };
        p.insert("gh", allow(&["create_issue", "get_*"]));
        p.insert("fs", ServerPolicy::default());
        assert!(p.lists_tool("gh", "create_issue"));
        // A pattern matches the tool without claiming it.
        assert!(p.tool_is_exposed("gh", "get_repo"));
        assert!(!p.lists_tool("gh", "get_repo"));
        // Allow-all claims nothing, and an unknown server claims nothing.
        assert!(!p.lists_tool("fs", "read_file"));
        assert!(!p.lists_tool("nope", "create_issue"));
    }

    fn resource_policy(uris: &[&str], templates: &[&str]) -> ResourcePolicy {
        ResourcePolicy {
            uris: uris.iter().map(|p| UriGlob::new(p).unwrap()).collect(),
            templates: templates.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn a_resource_is_allowed_only_by_its_own_servers_allowlist() {
        let mut p = Policy::new();
        p.insert("docs", ServerPolicy::default());
        p.insert("other", ServerPolicy::default());
        p.insert_resources("docs", resource_policy(&["file:///srv/docs/**"], &[]));
        let uri = |s: &str| uri::normalize(s).unwrap();
        assert!(p
            .decide_resource("docs", &uri("file:///srv/docs/a/b"))
            .is_allow());
        let rule = |server: &str, u: &str| match p.decide_resource(server, &uri(u)) {
            Decision::Deny { rule, .. } => rule,
            Decision::Allow => panic!("{server} {u}: allowed"),
        };
        assert_eq!(rule("docs", "file:///srv/other"), "resource-not-allowed");
        // A server with no list allows nothing, and an ungoverned one is unknown.
        assert_eq!(rule("other", "file:///srv/docs/a"), "resource-not-allowed");
        assert_eq!(rule("nope", "file:///srv/docs/a"), "unknown-server");
    }

    #[test]
    fn resources_are_offered_only_when_a_governed_server_exposes_one() {
        let mut p = Policy::new();
        p.insert("a", ServerPolicy::default());
        assert!(!p.exposes_resources());
        p.insert_resources("a", ResourcePolicy::default());
        assert!(!p.exposes_resources(), "an empty policy exposes nothing");
        assert!(p.resources("a").is_none());
        p.insert_resources("ghost", resource_policy(&["file:///**"], &[]));
        assert!(
            !p.exposes_resources(),
            "an ungoverned server exposes nothing"
        );
        p.insert_resources("a", resource_policy(&[], &["file:///{*}"]));
        assert!(p.exposes_resources());
        let templates = p.resources("a").unwrap();
        assert!(templates.shows_template("file:///{path}"));
        assert!(!templates.shows_template("https://h/{path}"));
        assert!(!templates.allows(&uri::normalize("file:///x").unwrap()));
    }

    #[test]
    fn a_prompt_is_exposed_only_by_its_own_servers_allowlist() {
        let mut p = Policy::new();
        p.insert("docs", ServerPolicy::default());
        p.insert("other", ServerPolicy::default());
        p.insert_prompts("docs", vec!["review_*".into(), "summarize".into()]);
        assert!(p.decide_prompt("docs", "review_code").is_allow());
        assert!(p.decide_prompt("docs", "summarize").is_allow());
        let rule = |server: &str, name: &str| match p.decide_prompt(server, name) {
            Decision::Deny { rule, reason } => {
                if rule == "prompt-not-allowed" {
                    assert_eq!(
                        reason,
                        format!("prompt '{name}' is not on the prompt allowlist of '{server}'")
                    );
                }
                rule
            }
            Decision::Allow => panic!("{server} {name}: allowed"),
        };
        assert_eq!(rule("docs", "summarize_all"), "prompt-not-allowed");
        // A server with no list shows nothing, and an ungoverned one is unknown.
        assert_eq!(rule("other", "review_code"), "prompt-not-allowed");
        assert_eq!(rule("nope", "review_code"), "unknown-server");
    }

    #[test]
    fn prompts_are_offered_only_when_a_governed_server_exposes_one() {
        let mut p = Policy::new();
        p.insert("a", ServerPolicy::default());
        assert!(!p.exposes_prompts());
        p.insert_prompts("a", vec![]);
        assert!(!p.exposes_prompts(), "an empty list exposes nothing");
        assert!(p.prompts("a").is_none());
        p.insert_prompts("ghost", vec!["*".into()]);
        assert!(!p.exposes_prompts(), "an ungoverned server exposes nothing");
        p.insert_prompts("a", vec!["*".into()]);
        assert!(p.exposes_prompts());
        assert_eq!(p.prompts("a"), Some(&["*".to_string()][..]));
    }

    #[test]
    fn a_prompt_get_needs_a_role_that_grants_the_prompt() {
        let mut rbac = Rbac::new();
        rbac.insert_role("writer", vec![("*".into(), "*".into())]);
        rbac.insert_prompt_grants("writer", vec![("docs".into(), "review_*".into())]);
        let held = || ["writer"].into_iter();
        assert!(rbac.decide_prompt(held(), "docs", "review_code").is_allow());
        // Another server, another prompt, or none of the caller's roles: denied.
        for (subjects, server, name) in [
            (vec!["writer"], "wiki", "review_code"),
            (vec!["writer"], "docs", "summarize"),
            (vec!["reader"], "docs", "review_code"),
        ] {
            match rbac.decide_prompt(subjects.into_iter(), server, name) {
                Decision::Deny { rule, reason } => {
                    assert_eq!(rule, "rbac");
                    assert_eq!(
                        reason,
                        format!("no role grants prompt '{name}' on '{server}'")
                    );
                }
                Decision::Allow => panic!("{server} {name} allowed"),
            }
        }
        // A grant of every tool grants no prompt, and a prompt grant no tool.
        let mut tools_only = Rbac::new();
        tools_only.insert_role("writer", vec![("*".into(), "*".into())]);
        assert!(!tools_only
            .decide_prompt(held(), "docs", "review_code")
            .is_allow());
        let mut prompts_only = Rbac::new();
        prompts_only.insert_prompt_grants("p", vec![("*".into(), "*".into())]);
        assert!(!prompts_only
            .decide(["p"].into_iter(), "docs", "review_code")
            .is_allow());
        // Grants alone make a model that is not empty.
        let mut grants_only = Rbac::new();
        grants_only.insert_prompt_grants("r", vec![]);
        assert!(!grants_only.is_empty());
    }

    #[test]
    fn a_template_is_completed_only_where_it_is_shown_and_a_role_grants_its_server() {
        let mut p = Policy::new();
        p.insert("fs", ServerPolicy::default());
        p.insert("db", ServerPolicy::default());
        p.insert_resources("db", resource_policy(&["db://orders/**"], &[]));
        assert!(!p.exposes_templates(), "URIs alone show no template");
        p.insert_resources("fs", resource_policy(&[], &["file:///{*}"]));
        assert!(p.exposes_templates());
        assert!(p.decide_template("fs", "file:///{path}").is_allow());
        let rule = |server: &str, template: &str| match p.decide_template(server, template) {
            Decision::Deny { rule, .. } => rule,
            Decision::Allow => panic!("{server} {template}: allowed"),
        };
        assert_eq!(rule("fs", "db://{table}"), "template-not-allowed");
        assert_eq!(rule("db", "file:///{path}"), "template-not-allowed");
        assert_eq!(rule("nope", "file:///{path}"), "unknown-server");

        let mut rbac = Rbac::new();
        rbac.insert_resource_grants(
            "reader",
            vec![("fs".into(), UriGlob::new("file:///srv/docs/**").unwrap())],
        );
        rbac.insert_prompt_grants("writer", vec![("*".into(), "*".into())]);
        assert!(rbac
            .decide_template(["reader"].into_iter(), "fs", "file:///{path}")
            .is_allow());
        for (role, server) in [("reader", "db"), ("writer", "fs")] {
            match rbac.decide_template([role].into_iter(), server, "file:///{path}") {
                Decision::Deny { rule, reason } => {
                    assert_eq!(rule, "rbac");
                    assert_eq!(
                        reason,
                        format!("no role grants a resource on '{server}' to complete 'file:///{{path}}'")
                    );
                }
                Decision::Allow => panic!("{role} on {server}: allowed"),
            }
        }
    }

    #[test]
    fn a_resource_read_needs_a_role_that_grants_its_uri() {
        let mut rbac = Rbac::new();
        rbac.insert_role("reader", vec![("*".into(), "get_*".into())]);
        rbac.insert_resource_grants(
            "reader",
            vec![("fs".into(), UriGlob::new("file:///srv/docs/**").unwrap())],
        );
        assert!(!rbac.is_empty());
        let uri = |s: &str| uri::normalize(s).unwrap();
        let held = || ["reader"].into_iter();
        assert!(rbac
            .decide_resource(held(), "fs", &uri("file:///srv/docs/a"))
            .is_allow());
        // Another server, another tree, or a role that grants only tools: denied.
        for (server, u) in [("db", "file:///srv/docs/a"), ("fs", "file:///srv/secret/a")] {
            match rbac.decide_resource(held(), server, &uri(u)) {
                Decision::Deny { rule, reason } => {
                    assert_eq!(rule, "rbac");
                    assert_eq!(reason, format!("no role grants '{u}' on '{server}'"));
                }
                Decision::Allow => panic!("{server} {u} allowed"),
            }
        }
        let mut tools_only = Rbac::new();
        tools_only.insert_role("reader", vec![("*".into(), "*".into())]);
        assert!(!tools_only
            .decide_resource(held(), "fs", &uri("file:///srv/docs/a"))
            .is_allow());
        // Grants alone make a model that is not empty.
        let mut grants_only = Rbac::new();
        grants_only.insert_resource_grants("r", vec![]);
        assert!(!grants_only.is_empty());
    }

    #[test]
    fn rbac_grants_match_a_middle_star() {
        let mut rbac = Rbac::new();
        rbac.insert_role("reader", vec![("*".into(), "get_*_info".into())]);
        let held = || ["reader"].into_iter();
        assert!(rbac.decide(held(), "gh", "get_user_info").is_allow());
        assert!(!rbac.decide(held(), "gh", "get_user").is_allow());
    }
}
