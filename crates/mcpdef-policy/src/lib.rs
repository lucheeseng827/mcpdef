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
//!
//! A `transform` effect (argument/result mutation) is the remaining Phase-3 step.

use mcpdef_core::Decision;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod rules;
pub use rules::{ArgMatch, ArgOp, Effect, PolicyContext, PolicyRules, Rule};

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
}

impl Policy {
    pub fn new() -> Self {
        Policy::default()
    }

    pub fn from_map(servers: HashMap<String, ServerPolicy>) -> Self {
        Policy {
            servers,
            active: None,
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
}

impl Rbac {
    pub fn new() -> Self {
        Rbac::default()
    }

    /// Define a role from `(server-glob, tool-glob)` grants.
    pub fn insert_role(&mut self, name: impl Into<String>, grants: Vec<(String, String)>) {
        self.roles.insert(name.into(), grants);
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
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
        for subject in subjects {
            if let Some(grants) = self.roles.get(subject) {
                for (server_glob, tool_glob) in grants {
                    if glob_match(server_glob, server) && glob_match(tool_glob, tool) {
                        return Decision::Allow;
                    }
                }
            }
        }
        Decision::Deny {
            rule: "rbac".into(),
            reason: format!("no role grants '{tool}' on '{server}'"),
        }
    }
}

/// Minimal glob matcher: exact, single trailing `*` (prefix), or single leading
/// `*` (suffix). Enough for Phase-1 patterns like `delete_*`; the Phase-3 engine
/// replaces this with the full policy language.
pub(crate) fn glob_match(pattern: &str, s: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        s.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        s.ends_with(suffix)
    } else {
        pattern == s
    }
}

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
}
