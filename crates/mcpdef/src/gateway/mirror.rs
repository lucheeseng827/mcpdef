// SPDX-License-Identifier: Apache-2.0
//! `x-mcp-header`: which arguments of a call to each tool go out mirrored into
//! `Mcp-Param-{Name}` headers, and which tools ask for a mirroring no client
//! may perform.
//!
//! Both are facts about a tool's definition as its server lists it *now*. So
//! they are judged each time an upstream's tools are read, at an opening (a
//! start, a restart, a reload) and when it says they changed, and kept on the
//! [`Upstream`](super::Upstream) that carries that list: they are replaced with
//! it, never apart from it. The transport is told at the same moment, and
//! sends by them from then on. The listener checks a client's headers against
//! them as they stand when its request arrives.

use super::Decision;
use mcpdef_core::wire::{self, ParamHeader, WireError};
use mcpdef_core::{method, Message};
use mcpdef_transport::ParamHeaders;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// What one listing of an upstream's tools asks of a call to each of them.
#[derive(Debug, Default)]
pub(super) struct Mirroring {
    /// Each tool with `x-mcp-header` annotations, by its name upstream: the
    /// arguments a call to it mirrors into headers.
    pub(super) headers: Arc<HashMap<String, Vec<ParamHeader>>>,
    /// Each tool whose annotations break the revision's rules, and why. The
    /// revision has a client exclude such a tool from `tools/list`, so it is
    /// hidden, and a call to it is refused. It keeps its name, as a drifted
    /// one does: a call to it is never handed to another server.
    pub(super) refused: HashMap<String, String>,
}

impl Mirroring {
    /// Judge `tools`, the ones upstream `server` lists, and have `params`, its
    /// transport's, send by what they say from now on. A refusal goes to the
    /// log, as the revision advises, unless `before`, what the listing before
    /// this one judged, already refused the tool for the same reason.
    ///
    /// Applied whatever the upstream's transport. The revision lets a client
    /// over stdio ignore annotations, but MCPdef serves what it takes from
    /// any upstream to clients over HTTP, who must refuse such a tool
    /// themselves, and it checks their headers against annotations it could
    /// not make sense of either.
    pub(super) fn judge(
        server: &str,
        tools: &[serde_json::Value],
        params: Option<&ParamHeaders>,
        before: Option<&Mirroring>,
    ) -> Mirroring {
        let mut headers = HashMap::new();
        let mut refused = HashMap::new();
        let mut seen = HashSet::new();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            // The first definition of a name is the one routed to, as
            // everywhere else, whether or not it has annotations.
            if !seen.insert(name) {
                continue;
            }
            let schema = tool.get("inputSchema").unwrap_or(&serde_json::Value::Null);
            match wire::param_headers(schema) {
                Ok(found) if found.is_empty() => {}
                Ok(found) => {
                    headers.insert(name.to_string(), found);
                }
                Err(why) => {
                    let why = why.to_string();
                    let known = before
                        .and_then(|b| b.refused.get(name))
                        .is_some_and(|was| *was == why);
                    if !known {
                        eprintln!(
                            "mcpdef: warning — tool '{name}' on '{server}' is not served: {why}"
                        );
                    }
                    refused.insert(name.to_string(), why);
                }
            }
        }
        let headers = Arc::new(headers);
        if let Some(params) = params {
            params.set(Arc::clone(&headers));
        }
        Mirroring { headers, refused }
    }

    /// The decision for a call to `tool` on `server`, if it is refused.
    pub(super) fn refusal(&self, server: &str, tool: &str) -> Option<Decision> {
        let why = self.refused.get(tool)?;
        Some(Decision::Deny {
            rule: "x-mcp-header".into(),
            reason: format!("tool '{tool}' on '{server}' is not served: {why}"),
        })
    }
}

impl super::Gateway {
    /// Check a modern `tools/call`'s `Mcp-Param-{Name}` headers against its
    /// body, by the annotations of the tool it names as its server lists it at
    /// this moment ([`wire::validate_param_headers`]). `get` looks a header up
    /// by its lower-case name.
    ///
    /// For the HTTP listener, which has the headers: the gateway has the
    /// tools. Only a tool `tools/list` shows is checked. A call to any other,
    /// one no server lists, the allowlist hides, or that is refused for its
    /// definition, is refused as the call itself; checking it first would
    /// tell a caller what the hidden tool's annotations are, in the mismatch.
    /// Nor is a notification checked: it is not a call, and the gateway
    /// answers none.
    ///
    /// Read now, not kept: a re-list, a restart or a reload can change a
    /// tool's annotations at any time. A change between this check and the
    /// call is harmless to the upstream, whose headers are made from the call
    /// as it is sent, by what its tools say then.
    pub fn check_param_headers<'a, F>(&self, msg: &Message, get: F) -> Result<(), WireError>
    where
        F: Fn(&str) -> Option<&'a str>,
    {
        if !msg.is_request() || msg.method() != Some(method::TOOLS_CALL) {
            return Ok(());
        }
        let g = self.inner.governance.load();
        let annotations = msg
            .tool_name()
            .and_then(|listed| g.routes.get(listed))
            .and_then(|route| {
                let slot = &g.upstreams[route.index];
                let tool = route.tool.as_str();
                let hidden = !g.offers(slot, tool)
                    || slot.drifted.contains(tool)
                    || slot.poisoned.contains(tool);
                let up = slot.conn.as_ref().filter(|_| !hidden)?;
                up.mirroring.headers.get(tool).cloned()
            })
            .unwrap_or_default();
        wire::validate_param_headers(msg, get, &annotations)
    }
}

#[cfg(test)]
mod tests {
    use super::super::deny_reason;
    use super::*;
    use serde_json::json;

    fn tool(name: &str, schema: serde_json::Value) -> serde_json::Value {
        json!({ "name": name, "inputSchema": schema })
    }

    fn annotated(header: &str) -> serde_json::Value {
        json!({ "type": "object", "properties": {
            "region": { "type": "string", "x-mcp-header": header } } })
    }

    /// Per tool, never per upstream: one malformed definition costs only
    /// itself. The transport is told what the rest ask for.
    #[test]
    fn a_malformed_annotation_refuses_its_tool_alone() {
        let tools = [
            tool("plain", json!({ "type": "object" })),
            tool("sql", annotated("Region")),
            tool("leaky", annotated("X\r\nInjected: yes")),
        ];
        let params = ParamHeaders::default();
        let m = Mirroring::judge("up", &tools, Some(&params), None);
        assert_eq!(
            m.headers.keys().collect::<Vec<_>>(),
            ["sql"],
            "only a tool with annotations has headers"
        );
        assert_eq!(m.refused.keys().collect::<Vec<_>>(), ["leaky"]);
        assert!(m.refusal("up", "sql").is_none());
        let refused = m.refusal("up", "leaky").unwrap();
        assert!(
            deny_reason(&refused).contains("not an HTTP field name"),
            "{refused:?}"
        );
    }

    /// The first definition of a name decides, as routing does.
    #[test]
    fn a_name_listed_twice_is_judged_by_its_first_definition() {
        let tools = [
            tool("sql", annotated("Region")),
            tool("sql", annotated("bad header")),
        ];
        let m = Mirroring::judge("up", &tools, None, None);
        assert!(m.refused.is_empty());
        assert_eq!(m.headers["sql"][0].name, "Region");

        // A first definition with no annotations decides too: the later
        // ones neither refuse it nor give it headers it never asked for.
        for later in [annotated("bad header"), annotated("Region")] {
            let tools = [tool("sql", json!({ "type": "object" })), tool("sql", later)];
            let m = Mirroring::judge("up", &tools, None, None);
            assert!(m.refused.is_empty() && m.headers.is_empty(), "{m:?}");
        }
    }
}
