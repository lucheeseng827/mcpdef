// SPDX-License-Identifier: Apache-2.0
//! A minimal MCP server over stdio, used by `mcpdef`'s integration tests as a
//! real upstream child process. NOT a product component — it exposes a harmless
//! `echo` tool and a `delete_repo` tool (to exercise the deny path).
//!
//! Run with `--modern` and it is a **2026-07-28** server instead: no
//! `initialize`, `server/discover` implemented, and every request required to
//! carry its own `_meta`. That last part is the point — a request that arrives
//! without one is refused, so a test passing against this mock is evidence that
//! MCPdef really did stamp what the revision asks for, rather than evidence that
//! the mock was lenient.
//!
//! Run with `--out-of-order` and each `tools/call` is answered on a thread of
//! its own, after the call's `arguments.delay_ms`. Replies then come back in
//! the order their delays end, not the order the requests arrived.
//!
//! For the supervision tests, the legacy side also takes:
//! - `--tool-prefix P`: every tool name starts with `P`;
//! - `--label L`: every tool result's text starts with `L`, to tell apart two
//!   servers listing the same tools;
//! - `--with-pid`: also list a `pid` tool (prefixed too), which answers with this
//!   process's id, so a test can kill it;
//! - `--with-env`: also list an `env` tool (prefixed too), which answers with the
//!   value of the variable its `name` argument names, or `(unset)`, so a test
//!   can see what the server was given;
//! - `--start-delay-ms N`: read nothing for the first `N` ms, like a server slow
//!   to start;
//! - `--tools-from FILE`: list the tools in `FILE`, a JSON array, as it reads at
//!   startup, so a test can change what a restarted server lists;
//! - `--grows`: also list an `add_tool` tool (prefixed too). A call to it with
//!   `{"name": N}` adds a tool `N` to what this server lists, and says so with
//!   `notifications/tools/list_changed` before it answers, as a server whose
//!   tools a call unlocks does;
//! - `--asks`: also list an `ask` tool (prefixed too). A call to it with
//!   `{"method": M}` sends the client a request `M` of the server's own, as a
//!   2025-11-25 server asks for an elicitation, waits for the answer, and
//!   gives it back as the call's text: `answered: <result or error>`.
//!
//! And the modern side takes `--mrtr`: also list a `greet_v2` tool, which
//! needs the user's name. It asks for it in an `InputRequiredResult`, an
//! elicitation, when the request says the client can elicit, and greets the
//! name once asked again with the answer and the `requestState` it gave.
//! Asked by a client that cannot elicit, it says so, as a tool error.

use mcpdef_core::wire::{error_code, meta_key, SPEC_2026_07_28};
use mcpdef_core::{method, Message};
use std::io::{BufRead, Write};
use std::time::Duration;

/// What the legacy side lists and answers, from the flags.
struct Legacy {
    prefix: String,
    label: String,
    tools: Vec<serde_json::Value>,
}

/// The value after `flag`, if it was given.
fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

impl Legacy {
    fn from_args() -> Self {
        let prefix = arg("--tool-prefix").unwrap_or_default();
        let tools = match arg("--tools-from") {
            Some(path) => {
                let text = std::fs::read_to_string(&path).expect("--tools-from names a file");
                serde_json::from_str(&text).expect("--tools-from holds a JSON array")
            }
            None => {
                let mut tools = vec![
                    serde_json::json!({ "name": format!("{prefix}echo"), "description": "echo arguments back", "inputSchema": { "type": "object" } }),
                    serde_json::json!({ "name": format!("{prefix}delete_repo"), "description": "destructive", "inputSchema": { "type": "object" } }),
                ];
                if std::env::args().any(|a| a == "--with-pid") {
                    tools.push(serde_json::json!({ "name": format!("{prefix}pid"), "description": "this server's process id", "inputSchema": { "type": "object" } }));
                }
                if std::env::args().any(|a| a == "--with-env") {
                    tools.push(serde_json::json!({ "name": format!("{prefix}env"), "description": "an environment variable of this server's", "inputSchema": { "type": "object" } }));
                }
                tools
            }
        };
        Legacy {
            label: arg("--label").unwrap_or_default(),
            prefix,
            tools,
        }
    }
}

/// Answer the requests on stdin, as the flags above say, until it closes.
fn main() {
    let modern = std::env::args().any(|a| a == "--modern");
    // A legacy server that simply drops an unknown method rather than answering
    // `-32601`. JSON-RPC requires that error; plenty of servers never send it,
    // and a probe that waits forever for one is a probe that hangs startup.
    let silent_on_discover = std::env::args().any(|a| a == "--silent-on-discover");
    // A server that never answers `initialize` at all — hung, wedged, or still
    // starting up. Every MCP revision implements `initialize`, so silence here
    // is not evidence of an era the way silence on an unknown method was: the
    // probe must say it could not tell, not guess.
    let silent_on_initialize = std::env::args().any(|a| a == "--silent-on-initialize");
    let out_of_order = std::env::args().any(|a| a == "--out-of-order");
    let grows = std::env::args().any(|a| a == "--grows");
    let asks = std::env::args().any(|a| a == "--asks");
    // A server with one resource and one prompt as well as its tools, so a
    // gateway in front of it has something other than tools to carry — and a
    // test can tell whether it carried them.
    let with_resources = std::env::args().any(|a| a == "--resources");
    let mut legacy = Legacy::from_args();
    if grows {
        legacy.tools.push(serde_json::json!({ "name": format!("{}add_tool", legacy.prefix), "description": "add a tool to this server's list", "inputSchema": { "type": "object" } }));
    }
    if asks {
        legacy.tools.push(serde_json::json!({ "name": format!("{}ask", legacy.prefix), "description": "ask the client for something", "inputSchema": { "type": "object" } }));
    }
    if let Some(ms) = arg("--start-delay-ms").and_then(|v| v.parse().ok()) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = Message::from_json_line(&line) else {
            continue;
        };
        if silent_on_discover && msg.method() == Some(method::SERVER_DISCOVER) {
            continue;
        }
        if silent_on_initialize && msg.method() == Some(method::INITIALIZE) {
            continue;
        }
        if with_resources {
            if let Some(reply) = resources_reply(&legacy, &msg) {
                emit(Some(reply));
                continue;
            }
        }
        if out_of_order && msg.method() == Some(method::TOOLS_CALL) {
            std::thread::spawn(move || {
                let delay = msg
                    .params
                    .as_ref()
                    .and_then(|p| p["arguments"]["delay_ms"].as_u64())
                    .unwrap_or(0);
                std::thread::sleep(Duration::from_millis(delay));
                emit(handle(&Legacy::from_args(), &msg));
            });
            continue;
        }
        if grows
            && msg.method() == Some(method::TOOLS_CALL)
            && msg.tool_name() == Some(&format!("{}add_tool", legacy.prefix))
        {
            let params = msg.params.as_ref();
            let name = params
                .and_then(|p| p["arguments"]["name"].as_str())
                .unwrap_or("added");
            legacy.tools.push(serde_json::json!({ "name": name, "description": format!("{name}, added while running"), "inputSchema": { "type": "object" } }));
            emit(Some(Message::notification(
                method::TOOLS_LIST_CHANGED,
                None,
            )));
        }
        if asks
            && msg.method() == Some(method::TOOLS_CALL)
            && msg.tool_name() == Some(&format!("{}ask", legacy.prefix))
        {
            let Some(id) = msg.id.clone() else { continue };
            let asked = msg
                .params
                .as_ref()
                .and_then(|p| p["arguments"]["method"].as_str())
                .unwrap_or(method::ELICITATION_CREATE)
                .to_string();
            let params = (asked == method::ELICITATION_CREATE).then(|| {
                serde_json::json!({
                    "message": "What is your name?",
                    "requestedSchema": { "type": "object", "properties": { "name": { "type": "string" } } },
                })
            });
            let ours = mcpdef_core::Id::Str("ask-1".into());
            emit(Some(Message::request(ours.clone(), asked, params)));
            // The answer comes as a line of its own, among whatever else does.
            let mut answered = None;
            for line in lines.by_ref() {
                let Ok(line) = line else { break };
                let Ok(reply) = Message::from_json_line(&line) else {
                    continue;
                };
                if reply.is_response() && reply.id.as_ref() == Some(&ours) {
                    answered = Some(reply);
                    break;
                }
            }
            let text = match answered {
                Some(reply) => format!(
                    "answered: {}",
                    reply.result.or(reply.error).unwrap_or_default()
                ),
                None => "not answered".to_string(),
            };
            emit(Some(Message::result(
                id,
                serde_json::json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false
                }),
            )));
            continue;
        }
        emit(if modern {
            handle_modern(&msg)
        } else {
            handle(&legacy, &msg)
        });
    }
}

/// Write one reply, whole, as a line of its own.
fn emit(resp: Option<Message>) {
    if let Some(resp) = resp {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", resp.to_json_line());
        let _ = out.flush();
    }
}

/// The 2026-07-28 side of the mock.
///
/// Tools are named `*_v2` so a test can front this server and the legacy one at
/// the same time and tell from the tool name which upstream answered.
fn handle_modern(msg: &Message) -> Option<Message> {
    let id = msg.id.clone()?;

    // Every request must carry its own metadata; there is no handshake it could
    // have come from. Refusing here is what makes the tests meaningful.
    let declared = msg
        .params
        .as_ref()
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(meta_key::PROTOCOL_VERSION))
        .and_then(|v| v.as_str());
    match declared {
        Some(SPEC_2026_07_28) => {}
        Some(other) => {
            return Some(Message::error(
                id,
                error_code::UNSUPPORTED_PROTOCOL_VERSION,
                format!("this server speaks {SPEC_2026_07_28}, not {other}"),
            ))
        }
        None => {
            return Some(Message::error(
                id,
                error_code::HEADER_MISMATCH,
                format!(
                    "every request must carry {} in params._meta",
                    meta_key::PROTOCOL_VERSION
                ),
            ))
        }
    }

    match msg.method() {
        Some(method::INITIALIZE) => Some(Message::error(
            id,
            error_code::METHOD_NOT_FOUND,
            format!("this server speaks {SPEC_2026_07_28}, which has no `initialize`"),
        )),
        Some(method::SERVER_DISCOVER) => Some(Message::result(
            id,
            serde_json::json!({
                "resultType": "complete",
                "supportedVersions": [SPEC_2026_07_28],
                "capabilities": { "tools": {} },
                "_meta": { meta_key::SERVER_INFO: {
                    "name": "mock-mcp-server", "version": "0.0.0"
                } },
            }),
        )),
        Some(method::TOOLS_LIST) => {
            let mut tools = vec![
                serde_json::json!({ "name": "echo_v2", "description": "echo arguments back",
                  "inputSchema": { "type": "object" } }),
                serde_json::json!({ "name": "delete_repo_v2", "description": "destructive",
                  "inputSchema": { "type": "object" } }),
            ];
            if std::env::args().any(|a| a == "--mrtr") {
                tools.push(serde_json::json!({ "name": "greet_v2",
                  "description": "greet the user, asking their name",
                  "inputSchema": { "type": "object" } }));
            }
            Some(Message::result(id, serde_json::json!({ "tools": tools })))
        }
        Some(method::TOOLS_CALL) if msg.tool_name() == Some("greet_v2") => Some(greet(id, msg)),
        Some(method::TOOLS_CALL) => {
            let name = msg.tool_name().unwrap_or_default();
            let args = msg
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            Some(Message::result(
                id,
                serde_json::json!({
                    "content": [{ "type": "text", "text": format!("{name}: {args}") }],
                    "isError": false
                }),
            ))
        }
        _ => Some(Message::error(
            id,
            error_code::METHOD_NOT_FOUND,
            "unknown method",
        )),
    }
}

/// `greet_v2`: the name it needs is the user's, so it asks for it in an
/// `InputRequiredResult` and greets it once asked again with the answer.
fn greet(id: mcpdef_core::Id, msg: &Message) -> Message {
    let params = msg.params.clone().unwrap_or_default();
    const STATE: &str = "greet-1";
    let answer = &params["inputResponses"]["name"];
    if params["requestState"] == STATE && answer["action"] == "accept" {
        let name = answer["content"]["name"].as_str().unwrap_or("stranger");
        return Message::result(
            id,
            serde_json::json!({
                "resultType": "complete",
                "content": [{ "type": "text", "text": format!("hello, {name}") }],
                "isError": false
            }),
        );
    }
    let can_elicit = params["_meta"][meta_key::CLIENT_CAPABILITIES]
        .get("elicitation")
        .is_some();
    if !can_elicit {
        return Message::result(
            id,
            serde_json::json!({
                "resultType": "complete",
                "content": [{ "type": "text", "text": "greet_v2 needs a client that can elicit" }],
                "isError": true
            }),
        );
    }
    Message::result(
        id,
        serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "name": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form",
                        "message": "What is your name?",
                        "requestedSchema": {
                            "type": "object",
                            "properties": { "name": { "type": "string" } },
                            "required": ["name"]
                        }
                    }
                }
            },
            "requestState": STATE
        }),
    )
}

/// `--resources`: the replies a server with one resource and one prompt
/// gives, and its `initialize` saying so. `None` for anything else, which the
/// ordinary handler answers.
fn resources_reply(legacy: &Legacy, msg: &Message) -> Option<Message> {
    let id = msg.id.clone()?;
    match msg.method()? {
        method::INITIALIZE => {
            let mut reply = handle(legacy, msg)?;
            if let Some(result) = reply.result.as_mut() {
                result["capabilities"] =
                    serde_json::json!({ "tools": {}, "resources": {}, "prompts": {} });
            }
            Some(reply)
        }
        method::RESOURCES_LIST => Some(Message::result(
            id,
            serde_json::json!({ "resources": [
                { "uri": "file:///notes/readme.md", "name": "readme", "mimeType": "text/plain" }
            ] }),
        )),
        method::RESOURCES_READ => {
            let uri = msg.params.as_ref()?.get("uri")?.as_str()?.to_string();
            Some(Message::result(
                id,
                serde_json::json!({ "contents": [
                    { "uri": uri, "mimeType": "text/plain", "text": "the readme" }
                ] }),
            ))
        }
        method::PROMPTS_LIST => Some(Message::result(
            id,
            serde_json::json!({ "prompts": [
                { "name": "summarize", "description": "summarize a note" }
            ] }),
        )),
        method::PROMPTS_GET => Some(Message::result(
            id,
            serde_json::json!({ "messages": [
                { "role": "user", "content": { "type": "text", "text": "summarize the readme" } }
            ] }),
        )),
        _ => None,
    }
}

fn handle(legacy: &Legacy, msg: &Message) -> Option<Message> {
    let id = msg.id.clone();
    match msg.method() {
        Some(method::INITIALIZE) => Some(Message::result(
            id?,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp-server", "version": "0.0.0" }
            }),
        )),
        Some(method::INITIALIZED) => None,
        Some(method::TOOLS_LIST) => Some(Message::result(
            id?,
            serde_json::json!({ "tools": legacy.tools }),
        )),
        Some(method::TOOLS_CALL) => {
            let name = msg.tool_name().unwrap_or_default();
            let args = msg
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let text = if name == format!("{}pid", legacy.prefix) {
                std::process::id().to_string()
            } else if name == format!("{}env", legacy.prefix) {
                let var = args["name"].as_str().unwrap_or_default();
                std::env::var(var).unwrap_or_else(|_| "(unset)".to_string())
            } else {
                format!("{}{name}: {args}", legacy.label)
            };
            Some(Message::result(
                id?,
                serde_json::json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false
                }),
            ))
        }
        Some(method::PING) => Some(Message::result(id?, serde_json::json!({}))),
        _ => id.map(|i| Message::error(i, -32601, "method not found")),
    }
}
