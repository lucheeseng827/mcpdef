// SPDX-License-Identifier: Apache-2.0
//! `mcpdef` — the MCP gateway & governance plane (Phase 1: transport-mux proxy +
//! allowlist + tamper-evident audit, over stdio).
//!
//! The binary (`src/main.rs`) is a thin CLI over this library: [`Config`] loads
//! `mcpdef.toml`, [`Gateway`] is the proxy/governance loop, and [`serve_stdio`]
//! drives it as a stdio MCP server. See the module docs in
//! [`gateway`] for the Phase-1 governance scope.

pub mod admin;
pub mod bridge;
pub mod clients;
pub mod config;
pub mod connect;
pub mod discovery;
pub mod doctor;
pub mod gateway;
pub mod listener;
pub mod metrics;
pub mod redact;
pub mod reload;
pub mod sso;
pub mod tls;

pub use self::admin::{
    serve_admin, serve_admin_on, serve_admin_with, AdminState, ServerView, CONTENT_SECURITY_POLICY,
};
pub use self::config::Config;
pub use self::gateway::{
    handshake_list, list_tools_speaking, Connect, ConnectFuture, CredentialStatus, Gateway,
    HealthState, LastError, LastOk, Offers, Planned, RateScope, Reconfig, Reconfigured, Startup,
    Supervised, TlsStatus, ToolCollision, ToolCost, UpstreamOptions, UpstreamStatus,
    LISTED_NAME_WARN, TOOL_PREFIX_SEPARATOR,
};
pub use self::listener::{serve_http, serve_https, serve_proxied, HttpConfig};
pub use self::metrics::Metrics;

use anyhow::Result;
use mcpdef_core::{method, Message};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch, Semaphore};

/// How many stdio requests may run at once. Past this, reading pauses until one
/// finishes, so a client that floods the gateway backs up in its pipe rather
/// than in the gateway's memory.
pub const STDIO_INFLIGHT: usize = 64;

/// Serve the gateway as a stdio MCP server to a downstream client: read
/// newline-delimited JSON-RPC from `stdin`, handle each message, and write
/// responses to `stdout`. Returns when `stdin` reaches EOF and every request read
/// by then has been answered.
///
/// See [`serve_stdio_on`] for how requests are run.
pub async fn serve_stdio(gw: &Gateway) -> Result<()> {
    serve_stdio_on(gw, BufReader::new(tokio::io::stdin()), tokio::io::stdout()).await
}

/// [`serve_stdio`] over any reader and writer.
///
/// Requests run concurrently, up to [`STDIO_INFLIGHT`]: a client that sends
/// several tool calls at once (Claude Code does) gets each reply as soon as it
/// is ready, in whatever order they finish. One task writes every reply, a
/// whole line at a time. A request that fails at the gateway gets a JSON-RPC
/// error reply (`-32603`), and the session goes on. A call to an upstream that
/// is down is not such a failure: it gets a tool error, like a denied call.
///
/// The client is told when the tools change. The `initialize` it is answered
/// offers `tools.listChanged`, and once it sends `notifications/initialized`,
/// each change to what `tools/list` shows is sent to it as
/// `notifications/tools/list_changed`: an upstream's tools changing, a reload,
/// a restarted upstream listing different tools. A client that never sends
/// `initialize`, as on the 2026-07-28 wire, is sent none, having no way to ask
/// for them there (`subscriptions/listen` is not served).
pub async fn serve_stdio_on<R, W>(gw: &Gateway, input: R, output: W) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (replies, mut queue) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(line) = queue.recv().await {
            output.write_all(line.as_bytes()).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    // What `tools/list` showed when the client said it was initialized.
    let (initialized, ready) = watch::channel(None);
    let listing = gw.tool_list_changes();
    let relay = tokio::spawn(relay_list_changes(
        gw.tool_list_changes(),
        ready,
        replies.clone(),
    ));
    let slots = Arc::new(Semaphore::new(STDIO_INFLIGHT));
    let reading = async {
        let mut lines = input.lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let msg = match Message::from_json_line(&line) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("mcpdef: dropping invalid JSON-RPC frame: {e}");
                    continue;
                }
            };
            let asked = msg.method();
            if asked == Some(method::INITIALIZED) && msg.is_notification() {
                let showing = *listing.borrow();
                initialized.send_if_modified(|seen| seen.replace(showing).is_none());
            }
            let offers = asked == Some(method::INITIALIZE);
            let slot = Arc::clone(&slots).acquire_owned().await?;
            let (gw, replies) = (gw.clone(), replies.clone());
            tokio::spawn(async move {
                let _slot = slot;
                let id = msg.id.clone();
                let reply = match gw.handle(msg).await {
                    Ok(reply) => reply,
                    Err(e) => {
                        id.map(|id| Message::error(id, -32603, format!("gateway error: {e}")))
                    }
                };
                if let Some(mut reply) = reply {
                    if offers {
                        offer_list_changed(&mut reply);
                    }
                    let _ = replies.send(reply.to_json_line());
                }
            });
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // No word of a change after the client's end: the relay goes first, so
    // its sender is gone before the writer waits for the last.
    relay.abort();
    let _ = relay.await;
    // However reading ended, the requests already running finish, and are
    // answered and audited, before this returns: each holds a sender, so the
    // writer only runs dry once the last has replied.
    drop(replies);
    let written = writer.await?;
    reading?;
    written?;
    Ok(())
}

/// Say in an `initialize` result that the server sends
/// `notifications/tools/list_changed`: over stdio it does.
fn offer_list_changed(reply: &mut Message) {
    let tools = reply
        .result
        .as_mut()
        .and_then(|result| result.get_mut("capabilities"))
        .and_then(|capabilities| capabilities.get_mut("tools"))
        .and_then(|tools| tools.as_object_mut());
    if let Some(tools) = tools {
        tools.insert("listChanged".into(), true.into());
    }
}

/// Tell the client each time what `tools/list` shows changes, from when it
/// says it is initialized: `ready` then holds what it showed. What changed
/// before then, its first `tools/list` shows it anyway.
async fn relay_list_changes(
    mut changes: watch::Receiver<u64>,
    mut ready: watch::Receiver<Option<u64>>,
    replies: mpsc::UnboundedSender<String>,
) {
    let Ok(seen) = ready.wait_for(Option::is_some).await.map(|seen| *seen) else {
        return;
    };
    let notice = Message::notification(method::TOOLS_LIST_CHANGED, None).to_json_line();
    // A change between the client's word and this task's turn is told at once.
    if Some(*changes.borrow_and_update()) != seen && replies.send(notice.clone()).is_err() {
        return;
    }
    while changes.changed().await.is_ok() {
        if replies.send(notice.clone()).is_err() {
            return;
        }
    }
}
