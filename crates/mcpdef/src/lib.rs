// SPDX-License-Identifier: Apache-2.0
//! `mcpdef` — the MCP gateway & governance plane (Phase 1: transport-mux proxy +
//! allowlist + tamper-evident audit, over stdio).
//!
//! The binary (`src/main.rs`) is a thin CLI over this library: [`Config`] loads
//! `mcpdef.toml`, [`Gateway`] is the proxy/governance loop, and [`serve_stdio`]
//! drives it as a stdio MCP server. See the module docs in
//! [`gateway`] for the Phase-1 governance scope.

pub mod admin;
pub mod config;
pub mod gateway;
pub mod listener;
pub mod metrics;

pub use self::admin::{serve_admin, AdminState, ServerView};
pub use self::config::Config;
pub use self::gateway::{handshake_list, Gateway};
pub use self::listener::{serve_http, HttpConfig};
pub use self::metrics::Metrics;

use anyhow::Result;
use mcpdef_core::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Serve the gateway as a stdio MCP server to a downstream client: read
/// newline-delimited JSON-RPC from `stdin`, handle each message, and write
/// responses to `stdout`. Returns when `stdin` reaches EOF.
pub async fn serve_stdio(gw: &mut Gateway) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
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
        if let Some(resp) = gw.handle(msg).await? {
            stdout.write_all(resp.to_json_line().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
