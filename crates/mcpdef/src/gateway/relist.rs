// SPDX-License-Identifier: Apache-2.0
//! Keeping an upstream's tools current. When it sends
//! `notifications/tools/list_changed`, the gateway lists its tools again,
//! judges them against the pins and the scanner as it does at connect, and
//! routes by what they now are.

use super::lists::{next_cursor, MAX_ENTRIES, MAX_PAGES};
use super::{
    deny_reason, reject_error, Gateway, Inner, Mirroring, Opened, Slot, Upstream, GATEWAY_AGENT,
};
use crate::redact::redact_urls;
use mcpdef_audit::{Attrs, Entry, Kind, ToolChanges};
use mcpdef_core::{method, Decision, Id, Message};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::watch;

/// How long word that the tools changed must stop coming before they are
/// listed again: a burst of it lists them once.
const RELIST_QUIET: Duration = Duration::from_millis(100);

/// The longest a burst that does not stop holds a re-list back.
const RELIST_MAX_DELAY: Duration = Duration::from_secs(1);

/// How long a re-list waits for its answer when `upstream_timeout_ms` sets no
/// bound. Nobody waits on a re-list, and one that never ends would leave the
/// upstream's tools as they were without a word.
const RELIST_TIMEOUT: Duration = Duration::from_secs(30);

/// The method of the record a re-list that changed something writes, and of
/// the records of what the scanner finds in the tools it changed.
const TOOLS_CHANGED: &str = "tools-changed";

impl Gateway {
    /// Listen on a connection of upstream `id`, `opened` and now in place, for
    /// word that its tools changed, and list them again each time it comes:
    /// at once if it came while the opening listed them.
    pub(super) fn watch_tools(&self, id: &str, opened: Opened) {
        let watch = ToolWatch {
            me: Arc::downgrade(&self.inner),
            id: id.to_string(),
            serial: opened.upstream.serial,
            notices: opened.notices,
            shutdown: self.inner.shutdown.subscribe(),
        };
        tokio::spawn(watch.run(opened.changed));
    }

    /// Put `tools`, just listed on connection `serial` of upstream `id`, in
    /// force, and say what changed.
    ///
    /// A tool that is new or whose definition changed is judged as at connect:
    /// a new one is pinned on first use, one that no longer matches its pin is
    /// refused as drifted, and each is scanned. A tool that did not change
    /// keeps its verdict. Nothing is put in force if the connection is no
    /// longer the upstream's.
    async fn put_tools(
        &self,
        id: &str,
        serial: u64,
        tools: Vec<serde_json::Value>,
        took: Duration,
    ) {
        // One at a time with a reload, which judges every upstream's tools
        // against the pin store it reads: neither works on the other's stale
        // view of them.
        let _one_at_a_time = self.inner.reconfiguring.lock().await;
        let started = Instant::now();
        let g = self.inner.governance.load_full();
        let Some(slot) = g.upstreams.iter().find(|slot| slot.id == id) else {
            return;
        };
        let Some(up) = slot.conn.as_ref().filter(|up| up.serial == serial) else {
            return;
        };

        let before = by_name(&up.tools);
        let after = by_name(&tools);
        let mut changes = ToolChanges::default();
        let mut fresh = Vec::new();
        let mut seen = HashSet::new();
        for tool in &tools {
            let Some(name) = name_of(tool).filter(|name| seen.insert(*name)) else {
                continue;
            };
            match before.get(name) {
                None => changes.added += 1,
                Some(old) if *old != tool => changes.changed += 1,
                Some(_) => continue,
            }
            fresh.push(tool.clone());
        }
        changes.removed = count(before.keys().filter(|name| !after.contains_key(*name)));

        let drifted = self.pin_check(id, &tools);
        changes.drifted = count(drifted.difference(&slot.drifted));
        let scanner = g.inspect.as_deref();
        let mut poisoned = self.inspect_check(scanner, id, &fresh, TOOLS_CHANGED).await;
        poisoned.extend(
            slot.poisoned
                .iter()
                .filter(|name| {
                    let name = name.as_str();
                    before
                        .get(name)
                        .is_some_and(|old| after.get(name) == Some(old))
                })
                .cloned(),
        );

        let warned: HashSet<String> = self.tool_warnings().into_iter().collect();
        let next = Arc::new(up.listing(id, tools));
        let (drifted, poisoned) = (Arc::new(drifted), Arc::new(poisoned));
        let applied = Cell::new(false);
        self.govern(|g| {
            applied.set(false);
            let Some(slot) = g.slot_mut(id) else { return };
            if slot.conn.as_ref().is_none_or(|up| up.serial != serial) {
                return;
            }
            slot.conn = Some(Arc::clone(&next));
            slot.drifted = Arc::clone(&drifted);
            slot.poisoned = Arc::clone(&poisoned);
            g.reroute();
            applied.set(true);
        });
        if let Err(e) = self.write_pins() {
            eprintln!("mcpdef: saving the pin store: {e:#}");
        }
        if !applied.get() {
            return;
        }
        if !changes.is_empty() {
            eprintln!(
                "mcpdef: upstream '{id}' changed its tools: {}",
                summary(changes)
            );
            self.audit_tools_changed(id, changes, took + started.elapsed())
                .await;
        }
        // What startup would print about the tools it now lists: a collision
        // the change made, or a listed name grown too long.
        for finding in self.tool_warnings() {
            if !warned.contains(&finding) {
                eprintln!("mcpdef: warning — {finding}");
            }
        }
    }

    /// Record that upstream `server`'s tools changed, and how
    /// (`kind = "upstream"`, `method = "tools-changed"`). One that now drifts
    /// from its pin makes it a denial under `rug-pull`, as a call to it is.
    async fn audit_tools_changed(&self, server: &str, changes: ToolChanges, took: Duration) {
        let decision = match changes.drifted {
            0 => Decision::Allow,
            _ => Decision::Deny {
                rule: "rug-pull".into(),
                reason: String::new(),
            },
        };
        let entry = Entry {
            agent: GATEWAY_AGENT.to_string(),
            server: server.to_string(),
            method: Some(TOOLS_CHANGED.to_string()),
            tool: None,
            decision,
            latency_ms: u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
            attrs: Attrs {
                kind: Kind::Upstream,
                tool_changes: Some(changes),
                ..Attrs::default()
            },
        };
        if let Err(e) = self.inner.ledger.append(entry).await {
            eprintln!("mcpdef: audit append failed: {e}");
        }
    }
}

impl Upstream {
    /// This connection, of upstream `id`, listing `tools`, and sending each
    /// call from now on by what they ask of it.
    fn listing(&self, id: &str, tools: Vec<serde_json::Value>) -> Upstream {
        let mirroring = Mirroring::judge(id, &tools, self.params.as_ref(), Some(&self.mirroring));
        Upstream {
            handle: self.handle.clone(),
            serial: self.serial,
            era: self.era,
            spec_version: self.spec_version,
            tools,
            tls: self.tls.clone(),
            auth: self.auth.clone(),
            mirroring: Arc::new(mirroring),
            params: self.params.clone(),
            offers: self.offers,
        }
    }
}

/// Lists one connection's tools again each time it says they changed.
///
/// It holds the gateway only by a weak reference, and only upgrades it for the
/// moments it reads or changes it. It holds the connection only while a re-list
/// waits for its answer. The connection's notices close when the last handle
/// to it goes, and the watch ends with them.
struct ToolWatch {
    me: Weak<Inner>,
    id: String,
    serial: u64,
    notices: broadcast::Receiver<Message>,
    /// Closes when the gateway is dropped.
    shutdown: watch::Receiver<()>,
}

impl ToolWatch {
    /// Wait for word that the tools changed and list them again, until the
    /// connection or the gateway is gone. When the word came as the opening
    /// listed them (`changed`), the first re-list waits for no more of it.
    async fn run(mut self, changed: bool) {
        let mut waiting = !changed;
        loop {
            if waiting {
                tokio::select! {
                    heard = heard(&mut self.notices) => if !heard { return },
                    _ = self.shutdown.changed() => return,
                }
            }
            waiting = true;
            // Word of a change often comes in a burst: wait for it to stop,
            // or for the most it may hold the re-list back.
            let latest = tokio::time::Instant::now() + RELIST_MAX_DELAY;
            loop {
                let quiet = latest.min(tokio::time::Instant::now() + RELIST_QUIET);
                tokio::select! {
                    () = tokio::time::sleep_until(quiet) => break,
                    heard = heard(&mut self.notices) => if !heard { return },
                    _ = self.shutdown.changed() => return,
                }
            }
            if self.relist().await.is_none() {
                return;
            }
        }
    }

    /// List the tools again and put them in force. Word of a change that comes
    /// meanwhile waits in the notices, and lists them again after.
    ///
    /// `None` once there is nothing more to watch for: the gateway is gone, or
    /// this connection is no longer its upstream's.
    async fn relist(&mut self) -> Option<()> {
        let started = Instant::now();
        let (up, slot, timeout, client) = {
            let gw = Gateway::upgrade(&self.me)?;
            let g = gw.inner.governance.load();
            let slot = g.upstreams.iter().find(|slot| slot.id == self.id)?;
            let up = slot.conn.as_ref().filter(|up| up.serial == self.serial)?;
            let timeout = g.upstream_timeout.unwrap_or(RELIST_TIMEOUT);
            let client = Arc::clone(&gw.inner.client_info);
            (Arc::clone(up), slot.clone(), timeout, client)
        };
        // No hold on the gateway while the upstream answers: dropping it must
        // still close everything at once.
        let tools = tokio::select! {
            tools = list_tools(&slot, &up, &client, timeout) => tools,
            _ = self.shutdown.changed() => return None,
        };
        drop(up);
        let id = &self.id;
        let gw = Gateway::upgrade(&self.me)?;
        match tools {
            Ok(tools) => {
                gw.put_tools(id, self.serial, tools, started.elapsed())
                    .await
            }
            Err(why) => eprintln!(
                "mcpdef: upstream '{id}' said its tools changed, but listing them again failed: \
                 {why}; it keeps the tools it had"
            ),
        }
        Some(())
    }
}

/// Wait for word that the tools changed. `false` once the connection is gone.
async fn heard(notices: &mut broadcast::Receiver<Message>) -> bool {
    loop {
        match notices.recv().await {
            Ok(notice) if notice.method() == Some(method::TOOLS_LIST_CHANGED) => return true,
            Ok(_) => {}
            // Some went unread, and any of them may have been it.
            Err(RecvError::Lagged(_)) => return true,
            Err(RecvError::Closed) => return false,
        }
    }
}

/// Every page of the tools upstream `slot` lists on connection `up`, as the
/// opening reads them, each page bounded by `timeout`; or why they could not
/// all be read. Part of a list is no list: a tool on a page that failed would
/// read as removed.
async fn list_tools(
    slot: &Slot,
    up: &Upstream,
    client: &serde_json::Value,
    timeout: Duration,
) -> Result<Vec<serde_json::Value>, String> {
    let mut tools = Vec::new();
    let mut cursor = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .take()
            .map(|cursor| serde_json::json!({ "cursor": cursor }));
        let mut request = Message::request(Id::Num(0), method::TOOLS_LIST, params);
        up.stamp(&mut request, client);
        let reply = match up.handle.call(request, Some(timeout)).await {
            Ok(reply) => {
                slot.answered(up);
                reply
            }
            Err(error) => {
                let failure = slot.failure(&error, method::TOOLS_LIST, Some(timeout));
                return Err(deny_reason(&failure));
            }
        };
        let (page, next) = page_of(&reply)?;
        let room = MAX_ENTRIES - tools.len();
        tools.extend(page.into_iter().take(room));
        match next {
            Some(next) if tools.len() < MAX_ENTRIES => cursor = Some(next),
            _ => break,
        }
    }
    Ok(tools)
}

/// The tools on one page of an answer to `tools/list` and the cursor of the
/// next page, or why it holds no list.
fn page_of(reply: &Message) -> Result<(Vec<serde_json::Value>, Option<serde_json::Value>), String> {
    reject_error(reply, "`tools/list`").map_err(|e| redact_urls(&e.to_string()).into_owned())?;
    let result = reply.result.as_ref();
    let tools = result
        .and_then(|result| result.get("tools"))
        .and_then(|tools| tools.as_array())
        .cloned()
        .ok_or_else(|| "its answer held no list of tools".to_string())?;
    Ok((tools, result.and_then(next_cursor)))
}

/// Each named tool by its name; the first, for a name listed twice.
fn by_name(tools: &[serde_json::Value]) -> HashMap<&str, &serde_json::Value> {
    let mut named = HashMap::new();
    for tool in tools {
        if let Some(name) = name_of(tool) {
            named.entry(name).or_insert(tool);
        }
    }
    named
}

/// A tool's name, if it has one.
fn name_of(tool: &serde_json::Value) -> Option<&str> {
    tool.get("name").and_then(|name| name.as_str())
}

/// How many `items` there are, as a count in a record.
fn count<T>(items: impl Iterator<Item = T>) -> u32 {
    u32::try_from(items.count()).unwrap_or(u32::MAX)
}

/// What changed, as the log says it.
fn summary(changes: ToolChanges) -> String {
    let ToolChanges {
        added,
        removed,
        changed,
        drifted,
    } = changes;
    let mut text = format!("{added} added, {removed} removed, {changed} changed");
    match drifted {
        0 => {}
        1 => text.push_str(
            "; 1 no longer matches its pin and is refused until `mcpdef pin` approves it",
        ),
        n => text.push_str(&format!(
            "; {n} no longer match their pins and are refused until `mcpdef pin` approves them"
        )),
    }
    text
}
