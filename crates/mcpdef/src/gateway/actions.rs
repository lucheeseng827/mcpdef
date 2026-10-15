// SPDX-License-Identifier: Apache-2.0
//! What an operator can ask of an upstream through the admin API: open it
//! again now, answer a `ping`, and take the definitions its drifted tools
//! have now as their pins.

use super::{read, write, Gateway, Slot};
use crate::redact::redact_urls;
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::tool_hash;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why an action on an upstream was not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// No upstream has that id.
    Unknown,
    /// The action does not apply to it now, and why.
    Not(String),
}

impl Gateway {
    /// The upstream `id`'s place, as the calls starting now see it.
    fn place(&self, id: &str) -> Result<Slot, Refused> {
        let g = self.inner.governance.load();
        g.upstreams
            .iter()
            .find(|slot| slot.id == id)
            .cloned()
            .ok_or(Refused::Unknown)
    }

    /// Ask the keeper of the upstream `id` to open it again now, its backoff
    /// reset: a stdio server is started afresh. The connection it holds
    /// serves until the new one opens, and keeps serving if that fails.
    pub fn restart_upstream(&self, id: &str) -> Result<(), Refused> {
        let slot = self.place(id)?;
        if !slot.supervised {
            return Err(Refused::Not(
                "the gateway does not keep it running, so does not open it again".into(),
            ));
        }
        if slot.health.is_starting() {
            return Err(Refused::Not("it is opening already".into()));
        }
        slot.health.kick();
        Ok(())
    }

    /// A `ping` over the upstream `id`'s connection, given `timeout` to
    /// answer: how long its answer took, or why there was none.
    pub async fn ping_upstream(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<Result<Duration, String>, Refused> {
        let slot = self.place(id)?;
        let Some(up) = slot.conn else {
            return Ok(Err("it has no connection yet".into()));
        };
        let mut request = Message::request(Id::Num(0), method::PING, None);
        up.stamp(&mut request, &self.inner.client_info);
        let started = Instant::now();
        Ok(match up.handle.call(request, Some(timeout)).await {
            Ok(reply) => match reply.error {
                Some(error) => Err(format!(
                    "it answered with an error: {}",
                    error["message"].as_str().unwrap_or("(no message)")
                )),
                None => Ok(started.elapsed()),
            },
            Err(error) => Err(redact_urls(&error.to_string()).into_owned()),
        })
    }

    /// Take the definitions of the upstream `id`'s drifted tools named in
    /// `tools`, each with the hash of the definition its approver looked at,
    /// as their pins: each recorded in the pin store, the store saved, and
    /// the tools served again from the next call. Nothing is taken when a
    /// tool named has not drifted, or offers another definition now than the
    /// one looked at: approving what changed since would serve what no one
    /// saw. The names taken, in order.
    pub fn approve_drift(
        &self,
        id: &str,
        tools: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, Refused> {
        let slot = self.place(id)?;
        if read(&self.inner.pins).is_none() {
            return Err(Refused::Not(
                "pinning is off: `[gateway] pins` names no store".into(),
            ));
        }
        let Some(up) = &slot.conn else {
            return Err(Refused::Not("it has no connection yet".into()));
        };
        if tools.is_empty() {
            return Err(Refused::Not("no tool is named".into()));
        }
        let steady: Vec<&str> = tools
            .keys()
            .filter(|name| !slot.drifted.contains(*name))
            .map(String::as_str)
            .collect();
        if !steady.is_empty() {
            return Err(Refused::Not(format!(
                "not drifted from its pin: {}",
                steady.join(", ")
            )));
        }
        let changed: Vec<String> = tools
            .iter()
            .filter_map(|(name, hash)| match offered(&up.tools, name) {
                Some(now) if now == *hash => None,
                Some(now) => Some(format!("{name}, whose definition is {now} now")),
                None => Some(format!("{name}, which it no longer offers")),
            })
            .collect();
        if !changed.is_empty() {
            return Err(Refused::Not(format!(
                "changed since it was looked at, so nothing is approved: {}. Look at it again",
                changed.join("; ")
            )));
        }
        if let Some(pins) = write(&self.inner.pins).as_mut() {
            for (name, hash) in tools {
                pins.store.record(id, name, hash.clone());
            }
            pins.dirty = true;
        }
        // On disk before the tools are served: a reload, or a restart, reads
        // the store from there.
        self.write_pins()
            .map_err(|e| Refused::Not(format!("saving the pin store: {e:#}")))?;
        // A connection that offers another definition by now than the one
        // approved stays drifted.
        self.govern(|g| {
            for slot in g.upstreams.iter_mut().filter(|slot| slot.id == id) {
                let offers = slot.conn.as_ref().map(|up| up.tools.clone());
                let left = slot.drifted.iter().filter(|name| match tools.get(*name) {
                    None => true,
                    Some(hash) => {
                        offers
                            .as_ref()
                            .and_then(|offers| offered(offers, name))
                            .as_ref()
                            != Some(hash)
                    }
                });
                slot.drifted = Arc::new(left.cloned().collect());
            }
        });
        Ok(tools.keys().cloned().collect())
    }
}

/// The hash of the definition of the tool `name` among `tools`, if one is
/// named so.
fn offered(tools: &[serde_json::Value], name: &str) -> Option<String> {
    tools
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
        .map(tool_hash)
}
