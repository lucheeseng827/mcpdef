// SPDX-License-Identifier: Apache-2.0
//! Applying a whole new configuration to a running gateway: its governance
//! swapped at once, and its upstreams diffed by id.

use super::supervise::{
    reach, secs, Backoff, Health, Next, Supervised, Tenure, Together, UpstreamEvent,
};
use super::{write, Budget, Gateway, Opened, Pins, Slot, Upstream};
use mcpdef_inspect::Scanner;
use mcpdef_pin::PinStore;
use mcpdef_policy::{Policy, PolicyRules, Rbac};
use mcpdef_ratelimit::RateLimiter;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One token-bucket scope: `(refill_per_sec, burst)`.
pub type RateScope = (f64, f64);

/// A whole configuration for a running gateway, as
/// [`Gateway::reconfigure`] applies it.
pub struct Reconfig {
    pub policy: Policy,
    /// RBAC roles. An empty set turns the gate off.
    pub rbac: Rbac,
    pub rules: PolicyRules,
    pub upstream_timeout: Option<Duration>,
    /// New `(per_tool, global)` rate limits, or `None` to keep the limiter,
    /// and its buckets, as they are.
    pub rate_limit: Option<(Option<RateScope>, Option<RateScope>)>,
    /// A new injection scanner (`Some(None)` turns scanning off), or `None` to
    /// keep the one in force.
    pub inspect: Option<Option<Scanner>>,
    /// The pin store as it now stands, and where to save it. `None` turns
    /// pinning off.
    pub pins: Option<(PinStore, PathBuf)>,
    /// Each server's tool prefix by its id, with `tool_namespace = "prefix"`;
    /// `None` lists each tool as its server names it.
    pub tool_prefixes: Option<HashMap<String, String>>,
    /// Every upstream, in the order calls should prefer them.
    pub upstreams: Vec<Planned>,
}

/// One upstream in a [`Reconfig`].
pub struct Planned {
    pub server: Supervised,
    /// Whether how it is reached changed: its transport, command, URL,
    /// environment and so on. An upstream new to the gateway opens either way.
    pub changed: bool,
}

/// What [`Gateway::reconfigure`] did to the upstreams.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconfigured {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Changed upstreams now on a connection opened with their new settings.
    /// The old one drains: the calls it carries finish, and it closes.
    pub reconnected: Vec<String>,
    /// Added or changed upstreams that did not open, with why. An added one
    /// starts down and is retried. A changed one keeps the connection it had
    /// while its new settings are retried.
    pub failed: Vec<(String, String)>,
}

impl Gateway {
    /// Apply a whole new configuration, without dropping a call in flight.
    ///
    /// An upstream new to the gateway opens, and one whose connection settings
    /// changed opens a second connection on its new ones, all at once and all
    /// before anything changes: when the new configuration takes effect, what
    /// it adds is there. Then, as one step for every call that starts after
    /// it, the policy, roles, rules, timeout and scanner are replaced, and the
    /// upstreams become those planned, in the order planned. Upstreams left out
    /// are removed, and one that changed moves to its new connection. A call
    /// already running keeps the configuration it started under, connection
    /// included, so a removed or replaced connection closes once its last call
    /// is done.
    ///
    /// Every upstream's tools are judged again against the pin store as it now
    /// stands, which is how a tool re-approved with `mcpdef pin` is let back
    /// in, and against a changed scanner. An added upstream that does not open
    /// starts down, as at startup. A changed one that does not open keeps its
    /// old connection while its new settings are retried. Either way the rest
    /// of the configuration applies.
    ///
    /// One runs at a time.
    pub async fn reconfigure(&self, new: Reconfig) -> Reconfigured {
        let _one_at_a_time = self.inner.reconfiguring.lock().await;
        let Reconfig {
            policy,
            rbac,
            rules,
            upstream_timeout,
            rate_limit,
            inspect,
            pins,
            tool_prefixes,
            upstreams,
        } = new;
        let tool_prefixes = tool_prefixes.map(Arc::new);

        // The pins first: what opens below, and every upstream kept, is judged
        // against the store as it now stands. What the old one learned since it
        // was last saved is saved before it goes.
        if let Err(e) = self.write_pins() {
            eprintln!("mcpdef: saving the pin store: {e:#}");
        }
        *write(&self.inner.pins) = pins.map(|(store, path)| Pins {
            store,
            path,
            dirty: false,
        });
        let current = self.inner.governance.load_full();
        let scanner_changed = inspect.is_some();
        let scanner: Option<Arc<Scanner>> = match inspect {
            Some(scanner) => scanner.map(Arc::new),
            None => current.inspect.clone(),
        };

        // What opens: every upstream the gateway lacks, and every one changed.
        let had: HashMap<&str, &Slot> = current
            .upstreams
            .iter()
            .map(|slot| (slot.id.as_str(), slot))
            .collect();
        let opens: Vec<usize> = upstreams
            .iter()
            .enumerate()
            .filter(|(_, p)| p.changed || !had.contains_key(p.server.id.as_str()))
            .map(|(i, _)| i)
            .collect();
        let client = Arc::clone(&self.inner.client_info);
        let mut opened: HashMap<usize, anyhow::Result<Opened>> = HashMap::new();
        {
            let mut openings = Together::new(opens.iter().map(|&i| {
                let s = &upstreams[i].server;
                let budget = Budget::of(upstream_timeout, s.options.spec);
                let (client, scanner) = (&client, scanner.as_deref());
                async move {
                    let (transport, listed) =
                        reach(&s.id, &s.connect, s.options, client, &budget).await?;
                    Ok(self
                        .admit_with(scanner, &s.id, transport, listed, s.options)
                        .await)
                }
            }));
            while let Some((k, result)) = openings.next().await {
                opened.insert(opens[k], result);
            }
        }

        // Every upstream kept: its tools judged again.
        let mut judged: HashMap<&str, Judged> = HashMap::new();
        for p in upstreams.iter().filter(|p| !p.changed) {
            let id = p.server.id.as_str();
            let Some(up) = had.get(id).and_then(|slot| slot.conn.as_ref()) else {
                continue;
            };
            let drifted = Arc::new(self.pin_check(id, &up.tools));
            let poisoned = match scanner_changed {
                true => Some(Arc::new(
                    self.inspect_check(scanner.as_deref(), id, &up.tools, "connect")
                        .await,
                )),
                false => None,
            };
            let conn = Arc::clone(up);
            judged.insert(
                id,
                Judged {
                    conn,
                    drifted,
                    poisoned,
                },
            );
        }

        // A new tenure for every upstream that opened. A changed one keeps its
        // health, and so its restart count.
        let mut fresh: HashMap<usize, (Arc<Tenure>, Arc<Health>)> = opens
            .iter()
            .map(|&i| {
                let health = match had.get(upstreams[i].server.id.as_str()) {
                    Some(slot) => Arc::clone(&slot.health),
                    None => Arc::default(),
                };
                (i, (Tenure::new(), health))
            })
            .collect();

        let policy = Arc::new(policy);
        let rbac = (!rbac.is_empty()).then(|| Arc::new(rbac));
        let rules = Arc::new(rules);
        // What each changed place held when its tenure changed hands: the
        // connection a new one replaced, or the one that serves on until its
        // new settings start.
        let displaced: RefCell<HashMap<usize, Arc<Upstream>>> = RefCell::default();
        self.govern(|g| {
            displaced.borrow_mut().clear();
            let mut slots = Vec::with_capacity(upstreams.len());
            for (i, p) in upstreams.iter().enumerate() {
                let id = p.server.id.as_str();
                let existing = g.upstreams.iter().find(|slot| slot.id == id);
                let slot = match (existing, fresh.get(&i)) {
                    // Kept as it is, with its tools judged again, unless a
                    // restart put a new connection there in the meantime.
                    (Some(slot), None) => {
                        let mut slot = slot.clone();
                        let again = judged.get(id).filter(|j| {
                            slot.conn.as_ref().is_some_and(|c| Arc::ptr_eq(c, &j.conn))
                        });
                        if let Some(j) = again {
                            slot.drifted = Arc::clone(&j.drifted);
                            if let Some(poisoned) = &j.poisoned {
                                slot.poisoned = Arc::clone(poisoned);
                            }
                        }
                        slot
                    }
                    // Changed or added: its new tenure, and its new connection
                    // if that opened. A changed one that did not open keeps
                    // serving on its old connection.
                    (existing, Some((tenure, health))) => {
                        if let Some(conn) = existing.and_then(|old| old.conn.clone()) {
                            displaced.borrow_mut().insert(i, conn);
                        }
                        let credentials = p.server.options.credentials;
                        let mut slot = match existing {
                            Some(old) => Slot {
                                tenure: Arc::clone(tenure),
                                supervised: true,
                                credentials,
                                ..old.clone()
                            },
                            None => Slot::new(
                                id.to_string(),
                                Arc::clone(health),
                                Arc::clone(tenure),
                                true,
                                credentials,
                            ),
                        };
                        if let Some(Ok(opened)) = opened.get(&i) {
                            opened.fill(&mut slot);
                        }
                        slot
                    }
                    // Only a reconfiguration removes a place, and they run one
                    // at a time, so a place kept is still there.
                    (None, None) => continue,
                };
                slots.push(slot);
            }
            g.upstreams = slots;
            g.policy = Arc::clone(&policy);
            g.rbac = rbac.clone();
            g.policy_rules = Arc::clone(&rules);
            g.upstream_timeout = upstream_timeout;
            g.inspect = scanner.clone();
            g.prefixes = tool_prefixes.clone();
            g.reroute();
        });
        if let Some((per_tool, global)) = rate_limit {
            let limiter = RateLimiter::new(per_tool, global, Instant::now());
            self.inner
                .rate_limiter
                .store(limiter.map(|l| Arc::new(Mutex::new(l))));
        }

        let mut report = Reconfigured::default();
        // The keepers of upstreams removed stop, and those of upstreams changed
        // hand over to new ones.
        for slot in &current.upstreams {
            match upstreams.iter().position(|p| p.server.id == slot.id) {
                None => {
                    slot.tenure.retire();
                    eprintln!(
                        "mcpdef: upstream '{}' removed; the calls it carries finish first",
                        slot.id
                    );
                    report.removed.push(slot.id.clone());
                }
                Some(i) if fresh.contains_key(&i) => slot.tenure.retire(),
                Some(_) => {}
            }
        }
        let mut displaced = displaced.into_inner();
        for (i, p) in upstreams.into_iter().enumerate() {
            let Some((tenure, health)) = fresh.remove(&i) else {
                continue;
            };
            let id = p.server.id.clone();
            let changed = had.contains_key(id.as_str());
            let serving = displaced
                .remove(&i)
                .filter(|up| up.handle.down_reason().is_none());
            let mut backoff = Backoff::new();
            let (next, replacing) = match opened.remove(&i) {
                Some(Ok(o)) => {
                    let watch = o.upstream.handle.watch();
                    self.watch_tools(&id, o);
                    // This opening settles the upstream, whatever its keeper
                    // was doing. One retired while it started the upstream
                    // again never did, and the health it left `starting` is
                    // this place's still.
                    health.settle();
                    if changed {
                        eprintln!(
                            "mcpdef: upstream '{id}' reconnected with its new settings; the old \
                             connection closes once its calls finish"
                        );
                        if serving.is_none() {
                            // It was down, and is up again.
                            self.audit_upstream(&id, UpstreamEvent::Up).await;
                        }
                        report.reconnected.push(id);
                    } else {
                        eprintln!("mcpdef: upstream '{id}' added");
                        report.added.push(id);
                    }
                    (Next::Watch(watch), None)
                }
                Some(Err(e)) => {
                    let delay = backoff.next_delay();
                    let message = health.record_failure(&e);
                    // Settled as a keeper's failed attempt is: down until the
                    // next one, not starting.
                    health.settle();
                    let next_attempt = secs(delay);
                    match (changed, &serving) {
                        (true, Some(_)) => eprintln!(
                            "mcpdef: upstream '{id}': its new settings did not start: {message}; \
                             it keeps its old connection; next attempt in {next_attempt}"
                        ),
                        (true, None) => eprintln!(
                            "mcpdef: upstream '{id}': its new settings did not start: {message}; \
                             next attempt in {next_attempt}"
                        ),
                        (false, _) => {
                            eprintln!(
                                "mcpdef: upstream '{id}' did not start: {message}; next attempt \
                                 in {next_attempt}"
                            );
                            self.audit_upstream(&id, UpstreamEvent::Down).await;
                            report.added.push(id.clone());
                        }
                    }
                    report.failed.push((id, message));
                    (Next::Retry(delay), serving.map(|up| up.handle.watch()))
                }
                None => continue,
            };
            self.keep(p.server, health, tenure, backoff, next, replacing);
        }
        if let Err(e) = self.write_pins() {
            eprintln!("mcpdef: saving the pin store: {e:#}");
        }
        report
    }
}

/// A kept upstream's connection, and what its tools were judged on it.
struct Judged {
    conn: Arc<Upstream>,
    drifted: Arc<HashSet<String>>,
    /// Only when the scanner changed; otherwise its findings stand.
    poisoned: Option<Arc<HashSet<String>>>,
}
