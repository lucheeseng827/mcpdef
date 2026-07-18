// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-ratelimit` — token-bucket rate limiting for the gateway hot path.
//!
//! MCPdef is **in the data path of every agent action**, so it is a single choke
//! point and must defend its own availability, not only the upstreams
//! (ARCHITECTURE.md §5b). A runaway agent that floods `tools/call` must not be
//! able to starve others or wedge the gateway. This crate is a small,
//! dependency-free **token bucket**: each call refills the bucket by the elapsed
//! time × rate, then tries to spend one token; an empty bucket sheds the call
//! (the gateway turns that into a `rate-limited` deny + audit, the stdio analog
//! of a `429`).
//!
//! Two scopes compose: an optional **global** bucket (protects the whole
//! gateway) and an optional **per-tool** bucket (one runaway tool can't starve
//! the rest). Per-agent / per-principal limiting layers on with Phase-2 auth,
//! once calls carry a real authenticated identity.
//!
//! The clock is **injected** (`now: Instant`) so behavior is deterministic and
//! testable without sleeps — callers pass `Instant::now()`; tests pass a base
//! instant plus offsets.

use std::collections::HashMap;
use std::time::Instant;

/// A classic token bucket: `capacity` tokens max, refilling at `refill_per_sec`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket as of `now`.
    pub fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: now,
        }
    }

    /// Refill for the time elapsed since the last call, then try to spend one
    /// token. Returns `true` if a token was available (call allowed).
    pub fn try_acquire(&mut self, now: Instant) -> bool {
        // `saturating_duration_since`: Instant is monotonic, but never panic if a
        // caller passes a `now` before `last`.
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Which bucket shed a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// The gateway-wide bucket.
    Global,
    /// The bucket for one specific tool.
    Tool,
}

impl LimitScope {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitScope::Global => "global",
            LimitScope::Tool => "tool",
        }
    }
}

/// The decision for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Limited(LimitScope),
}

impl RateDecision {
    pub fn is_allow(self) -> bool {
        matches!(self, RateDecision::Allow)
    }
}

/// A per-tool + global token-bucket rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// `(capacity, refill_per_sec)` template for lazily-created per-tool buckets.
    tool_template: Option<(f64, f64)>,
    per_tool: HashMap<String, TokenBucket>,
    global: Option<TokenBucket>,
}

impl RateLimiter {
    /// Build a limiter from optional `(refill_per_sec, burst_capacity)` settings
    /// for the per-tool and global scopes. Returns `None` when neither is set —
    /// i.e. rate limiting is off and the caller skips it entirely.
    pub fn new(
        per_tool: Option<(f64, f64)>,
        global: Option<(f64, f64)>,
        now: Instant,
    ) -> Option<Self> {
        if per_tool.is_none() && global.is_none() {
            return None;
        }
        Some(RateLimiter {
            // store as (capacity, refill_per_sec) for TokenBucket::new
            tool_template: per_tool.map(|(rate, burst)| (burst, rate)),
            per_tool: HashMap::new(),
            global: global.map(|(rate, burst)| TokenBucket::new(burst, rate, now)),
        })
    }

    /// Check + spend one token for `tool`. The **global** bucket is checked first
    /// (it guards the whole gateway); if it sheds the call, the per-tool bucket is
    /// left untouched. A global token spent on a call the per-tool bucket then
    /// rejects is an accepted approximation for a load-shedding heuristic.
    pub fn check(&mut self, tool: &str, now: Instant) -> RateDecision {
        if let Some(global) = &mut self.global {
            if !global.try_acquire(now) {
                return RateDecision::Limited(LimitScope::Global);
            }
        }
        if let Some((capacity, refill)) = self.tool_template {
            let bucket = self
                .per_tool
                .entry(tool.to_string())
                .or_insert_with(|| TokenBucket::new(capacity, refill, now));
            if !bucket.try_acquire(now) {
                return RateDecision::Limited(LimitScope::Tool);
            }
        }
        RateDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let t0 = Instant::now();
        // capacity 3, 1 token/sec.
        let mut b = TokenBucket::new(3.0, 1.0, t0);
        assert!(b.try_acquire(t0)); // 3 -> 2
        assert!(b.try_acquire(t0)); // 2 -> 1
        assert!(b.try_acquire(t0)); // 1 -> 0
        assert!(!b.try_acquire(t0)); // empty -> shed

        // After 1s, one token refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.try_acquire(t1)); // 1 -> 0
        assert!(!b.try_acquire(t1)); // empty again

        // Refill is capped at capacity (10s of idle doesn't exceed 3).
        let t2 = t1 + Duration::from_secs(10);
        assert!(b.try_acquire(t2));
        assert!(b.try_acquire(t2));
        assert!(b.try_acquire(t2));
        assert!(!b.try_acquire(t2));
    }

    #[test]
    fn none_when_no_limits_configured() {
        assert!(RateLimiter::new(None, None, Instant::now()).is_none());
    }

    #[test]
    fn per_tool_buckets_are_isolated() {
        let t0 = Instant::now();
        // per-tool: 1 token/sec, burst 2. No global.
        let mut rl = RateLimiter::new(Some((1.0, 2.0)), None, t0).unwrap();
        assert!(rl.check("a", t0).is_allow()); // a: 2 -> 1
        assert!(rl.check("a", t0).is_allow()); // a: 1 -> 0
        assert_eq!(rl.check("a", t0), RateDecision::Limited(LimitScope::Tool));
        // A different tool has its own budget.
        assert!(rl.check("b", t0).is_allow());
        assert!(rl.check("b", t0).is_allow());
        assert_eq!(rl.check("b", t0), RateDecision::Limited(LimitScope::Tool));
    }

    #[test]
    fn global_caps_across_tools() {
        let t0 = Instant::now();
        // global: 1 token/sec, burst 2. No per-tool.
        let mut rl = RateLimiter::new(None, Some((1.0, 2.0)), t0).unwrap();
        assert!(rl.check("a", t0).is_allow()); // global 2 -> 1
        assert!(rl.check("b", t0).is_allow()); // global 1 -> 0 (different tool, same global)
        assert_eq!(rl.check("c", t0), RateDecision::Limited(LimitScope::Global));
    }

    #[test]
    fn global_checked_before_tool() {
        let t0 = Instant::now();
        // global burst 1; per-tool burst 5. Global is the binding constraint.
        let mut rl = RateLimiter::new(Some((1.0, 5.0)), Some((1.0, 1.0)), t0).unwrap();
        assert!(rl.check("a", t0).is_allow());
        assert_eq!(rl.check("a", t0), RateDecision::Limited(LimitScope::Global));
    }
}
