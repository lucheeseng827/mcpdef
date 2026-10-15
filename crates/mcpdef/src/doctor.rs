// SPDX-License-Identifier: Apache-2.0
//! `mcpdef doctor`: what is wrong with a gateway, or soon will be, in one
//! report.
//!
//! The checks here take what was read or measured and say what it means. The
//! binary does the reading: the config and its own warnings, the listeners'
//! certificates as `mcpdef tls show` reads them, a `GET` of the identity
//! provider, and the upstreams as a gateway opened like `mcpdef run`'s finds
//! them ([`examine`](crate::connect::examine)). So doctor holds no second
//! opinion of its own: it says what the gateway would.

use crate::config::{GatewayConfig, ServerConfig};
use crate::gateway::{HealthState, ToolCost, UpstreamStatus};
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A certificate that ends within this many days is said to.
pub const EXPIRY_WARN_DAYS: i64 = 14;

/// How a finding reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// Checked, and as it should be.
    Ok,
    /// Said for what it tells, neither good nor bad.
    Note,
    /// Works, but should not be left as it is.
    Warn,
    /// Does not work, or is not safe, as it is.
    Fail,
}

impl Mark {
    fn symbol(self) -> &'static str {
        match self {
            Mark::Ok => "✓",
            Mark::Note => "·",
            Mark::Warn => "⚠",
            Mark::Fail => "✗",
        }
    }
}

/// One line of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub mark: Mark,
    pub text: String,
}

impl Finding {
    pub fn ok(text: impl Into<String>) -> Finding {
        Finding::new(Mark::Ok, text)
    }

    pub fn note(text: impl Into<String>) -> Finding {
        Finding::new(Mark::Note, text)
    }

    pub fn warn(text: impl Into<String>) -> Finding {
        Finding::new(Mark::Warn, text)
    }

    pub fn fail(text: impl Into<String>) -> Finding {
        Finding::new(Mark::Fail, text)
    }

    fn new(mark: Mark, text: impl Into<String>) -> Finding {
        Finding {
            mark,
            text: text.into(),
        }
    }
}

/// A titled part of the report.
#[derive(Debug)]
pub struct Section {
    pub title: &'static str,
    pub findings: Vec<Finding>,
}

impl Section {
    pub fn new(title: &'static str) -> Section {
        Section {
            title,
            findings: Vec::new(),
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// How many of its findings are marked `mark`.
    pub fn count(&self, mark: Mark) -> usize {
        self.findings.iter().filter(|f| f.mark == mark).count()
    }

    pub fn render(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "{}", self.title)?;
        for finding in &self.findings {
            writeln!(out, "  {} {}", finding.mark.symbol(), finding.text)?;
        }
        writeln!(out)
    }
}

/// The admin listener: off; open to this machine alone; open to others that
/// must each present a client certificate, which its TLS checks at the
/// handshake; open to others who sign in at the identity provider, or bring
/// the break-glass token; open to others behind a proxy said to authenticate
/// them; or open to others with no sign-in at all, which `validate` refuses.
pub fn admin(g: &GatewayConfig) -> Finding {
    let admin = &g.admin;
    if !admin.enabled {
        return Finding::note("not enabled");
    }
    if admin.listens_locally() {
        return Finding::ok(format!("{}: this machine only", admin.listen));
    }
    if g.admin_requires_certificates() {
        return Finding::ok(format!(
            "{}: other machines reach it, and each must present a client certificate",
            admin.listen
        ));
    }
    if admin.oidc.is_some() {
        let or_token = match admin.break_glass {
            Some(_) => ", or brings the break-glass token",
            None => "",
        };
        return Finding::ok(format!(
            "{}: other machines reach it, and each person signs in at the identity \
             provider{or_token}",
            admin.listen
        ));
    }
    if admin.break_glass.is_some() {
        return Finding::ok(format!(
            "{}: other machines reach it, and only the break-glass token is let in",
            admin.listen
        ));
    }
    if admin.allow_unauthenticated {
        return Finding::warn(format!(
            "[gateway.admin] listen = \"{}\" takes connections from other machines with \
             allow_unauthenticated: whoever the proxy in front lets through reads the audit \
             ledger and acts as console:admin. Make sure it authenticates every request",
            admin.listen
        ));
    }
    Finding::warn(format!(
        "[gateway.admin] listen = \"{}\" takes connections from other machines, and the admin \
         listener asks no one who they are: whoever reaches it reads each server's status, the \
         metrics and the audit ledger. Listen on 127.0.0.1, or keep it behind a network policy \
         of your own",
        admin.listen
    ))
}

/// What the difference between this machine's clock and an identity
/// provider's means for its tokens.
///
/// `sent` and `received` bracket the request on this machine's clock, and
/// `date` is the time the provider's `Date` header gave, whole seconds,
/// rounded down. `leeway` is the difference a token's times are allowed
/// ([`mcpdef_auth::clock_leeway`]).
pub fn clock(
    sent: SystemTime,
    received: SystemTime,
    date: SystemTime,
    leeway: Duration,
) -> Finding {
    let ours = unix_ms(sent) + (unix_ms(received) - unix_ms(sent)) / 2;
    // The header drops the fraction of its second: half of one on average.
    let theirs = unix_ms(date) + 500;
    let ahead_ms = ours - theirs;
    let off_ms = ahead_ms.unsigned_abs();
    let leeway_ms = u64::try_from(leeway.as_millis()).unwrap_or(u64::MAX);
    let allowed = leeway.as_secs();
    if off_ms <= leeway_ms {
        return Finding::ok(format!(
            "this machine's clock is within {}s of the identity provider's ({allowed}s allowed)",
            seconds(off_ms)
        ));
    }
    let (off, beyond) = (span(seconds(off_ms)), span(seconds(off_ms - leeway_ms)));
    if ahead_ms > 0 {
        Finding::fail(format!(
            "this machine's clock is {off} ahead of the identity provider's, more than the \
             {allowed}s a token's times are allowed: every token expires here {beyond} early, \
             and one that lives less than that is refused as soon as it is issued. Set the \
             clock right, by NTP"
        ))
    } else {
        Finding::fail(format!(
            "this machine's clock is {off} behind the identity provider's, more than the \
             {allowed}s a token's times are allowed: a token with a `nbf` is refused as not \
             valid yet for its first {beyond}. Set the clock right, by NTP"
        ))
    }
}

/// Milliseconds to the nearest second.
fn seconds(ms: u64) -> u64 {
    ms.saturating_add(500) / 1000
}

/// One upstream as the gateway found it on opening it: whether it is up,
/// what it offers that its config exposes none of, and the certificates
/// near their end. `cost` is what it adds to `tools/list`.
pub fn upstream(
    server: &ServerConfig,
    status: &UpstreamStatus,
    cost: Option<&ToolCost>,
    now: SystemTime,
) -> Vec<Finding> {
    let id = &status.id;
    let why = || {
        status
            .last_error
            .as_ref()
            .map_or("no error was recorded", |e| e.message.as_str())
    };
    let mut findings = vec![match status.health {
        HealthState::Up => Finding::ok(format!("{id}: up{}", tools(cost))),
        HealthState::Degraded => Finding::warn(format!(
            "{id}: up, but its last call failed: {}{}",
            why(),
            tools(cost)
        )),
        HealthState::Down => Finding::fail(format!("{id}: down: {}", why())),
        HealthState::Starting => Finding::warn(format!("{id}: still opening")),
    }];

    if let Some(offers) = status.offers {
        if offers.resources && server.resource_policy().is_empty() {
            findings.push(Finding::warn(format!(
                "{id} offers resources, and no client sees them: it has no `resources` list, \
                 and an unset list exposes none. Before 0.4.0, the first server's resources \
                 went to any client that asked, ungoverned. To expose them, list their URIs, \
                 as `resources = [\"file:///docs/**\"]`, or `[\"*\"]` for all"
            )));
        }
        if offers.prompts && server.prompts.as_ref().is_none_or(Vec::is_empty) {
            findings.push(Finding::warn(format!(
                "{id} offers prompts, and no client sees them: it has no `prompts` list, and an \
                 unset list exposes none. Before 0.4.0, the first server's prompts went to any \
                 client that asked, ungoverned. To expose them, list them by name, or \
                 `prompts = [\"*\"]` for all"
            )));
        }
    }

    if let Some(tls) = &status.tls {
        let certificates = [
            (tls.not_after_unix, "the certificate it presents"),
            (
                tls.client_not_after_unix,
                "the certificate MCPdef presents to it",
            ),
        ];
        for (not_after, which) in certificates {
            let Some(not_after) = not_after else { continue };
            let days = days_until(not_after, now);
            if days < 0 {
                findings.push(Finding::fail(format!("{id}: {which} has expired")));
            } else if days < EXPIRY_WARN_DAYS {
                findings.push(Finding::warn(format!(
                    "{id}: {which} expires in {days} days: renew it"
                )));
            }
        }
    }
    findings
}

/// `, N tools listed, M bytes (~T tokens)`: what an upstream adds to every
/// `tools/list`, which every agent that lists them reads into its context.
fn tools(cost: Option<&ToolCost>) -> String {
    let Some(cost) = cost else {
        return String::new();
    };
    format!(
        ", {} of its {} tools listed, {} bytes (~{} tokens)",
        cost.listed,
        cost.offered,
        cost.bytes,
        ToolCost::tokens(cost.bytes)
    )
}

/// Days from `now` to `secs` since the Unix epoch, rounded down.
fn days_until(secs: i64, now: SystemTime) -> i64 {
    let now = unix_ms(now) / 1000;
    (secs - now).div_euclid(86_400)
}

/// Milliseconds since the Unix epoch, negative before it.
fn unix_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// A span of `s` seconds as a person says it: `45s`, `7m 5s`, `2h 3m`.
fn span(s: u64) -> String {
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, s % 3600 / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::gateway::{LastError, Offers, TlsStatus};

    const LEEWAY: Duration = Duration::from_secs(60);

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A request answered at once, at `ours` on this machine's clock, by a
    /// server whose clock read `theirs`.
    fn skew(ours: u64, theirs: u64) -> Finding {
        clock(at(ours), at(ours), at(theirs), LEEWAY)
    }

    #[test]
    fn a_clock_within_the_leeway_is_fine_either_way() {
        for theirs in [1_000_000, 1_000_030, 999_970, 1_000_059, 999_941] {
            let finding = skew(1_000_000, theirs);
            assert_eq!(finding.mark, Mark::Ok, "{theirs}: {}", finding.text);
        }
    }

    /// Behind the provider, a fresh token is not valid yet here, which is
    /// how a token with a `nbf` fails.
    #[test]
    fn a_clock_behind_the_provider_refuses_fresh_tokens() {
        let finding = skew(1_000_000, 1_000_000 + 7 * 60);
        assert_eq!(finding.mark, Mark::Fail);
        assert!(finding.text.contains("behind"), "{}", finding.text);
        assert!(finding.text.contains("7m"), "{}", finding.text);
        assert!(finding.text.contains("not valid yet"), "{}", finding.text);
    }

    /// Ahead of it, tokens expire early here. (7m and a second by the
    /// header, which drops the half second the provider's clock had on it.)
    #[test]
    fn a_clock_ahead_of_the_provider_expires_tokens_early() {
        let finding = skew(1_000_000 + 7 * 60 + 1, 1_000_000);
        assert_eq!(finding.mark, Mark::Fail);
        assert!(finding.text.contains("ahead"), "{}", finding.text);
        assert!(finding.text.contains("expires here 6m"), "{}", finding.text);
    }

    /// The time the answer took is split down the middle: the provider wrote
    /// its `Date` somewhere between the request and the answer.
    #[test]
    fn the_skew_is_taken_at_the_middle_of_the_request() {
        // Sent at 0 and answered at 200 on this clock; the provider said 100.
        // Ours, at the middle, is 100: no skew, not 100s of it.
        let finding = clock(at(1_000_000), at(1_000_200), at(1_000_100), LEEWAY);
        assert_eq!(finding.mark, Mark::Ok, "{}", finding.text);
    }

    fn config(toml: &str) -> Config {
        Config::parse(toml).unwrap()
    }

    #[test]
    fn an_admin_listener_on_another_address_is_said_to_be_exposed() {
        let open = "[gateway.admin]\nenabled = true\nlisten = \"0.0.0.0:7879\"\n";
        let finding = admin(&config(open).gateway);
        assert_eq!(finding.mark, Mark::Warn);
        assert!(finding.text.contains("audit ledger"), "{}", finding.text);

        for listen in ["127.0.0.1:7879", "[::1]:7879", "localhost:7879"] {
            let local = config(&format!(
                "[gateway.admin]\nenabled = true\nlisten = \"{listen}\""
            ));
            assert_eq!(admin(&local.gateway).mark, Mark::Ok, "{listen}");
        }
        let off = config("[gateway.admin]\nlisten = \"0.0.0.0:7879\"");
        assert_eq!(admin(&off.gateway).mark, Mark::Note);

        // A client certificate each must present is a sign-in of its own; one
        // they may present is not.
        let certificates = |mode: &str| {
            config(&format!(
                "{open}[gateway.admin.tls]\nmode = \"self-signed\"\n\
                 [gateway.admin.tls.client_auth]\nmode = \"{mode}\"\nca = [\"/ca.pem\"]\n\
                 identity = \"subject-cn\""
            ))
        };
        assert_eq!(admin(&certificates("required").gateway).mark, Mark::Ok);
        assert_eq!(admin(&certificates("optional").gateway).mark, Mark::Warn);

        // People who sign in at the identity provider, or the break-glass
        // token alone: no certificate is asked for, and none is said to be.
        let oidc = "public_url = \"https://console.example\"\n\n\
                    [gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n";
        let token = format!(
            "[gateway.admin.break_glass]\ntoken_sha256 = \"{}\"\n",
            "0".repeat(64)
        );
        for (with, said) in [
            (
                oidc.to_string(),
                "each person signs in at the identity provider",
            ),
            (
                format!("{oidc}\n{token}"),
                "signs in at the identity provider, or brings the break-glass token",
            ),
            (token.clone(), "only the break-glass token is let in"),
        ] {
            let finding = admin(&config(&format!("{open}{with}")).gateway);
            assert_eq!(finding.mark, Mark::Ok, "{}", finding.text);
            assert!(finding.text.contains(said), "{}", finding.text);
            assert!(!finding.text.contains("certificate"), "{}", finding.text);
        }

        // Behind a proxy said to authenticate: allowed, and said to rely on it.
        let proxied = config(&format!("{open}allow_unauthenticated = true\n"));
        let finding = admin(&proxied.gateway);
        assert_eq!(finding.mark, Mark::Warn);
        assert!(
            finding.text.contains("authenticates every request"),
            "{}",
            finding.text
        );
    }

    fn status(health: HealthState) -> UpstreamStatus {
        UpstreamStatus {
            id: "files".into(),
            health,
            restarts: 0,
            last_error: None,
            tls: None,
            credential: None,
            auth_failures: 0,
            tool_collisions: Vec::new(),
            offers: None,
        }
    }

    fn server(lists: &str) -> ServerConfig {
        let cfg = config(&format!(
            "[gateway]\n[[server]]\nid = \"files\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n{lists}"
        ));
        cfg.servers.into_iter().next().unwrap()
    }

    #[test]
    fn a_down_upstream_fails_with_why() {
        let mut down = status(HealthState::Down);
        down.last_error = Some(LastError {
            message: "spawning upstream 'files': No such file or directory".into(),
            at_unix_ms: 0,
        });
        let findings = upstream(&server(""), &down, None, at(0));
        assert_eq!(findings[0].mark, Mark::Fail);
        assert!(findings[0].text.contains("No such file"), "{findings:?}");
    }

    /// What a server offers that no list of its config exposes is said, with
    /// what it was before: the change an upgrade would otherwise find only by
    /// missing them.
    #[test]
    fn offers_no_list_exposes_are_said() {
        let mut up = status(HealthState::Up);
        up.offers = Some(Offers {
            resources: true,
            prompts: true,
            tools_list_changed: false,
        });
        let findings = upstream(&server(""), &up, None, at(0));
        let warned: Vec<&str> = findings
            .iter()
            .filter(|f| f.mark == Mark::Warn)
            .map(|f| f.text.as_str())
            .collect();
        assert_eq!(warned.len(), 2, "{findings:?}");
        assert!(warned[0].contains("offers resources"), "{warned:?}");
        assert!(warned[0].contains("Before 0.4.0"), "{warned:?}");
        assert!(warned[1].contains("offers prompts"), "{warned:?}");

        // Listed, they are exposed, and nothing is said.
        let listed = server("resources = [\"file:///**\"]\nprompts = [\"*\"]");
        let findings = upstream(&listed, &up, None, at(0));
        assert!(findings.iter().all(|f| f.mark == Mark::Ok), "{findings:?}");
    }

    #[test]
    fn certificates_near_their_end_are_said() {
        let now = 1_000_000_000;
        let mut up = status(HealthState::Up);
        up.tls = Some(TlsStatus {
            verify: "ca",
            fingerprint: None,
            not_after: None,
            not_after_unix: Some(now + 3 * 86_400),
            client_not_after: None,
            client_not_after_unix: Some(now - 1),
        });
        let findings = upstream(&server(""), &up, None, at(now as u64));
        assert!(
            findings
                .iter()
                .any(|f| f.mark == Mark::Warn && f.text.contains("expires in 3 days")),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.mark == Mark::Fail && f.text.contains("MCPdef presents")),
            "{findings:?}"
        );
    }

    #[test]
    fn spans_read_as_people_say_them() {
        assert_eq!(span(45), "45s");
        assert_eq!(span(425), "7m 5s");
        assert_eq!(span(7380), "2h 3m");
    }

    /// The header's second is taken at its middle, and the difference is
    /// said to the nearest second: wherever in its second the provider's
    /// clock was, ten minutes ahead reads as ten minutes, never 9m 59s.
    #[test]
    fn a_skew_reads_the_same_wherever_in_its_second_it_was_taken() {
        let date = at(1_000_600);
        for ms in [0, 1, 250, 499, 500, 501, 750, 999] {
            let ours = UNIX_EPOCH + Duration::from_millis(1_000_000_000 + ms);
            let finding = clock(ours, ours, date, LEEWAY);
            assert!(
                finding.text.contains("is 10m "),
                "{ms}ms into the second: {}",
                finding.text
            );
        }
    }
}
