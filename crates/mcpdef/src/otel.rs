// SPDX-License-Identifier: Apache-2.0
//! `[gateway.otel]`: the ledger's governed requests, sent as OpenTelemetry
//! spans to an OTLP/HTTP endpoint, such as evald's `:4318`.
//!
//! The exporter follows the ledger's file, as the console's live tail does:
//! each time records are appended, it reads them and sends their spans, made
//! by [`mcpdef_audit::otlp`], in one request. No call waits on it, and the
//! ledger is its buffer:
//!
//! - **An endpoint that cannot be reached**, or answers 429, 502, 503 or 504
//!   (the statuses OTLP/HTTP has a client try again on), holds back only the
//!   exporter. It tries again after its `Retry-After`, or after a second,
//!   twice as long each time up to a minute, and goes on from there with what
//!   was written meanwhile, oldest first.
//! - **An endpoint that refuses** the spans otherwise has them dropped, with
//!   a log line that says so.
//! - **A start** begins at the ledger's end: what was not sent before a
//!   restart is not sent after it. `mcpdef audit tail --format otlp` prints
//!   any record's span.

use crate::config::OtelConfig;
use crate::import::one_line;
use crate::listener::Fetching;
use crate::redact::redact_urls;
use arc_swap::ArcSwap;
use mcpdef_audit::{otlp, AuditError, Follow, Record};
use mcpdef_secrets::{ExposeSecret, SecretRef};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The most records one request holds: the OpenTelemetry SDKs' batch size.
const BATCH: usize = 512;

/// How long the exporter waits once a record is appended, so that the
/// records written meanwhile go in the same request.
const LINGER: Duration = Duration::from_secs(1);

/// The wait after a first failed send; each after it is twice as long, up to
/// [`BACKOFF_MAX`].
const BACKOFF: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How long the exporter waits before it follows the ledger again, after its
/// file could not be read.
const REOPEN: Duration = Duration::from_secs(30);

/// How much of a refusal's body the log line quotes.
const QUOTED: usize = 200;

/// The spans of the records appended to one ledger, sent to one endpoint.
pub struct Exporter {
    url: String,
    /// The URL as the log names it: a secret its query holds masked.
    shown: String,
    token: Option<SecretRef>,
    service: String,
    ledger: PathBuf,
    /// How the gateway's own requests go out: through its egress guard, with
    /// `[gateway.upstream_tls]`. A reload replaces it.
    fetching: Arc<ArcSwap<Fetching>>,
}

impl Exporter {
    pub fn new(cfg: &OtelConfig, ledger: PathBuf, fetching: Arc<ArcSwap<Fetching>>) -> Exporter {
        let url = cfg.traces_url();
        Exporter {
            shown: redact_urls(&url).into_owned(),
            url,
            token: cfg.token.clone(),
            service: cfg.service_name.trim().to_string(),
            ledger,
            fetching,
        }
    }

    /// Where the spans go, as the log names it.
    pub fn shown(&self) -> &str {
        &self.shown
    }

    /// Follow the ledger from the record after the one numbered `after`, or
    /// from its first when `None`, and send the span of each record appended,
    /// as `appends` says they are, until the ledger is closed.
    ///
    /// The ledger is opened now, so that no record appended before the task
    /// runs is missed.
    pub fn start(
        self,
        after: Option<u64>,
        appends: mcpdef_audit::Appends,
    ) -> Result<tokio::task::JoinHandle<()>, AuditError> {
        let follow = follow(&self.ledger, after)?;
        Ok(tokio::spawn(self.run(follow, appends)))
    }

    async fn run(self, follow: Follow, mut appends: mcpdef_audit::Appends) {
        let mut follow = Some(follow);
        let mut token: Option<String> = None;
        loop {
            let Some(reading) = follow.take() else {
                tokio::time::sleep(REOPEN).await;
                match blocking_follow(self.ledger.clone()).await {
                    Ok(reopened) => follow = Some(reopened),
                    Err(e) => eprintln!(
                        "mcpdef: otel: the ledger {} does not read: {e}",
                        self.ledger.display()
                    ),
                }
                continue;
            };
            let (reading, batch) = read(reading).await;
            let records = match batch {
                Ok(records) => {
                    follow = Some(reading);
                    records
                }
                Err(e) => {
                    // Cut short, replaced, or a line that does not read: the
                    // exporter goes on from the file's end as it is now, at
                    // once, and waits to try again only if it cannot.
                    eprintln!(
                        "mcpdef: otel: reading the ledger {} failed: {e}; the spans of the \
                         records from here to its end are not sent",
                        self.ledger.display()
                    );
                    match blocking_follow(self.ledger.clone()).await {
                        Ok(reopened) => follow = Some(reopened),
                        Err(e) => eprintln!(
                            "mcpdef: otel: the ledger {} does not read: {e}",
                            self.ledger.display()
                        ),
                    }
                    continue;
                }
            };
            if records.is_empty() {
                if !appends.wait().await {
                    return;
                }
                tokio::time::sleep(LINGER).await;
                continue;
            }
            if let Some(request) = otlp::request(&records, &self.service) {
                let spans = request["resourceSpans"][0]["scopeSpans"][0]["spans"]
                    .as_array()
                    .map_or(0, Vec::len);
                self.send(request.to_string().into_bytes(), spans, &mut token)
                    .await;
            }
        }
    }

    /// Send one request until the endpoint takes it or refuses it for good.
    async fn send(&self, body: Vec<u8>, spans: usize, token: &mut Option<String>) {
        let mut wait = BACKOFF;
        let mut failures = 0u32;
        let mut reread = false;
        loop {
            let why = match self.post(&body, token).await {
                Ok(posted) if (200..300).contains(&posted.status) => {
                    if failures > 0 {
                        eprintln!(
                            "mcpdef: otel: {} takes spans again, after {failures} failed tries",
                            self.shown
                        );
                    }
                    if let Some(rejected) = rejected(&posted.body) {
                        eprintln!(
                            "mcpdef: otel: {} took {spans} span(s) and rejected {rejected}",
                            self.shown
                        );
                    }
                    return;
                }
                // A token rotated in place is read again, once.
                Ok(posted) if posted.status == 401 && self.token.is_some() && !reread => {
                    reread = true;
                    *token = None;
                    continue;
                }
                Ok(posted) if matches!(posted.status, 429 | 502 | 503 | 504) => {
                    if let Some(after) = posted.retry_after {
                        wait = after.clamp(BACKOFF, BACKOFF_MAX);
                    }
                    format!("it answered {}", posted.status)
                }
                Ok(posted) => {
                    eprintln!(
                        "mcpdef: otel: {} refused {spans} span(s) with {}: {}; they are not \
                         sent again",
                        self.shown,
                        posted.status,
                        quoted(&posted.body, token.as_deref())
                    );
                    return;
                }
                Err(why) => why,
            };
            if failures == 0 {
                eprintln!(
                    "mcpdef: otel: sending {spans} span(s) to {} failed: {}; trying again, up to \
                     a minute apart",
                    self.shown,
                    one_line(&redact_urls(&why))
                );
            }
            failures += 1;
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(BACKOFF_MAX);
        }
    }

    /// One try: the token read when there is none yet, then the request.
    async fn post(
        &self,
        body: &[u8],
        token: &mut Option<String>,
    ) -> Result<mcpdef_transport::Posted, String> {
        if let (Some(secret), None) = (&self.token, &*token) {
            let secret = secret.clone();
            let read = tokio::task::spawn_blocking(move || secret.resolve())
                .await
                .map_err(|e| e.to_string())?;
            match read {
                Ok(value) => *token = Some(value.expose_secret().to_string()),
                Err(e) => return Err(format!("its token does not read: {e}")),
            }
        }
        let fetching = self.fetching.load_full();
        let tls = fetching.tls.load_async().await.map_err(|e| e.to_string())?;
        mcpdef_transport::post_json(
            &self.url,
            body.to_vec(),
            token.as_deref(),
            &fetching.egress,
            &tls,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// The ledger at `path`, from the record after the one numbered `after`, or
/// from its first.
fn follow(path: &Path, after: Option<u64>) -> Result<Follow, AuditError> {
    match after {
        Some(seq) => Follow::after(path, Some(seq)),
        None => Follow::start(path),
    }
}

/// The ledger at `path` from its end, once it has been read in error.
async fn blocking_follow(path: PathBuf) -> Result<Follow, AuditError> {
    tokio::task::spawn_blocking(move || Follow::after(&path, None))
        .await
        .map_err(|e| AuditError::Io(std::io::Error::other(e)))?
}

/// Up to [`BATCH`] records appended since `follow` last read, read off the
/// runtime's threads. `follow` comes back, unless the read failed.
async fn read(mut follow: Follow) -> (Follow, Result<Vec<Record>, AuditError>) {
    let (follow, read) = tokio::task::spawn_blocking(move || {
        let read = follow.read(BATCH);
        (follow, read)
    })
    .await
    .expect("reading the ledger does not panic");
    let records = read.map(|batch| batch.into_iter().map(|(record, _)| record).collect());
    (follow, records)
}

/// The start of a refusal's body, on one line, for the log: the token, should
/// the endpoint repeat it, masked, and any secret a URL in it holds.
fn quoted(body: &[u8], token: Option<&str>) -> String {
    let mut text: String = String::from_utf8_lossy(body)
        .trim()
        .chars()
        .take(QUOTED)
        .collect();
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        text = text.replace(token, "[token]");
    }
    one_line(&redact_urls(&text))
}

/// How many spans an `ExportTraceServiceResponse` says were rejected, when it
/// says any were: `partialSuccess.rejectedSpans`, a number or, as the
/// protobuf JSON mapping writes a 64-bit one, a string.
fn rejected(body: &[u8]) -> Option<u64> {
    let response: serde_json::Value = serde_json::from_slice(body).ok()?;
    let count = &response["partialSuccess"]["rejectedSpans"];
    let count = count
        .as_u64()
        .or_else(|| count.as_str().and_then(|s| s.parse().ok()))?;
    (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_quoted_on_one_line_without_the_token() {
        let body = b"evald: unauthorized, Bearer s3cr3t-t0ken-0123456789 is not one\r\nforged line";
        let line = quoted(body, Some("s3cr3t-t0ken-0123456789"));
        assert_eq!(
            line,
            "evald: unauthorized, Bearer [token] is not one\\r\\nforged line"
        );
        assert_eq!(quoted(&[b'x'; 500], None).len(), QUOTED);
    }

    #[test]
    fn a_partial_success_names_the_spans_it_rejected() {
        assert_eq!(rejected(br#"{"partialSuccess":null}"#), None);
        assert_eq!(rejected(b"{}"), None);
        assert_eq!(rejected(b""), None);
        assert_eq!(
            rejected(br#"{"partialSuccess":{"rejectedSpans":"3","errorMessage":"x"}}"#),
            Some(3)
        );
        assert_eq!(
            rejected(br#"{"partialSuccess":{"rejectedSpans":2}}"#),
            Some(2)
        );
        assert_eq!(
            rejected(br#"{"partialSuccess":{"rejectedSpans":"0"}}"#),
            None
        );
    }
}
