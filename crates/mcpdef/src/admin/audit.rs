// SPDX-License-Identifier: Apache-2.0
//! The audit API: the ledger a page at a time, one record by its `seq`, the
//! chain verified, the ledger exported, and records as they are appended.
//! Each reads the file from where it needs to, never the whole of it for a
//! page, and off the async threads.

use super::{problem, AdminState};
use axum::{
    body::{Body, Bytes},
    extract::{rejection::QueryRejection, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::get,
    Router,
};
use mcpdef_audit::{AuditError, Cursor, ExportFormat, Filter, Follow};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

/// A page's records unless it asks for fewer or more, and the most it may.
const PAGE: usize = 50;
const PAGE_MAX: usize = 500;
/// The bare list's, for `?limit` alone, as before pages.
const LIST: usize = 100;
const LIST_MAX: usize = 1000;
/// The most records a filtered page reads looking for matches: one that
/// finds too few stops short, with a cursor to go on from.
const SCAN_BUDGET: u64 = 100_000;
/// Records read from the file at a time, for a stream or an export.
const BATCH: usize = 500;
/// How many streams, and how many exports, the listener serves at once.
const STREAMS: usize = 64;
const EXPORTS: usize = 4;
/// How long a stream runs before the listener ends it: the browser comes
/// back at once, from the last record it had, and its caller is checked
/// again.
const STREAM_FOR: Duration = Duration::from_secs(10 * 60);
/// How long a browser waits before it comes back.
const RECONNECT: Duration = Duration::from_secs(2);
/// How often an idle stream says it is still there.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// What the audit API keeps between requests: one verify runs at a time, and
/// streams and exports are counted.
pub(crate) struct Reads {
    verifying: Semaphore,
    streams: Arc<Semaphore>,
    exports: Arc<Semaphore>,
}

impl Default for Reads {
    fn default() -> Reads {
        Reads {
            verifying: Semaphore::new(1),
            streams: Arc::new(Semaphore::new(STREAMS)),
            exports: Arc::new(Semaphore::new(EXPORTS)),
        }
    }
}

/// The audit API, for a viewer.
pub(super) fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/api/v1/audit", get(list))
        .route("/api/v1/audit/verify", get(verify))
        .route("/api/v1/audit/export", get(export))
        .route("/api/v1/audit/stream", get(stream))
        .route("/api/v1/audit/{seq}", get(one))
}

/// The records a read wants, as a query names them. Every member is text, so
/// that a query's numbers are read here, with a reason when one is not.
#[derive(Deserialize, Default)]
struct Wanted {
    decision: Option<String>,
    server: Option<String>,
    tool: Option<String>,
    agent: Option<String>,
    rule: Option<String>,
    kind: Option<String>,
    since: Option<String>,
    until: Option<String>,
}

impl Wanted {
    fn is_empty(&self) -> bool {
        [
            &self.decision,
            &self.server,
            &self.tool,
            &self.agent,
            &self.rule,
            &self.kind,
            &self.since,
            &self.until,
        ]
        .iter()
        .all(|member| member.is_none())
    }

    fn filter(self) -> Result<Filter, Refused> {
        if let Some(decision) = &self.decision {
            if decision != "allow" && decision != "deny" {
                return Err(bad(format!("decision is allow or deny, not {decision:?}")));
            }
        }
        Ok(Filter {
            since: number("since", self.since.as_deref())?,
            until: number("until", self.until.as_deref())?,
            decision: self.decision,
            server: self.server,
            tool: self.tool,
            agent: self.agent,
            rule: self.rule,
            kind: self.kind,
        })
    }
}

/// A query member that is a whole number, if it is there.
fn number(name: &str, text: Option<&str>) -> Result<Option<u64>, Refused> {
    text.map(|t| {
        t.parse()
            .map_err(|_| bad(format!("{name} is a whole number, not {t:?}")))
    })
    .transpose()
}

/// Why a request gets no records: a request that is not one (`400`), or a
/// read that failed (`500`), each answered as a problem document.
enum Refused {
    Bad(String),
    Failed(String),
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        match self {
            Refused::Bad(detail) => problem(StatusCode::BAD_REQUEST, "Bad request", detail),
            Refused::Failed(detail) => problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit read failed",
                format!("audit read failed: {detail}"),
            ),
        }
    }
}

fn bad(detail: impl Into<String>) -> Refused {
    Refused::Bad(detail.into())
}

/// The query, or why it is not one.
fn query<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, Refused> {
    query.map(|Query(q)| q).map_err(|e| bad(e.body_text()))
}

/// Runs a read of the ledger off the async threads.
async fn blocking<T: Send + 'static>(
    read: impl FnOnce() -> Result<T, AuditError> + Send + 'static,
) -> Result<T, Refused> {
    match tokio::task::spawn_blocking(read).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(AuditError::Cursor(why))) => Err(bad(why)),
        Ok(Err(e)) => Err(Refused::Failed(e.to_string())),
        Err(e) => Err(Refused::Failed(e.to_string())),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<String>,
    #[serde(flatten)]
    wanted: Wanted,
}

/// `GET /api/v1/audit`: with a `cursor` (empty for the first page) or a
/// filter, a page of records newest first, and where the next one starts;
/// with `limit` alone, or nothing, the newest records as a bare list, as
/// the built-in page and scripts read them.
async fn list(
    State(s): State<Arc<AdminState>>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Response, Refused> {
    let q = query(q)?;
    let paged = q.cursor.is_some() || !q.wanted.is_empty();
    let limit = match (q.limit.as_deref(), paged) {
        (None, true) => PAGE,
        (None, false) => LIST,
        (Some(text), true) => text
            .parse()
            .ok()
            .filter(|n| (1..=PAGE_MAX).contains(n))
            .ok_or_else(|| {
                bad(format!(
                    "limit is a whole number from 1 to {PAGE_MAX}, not {text:?}"
                ))
            })?,
        (Some(text), false) => text
            .parse::<usize>()
            .map_err(|_| bad(format!("limit is a whole number, not {text:?}")))?
            .min(LIST_MAX),
    };
    let cursor = match q.cursor.as_deref() {
        None | Some("") => None,
        Some(text) => Some(Cursor::parse(text).ok_or_else(|| bad("not a cursor this API gave"))?),
    };
    let filter = q.wanted.filter()?;
    let path = s.audit_path.clone();
    let page =
        blocking(move || mcpdef_audit::page(&path, cursor, limit, &filter, SCAN_BUDGET)).await?;
    Ok(match paged {
        true => Json(serde_json::json!({
            "records": page.records,
            "next_cursor": page.next.map(|c| c.to_string()),
        }))
        .into_response(),
        false => Json(page.records).into_response(),
    })
}

/// `GET /api/v1/audit/{seq}`: one record.
async fn one(
    State(s): State<Arc<AdminState>>,
    Path(seq): Path<String>,
) -> Result<Response, Refused> {
    let n = seq
        .parse::<u64>()
        .map_err(|_| bad(format!("{seq:?} is not a record's seq")))?;
    let path = s.audit_path.clone();
    Ok(
        match blocking(move || mcpdef_audit::find(&path, n)).await? {
            Some(record) => Json(record).into_response(),
            None => problem(
                StatusCode::NOT_FOUND,
                "Not found",
                format!("the ledger holds no record {n}"),
            ),
        },
    )
}

#[derive(Deserialize)]
struct VerifyQuery {
    head: Option<String>,
    count: Option<String>,
}

/// `GET /api/v1/audit/verify`: the chain checked from its first record, and
/// against a point it must still hold: the `head` and `count` of a seal kept
/// elsewhere, when given, else how far this gateway has written. A ledger
/// cut short or replaced since that point fails, though its own chain holds.
async fn verify(
    State(s): State<Arc<AdminState>>,
    q: Result<Query<VerifyQuery>, QueryRejection>,
) -> Result<Response, Refused> {
    let q = query(q)?;
    let seal = match (q.head, q.count) {
        (Some(head), Some(count)) => {
            let count = number("count", Some(&count))?.unwrap_or_default();
            Some((count, head))
        }
        (None, None) => None,
        _ => return Err(bad("head and count go together")),
    };
    // One at a time: a verify reads the whole file.
    let _turn = s.reads.verifying.acquire().await;
    // Taken before the file is read, which holds at least these records.
    let (against, who, (count, head)) = match seal {
        Some(seal) => ("seal", "the seal names", seal),
        None => ("written", "this gateway wrote", s.gateway.audit_written()),
    };
    let path = s.audit_path.clone();
    let mark = count.checked_sub(1);
    let (report, marked) = blocking(move || mcpdef_audit::verify_marked(&path, mark)).await?;
    let (broken_at, reason) = match report.broken_at {
        Some(seq) => (Some(seq), Some(format!("the chain breaks at record {seq}"))),
        None if report.records < count => (
            Some(report.records),
            Some(format!(
                "the file holds {} records, and {who} {count}: records were removed from its end",
                report.records
            )),
        ),
        None if count > 0 && marked.as_deref() != Some(head.as_str()) => (
            Some(count - 1),
            Some(format!(
                "record {} is not the one {who}: the ledger was replaced",
                count - 1
            )),
        ),
        None => (None, None),
    };
    Ok(Json(serde_json::json!({
        "ok": broken_at.is_none(),
        "records": report.records,
        "head": report.head,
        "broken_at": broken_at,
        "ambiguous": report.ambiguous,
        "against": { "kind": against, "records": count, "head": head },
        "reason": reason,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    #[serde(flatten)]
    wanted: Wanted,
}

/// `GET /api/v1/audit/export?format=json|ocsf|cef|syslog`: the records a
/// filter wants, first to last, one line each in the format `mcpdef audit
/// tail` writes, streamed as they are read.
async fn export(
    State(s): State<Arc<AdminState>>,
    q: Result<Query<ExportQuery>, QueryRejection>,
) -> Result<Response, Refused> {
    let q = query(q)?;
    let format = q
        .format
        .as_deref()
        .and_then(ExportFormat::parse)
        .ok_or_else(|| {
            bad(format!(
                "format is one of {}",
                ExportFormat::NAMES.join(", ")
            ))
        })?;
    let filter = q.wanted.filter()?;
    let Ok(permit) = Arc::clone(&s.reads.exports).try_acquire_owned() else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many exports",
            format!("this listener runs {EXPORTS} exports at once, the most it will"),
        ));
    };
    let path = s.audit_path.clone();
    let mut follow = blocking(move || Follow::start(&path)).await?;
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        loop {
            let batch = match follow.read(BATCH) {
                Ok(batch) if batch.is_empty() => return,
                Ok(batch) => batch,
                Err(e) => {
                    let _ = tx.blocking_send(Err(std::io::Error::other(e)));
                    return;
                }
            };
            let mut out = String::new();
            for (record, _) in batch.iter().filter(|(r, _)| filter.matches(r)) {
                out.push_str(&record.export(format));
                out.push('\n');
            }
            if !out.is_empty() && tx.blocking_send(Ok(Bytes::from(out))).is_err() {
                return;
            }
        }
    });
    let (content_type, file) = match format {
        ExportFormat::Json => ("application/x-ndjson", "mcpdef-audit.jsonl"),
        ExportFormat::Ocsf => ("application/x-ndjson", "mcpdef-audit.ocsf.jsonl"),
        ExportFormat::Cef => ("text/plain; charset=utf-8", "mcpdef-audit.cef"),
        ExportFormat::Syslog => ("text/plain; charset=utf-8", "mcpdef-audit.log"),
    };
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
        ],
        Body::from_stream(ReceiverStream::new(rx)),
    )
        .into_response())
}

#[derive(Deserialize)]
struct StreamQuery {
    after: Option<String>,
    #[serde(flatten)]
    wanted: Wanted,
}

/// `GET /api/v1/audit/stream`: Server-Sent Events, one per record a filter
/// wants as it is appended, its `id` the record's `seq`. It starts after
/// `Last-Event-ID`, else after `?after=`, else at the end of the ledger.
/// A record the filter passes over still moves the stream's `id` on, so a
/// browser that comes back resumes after it.
async fn stream(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    q: Result<Query<StreamQuery>, QueryRejection>,
) -> Result<Response, Refused> {
    let q = query(q)?;
    let resume = headers
        .get("last-event-id")
        .map(|v| v.to_str().unwrap_or_default().trim().to_string());
    let after = match number("Last-Event-ID", resume.as_deref())? {
        Some(seq) => Some(seq),
        None => number("after", q.after.as_deref())?,
    };
    let filter = q.wanted.filter()?;
    let Ok(permit) = Arc::clone(&s.reads.streams).try_acquire_owned() else {
        return Ok(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many streams",
            format!("this listener holds {STREAMS} audit streams open, the most it will"),
        ));
    };
    // Taken before the start is found, so that a record appended in between
    // still wakes the stream.
    let mut appends = s.gateway.audit_appends();
    let path = s.audit_path.clone();
    let follow = blocking(move || Follow::after(&path, after)).await?;
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(BATCH);
    tokio::spawn(async move {
        let _permit = permit;
        let ends = tokio::time::Instant::now() + STREAM_FOR;
        if tx
            .send(Ok(Event::default().retry(RECONNECT)))
            .await
            .is_err()
        {
            return;
        }
        let mut follow = Some(follow);
        loop {
            // What has been appended, a batch at a time.
            loop {
                let Some(mut reading) = follow.take() else {
                    return;
                };
                let Ok((reading, read)) = tokio::task::spawn_blocking(move || {
                    let read = reading.read(BATCH);
                    (reading, read)
                })
                .await
                else {
                    return;
                };
                follow = Some(reading);
                // A ledger cut short or replaced: the browser starts again
                // from the last record it had.
                let Ok(batch) = read else {
                    return;
                };
                let full = batch.len() == BATCH;
                let mut passed_over = None;
                for (record, line) in batch {
                    if !filter.matches(&record) {
                        passed_over = Some(record.seq);
                        continue;
                    }
                    passed_over = None;
                    let event = Event::default().id(record.seq.to_string()).data(line);
                    if tx.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
                if let Some(seq) = passed_over {
                    let moved_on = Event::default().id(seq.to_string());
                    if tx.send(Ok(moved_on)).await.is_err() {
                        return;
                    }
                }
                if !full {
                    break;
                }
            }
            tokio::select! {
                more = appends.wait() => if !more { return },
                () = tokio::time::sleep_until(ends) => return,
                () = tx.closed() => return,
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
        .into_response())
}
