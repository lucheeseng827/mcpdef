// SPDX-License-Identifier: Apache-2.0
//! The console's files, from the `mcpdef-console` crate: each served in the
//! encoding the client prefers of those it has, with its entity tag, and kept
//! by the client for good when its name changes with its content.

use axum::{
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use mcpdef_console::Asset;

/// `/`: the console's page.
pub(super) async fn index(request: Request) -> Response {
    serve(mcpdef_console::index(), request.headers())
}

/// A file under `/assets/`, or `404`.
pub(super) async fn asset(request: Request) -> Response {
    match mcpdef_console::get(request.uri().path()) {
        Some(asset) => serve(asset, request.headers()),
        None => super::problem(StatusCode::NOT_FOUND, "Not found", "no such file"),
    }
}

/// `asset`, as `headers` ask for it: `304` when the client holds it already,
/// else in the encoding it prefers.
fn serve(asset: &'static Asset, headers: &HeaderMap) -> Response {
    let mut response = if holds(headers, asset.etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let (body, encoding) = negotiate(asset, headers);
        let mut response = body.into_response();
        let set = response.headers_mut();
        set.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        );
        if let Some(encoding) = encoding {
            set.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
        }
        response
    };
    let set = response.headers_mut();
    set.insert(header::ETAG, HeaderValue::from_static(asset.etag));
    if asset.br.is_some() || asset.gzip.is_some() {
        set.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    set.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(match asset.immutable {
            true => "public, max-age=31536000, immutable",
            false => "no-cache",
        }),
    );
    response
}

/// Whether `If-None-Match` names `etag`, or any (`*`): weakly, as RFC 9110
/// compares for it.
fn holds(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|tag| tag.trim().trim_start_matches("W/"))
        .any(|tag| tag == "*" || tag == etag)
}

/// The body to send, and its `Content-Encoding`: brotli, then gzip, as the
/// client accepts and the asset has them; else the file as built.
fn negotiate(asset: &'static Asset, headers: &HeaderMap) -> (&'static [u8], Option<&'static str>) {
    let accepts = |coding: &str| {
        headers
            .get_all(header::ACCEPT_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|item| {
                let mut parts = item.split(';');
                let name = parts.next().unwrap_or_default().trim();
                let refused = parts.any(|param| {
                    let param = param.trim();
                    param
                        .strip_prefix("q=")
                        .and_then(|q| q.trim().parse::<f32>().ok())
                        .is_some_and(|q| q <= 0.0)
                });
                name.eq_ignore_ascii_case(coding) && !refused
            })
    };
    match (asset.br, asset.gzip) {
        (Some(br), _) if accepts("br") => (br, Some("br")),
        (_, Some(gzip)) if accepts("gzip") => (gzip, Some("gzip")),
        _ => (asset.identity, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ASSET: Asset = Asset {
        path: "/assets/app-abc.js",
        content_type: "text/javascript; charset=utf-8",
        etag: "\"e1\"",
        immutable: true,
        identity: b"identity",
        br: Some(b"br"),
        gzip: Some(b"gz"),
    };

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn brotli_then_gzip_then_the_file() {
        let pick =
            |accept: &'static str| negotiate(&ASSET, &headers(&[("accept-encoding", accept)])).1;
        assert_eq!(pick("gzip, deflate, br, zstd"), Some("br"));
        assert_eq!(pick("gzip, deflate"), Some("gzip"));
        assert_eq!(pick("br;q=0, gzip;q=0.5"), Some("gzip"));
        assert_eq!(pick("BR"), Some("br"));
        assert_eq!(pick("identity"), None);
        assert_eq!(pick("br;q=0, gzip;q=0"), None);
        assert_eq!(negotiate(&ASSET, &HeaderMap::new()).1, None);
    }

    #[test]
    fn a_held_tag_is_not_sent_again() {
        assert!(holds(&headers(&[("if-none-match", "\"e1\"")]), "\"e1\""));
        assert!(holds(
            &headers(&[("if-none-match", "\"x\", W/\"e1\"")]),
            "\"e1\""
        ));
        assert!(holds(&headers(&[("if-none-match", "*")]), "\"e1\""));
        assert!(!holds(&headers(&[("if-none-match", "\"e2\"")]), "\"e1\""));
        assert!(!holds(&HeaderMap::new(), "\"e1\""));
    }
}
