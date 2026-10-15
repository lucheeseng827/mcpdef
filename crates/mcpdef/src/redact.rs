// SPDX-License-Identifier: Apache-2.0
//! Keeping the secrets a URL holds out of what MCPdef shows: its log, its
//! errors, the ledger, the admin API and the CLI.
//!
//! A URL can carry credentials of its own: a password, a key in its query, a
//! token in its path. `validate` warns about them, and strict mode refuses
//! them. Wherever a URL is shown, they are masked as `***`.

use std::borrow::Cow;

/// What a secret is shown as.
const MASK: &str = "***";

/// `url`, with each secret it holds shown as `***`:
///
/// - who it logs in as, and with what password;
/// - a path segment with a known credential's shape;
/// - the value of a query or fragment parameter that is a secret by its name
///   or its shape, as `validate` judges a `[server.env]` value: `api_key`,
///   `access_token`, a GitHub token.
///
/// A credential's shape anywhere else, and a URL that cannot be read but
/// might hold one, leave only its scheme shown. A URL that holds no secret
/// comes back as it is.
pub fn redact_url(url: &str) -> Cow<'_, str> {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return match url.contains(['@', '?', '#']) || shaped(url) {
            true => Cow::Owned(format!("{}{MASK}", scheme(url))),
            false => Cow::Borrowed(url),
        };
    };
    let masked = mask(&mut parsed);
    if !masked && !shaped(url) {
        return Cow::Borrowed(url);
    }
    let shown = parsed.to_string();
    match masked && !shaped(&shown) {
        true => Cow::Owned(shown),
        false => Cow::Owned(format!("{}://{MASK}", parsed.scheme())),
    }
}

/// `text` with each `http://` and `https://` URL in it redacted as
/// [`redact_url`] does: an error's, say, which names where a request went.
/// A URL runs to the first space, quote, angle bracket, backtick or `)`, less
/// any `.`, `,`, `;` or `:` it ends with.
pub fn redact_urls(text: &str) -> Cow<'_, str> {
    let mut out = String::new();
    // How much of `text` is in `out`, or was replaced there.
    let mut done = 0;
    let mut from = 0;
    while let Some(start) = find_url(text, from) {
        let rest = &text[start..];
        let len = rest
            .find(|c: char| c.is_whitespace() || "\"'<>`)".contains(c))
            .unwrap_or(rest.len());
        let url = rest[..len].trim_end_matches(['.', ',', ';', ':']);
        if let Cow::Owned(shown) = redact_url(url) {
            out.push_str(&text[done..start]);
            out.push_str(&shown);
            done = start + url.len();
        }
        from = start + url.len().max(1);
    }
    if done == 0 {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[done..]);
    Cow::Owned(out)
}

/// Mask what `url` holds that is secret. Whether it held any.
fn mask(url: &mut url::Url) -> bool {
    let mut masked = false;
    if !url.username().is_empty() {
        masked |= url.set_username(MASK).is_ok();
    }
    if url.password().is_some() {
        masked |= url.set_password(Some(MASK)).is_ok();
    }
    if url.path().split('/').any(shaped) {
        let path: Vec<&str> = url
            .path()
            .split('/')
            .map(|segment| if shaped(segment) { MASK } else { segment })
            .collect();
        url.set_path(&path.join("/"));
        masked = true;
    }
    if let Some(query) = url.query().and_then(mask_pairs) {
        url.set_query(Some(&query));
        masked = true;
    }
    if let Some(fragment) = url.fragment().and_then(mask_pairs) {
        url.set_fragment(Some(&fragment));
        masked = true;
    }
    masked
}

/// `pairs`, a query or a fragment, with the value of each parameter that holds
/// a secret shown as `***`. None if none does.
fn mask_pairs(pairs: &str) -> Option<String> {
    let mut masked = false;
    let shown: Vec<Cow<'_, str>> = pairs
        .split('&')
        .map(|pair| {
            let (name, value) = url::form_urlencoded::parse(pair.as_bytes())
                .next()
                .unwrap_or_default();
            if !crate::config::a_secret(&name, &value) {
                return Cow::Borrowed(pair);
            }
            masked = true;
            let name = pair.split('=').next().unwrap_or_default();
            Cow::Owned(format!("{name}={MASK}"))
        })
        .collect();
    masked.then(|| shown.join("&"))
}

/// Whether `text` holds a known credential's shape.
fn shaped(text: &str) -> bool {
    mcpdef_inspect::secret_pattern(text).is_some()
}

/// `url`'s scheme and what follows it, `https://`, or nothing if it has none.
fn scheme(url: &str) -> &str {
    match url.find("://") {
        Some(end) => &url[..end + 3],
        None => "",
    }
}

/// Where the next `http://` or `https://` in `text` starts, from `from` on,
/// in any case.
fn find_url(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    (from..bytes.len()).find(|&at| {
        let rest = &bytes[at..];
        ["http://", "https://"].iter().any(|scheme| {
            rest.len() >= scheme.len()
                && rest[..scheme.len()].eq_ignore_ascii_case(scheme.as_bytes())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GitHub token's shape, built here so no source file holds one.
    fn github_token() -> String {
        format!("ghp_{}", "a1B2c3D4e5".repeat(4))
    }

    #[test]
    fn a_url_without_a_secret_is_shown_as_it_is() {
        for url in [
            "https://api.example.com",
            "HTTPS://API.example.com/mcp?page=2&keyword=rust#top",
            "http://127.0.0.1:8080/mcp",
            "http://[::1]:9000/v1/tools?limit=10",
            "https://api.example.com/v1/key",
        ] {
            assert!(
                matches!(redact_url(url), Cow::Borrowed(u) if u == url),
                "{url}"
            );
        }
    }

    #[test]
    fn who_it_logs_in_as_and_its_password_are_masked() {
        assert_eq!(
            redact_url("https://mcpdef:hunter2@api.example.com/mcp"),
            "https://***:***@api.example.com/mcp"
        );
        assert_eq!(
            redact_url("https://only-a-name@api.example.com/mcp"),
            "https://***@api.example.com/mcp"
        );
        assert_eq!(
            redact_url("https://:hunter2@api.example.com/"),
            "https://:***@api.example.com/"
        );
    }

    #[test]
    fn a_query_parameter_that_is_a_secret_by_name_or_shape_is_masked() {
        let token = github_token();
        assert_eq!(
            redact_url("https://api.example.com/mcp?api_key=abc123&page=2"),
            "https://api.example.com/mcp?api_key=***&page=2"
        );
        assert_eq!(
            redact_url(&format!(
                "https://h/mcp?page=2&q={token}&access_token=x%20y"
            )),
            "https://h/mcp?page=2&q=***&access_token=***"
        );
        // An empty one holds none, and a name alone none either.
        assert_eq!(
            redact_url("https://h/mcp?token=&key"),
            "https://h/mcp?token=&key"
        );
        // A fragment is read the same way.
        assert_eq!(
            redact_url("https://h/cb#access_token=abc&state=1"),
            "https://h/cb#access_token=***&state=1"
        );
    }

    #[test]
    fn a_path_segment_with_a_credential_shape_is_masked() {
        let token = github_token();
        assert_eq!(
            redact_url(&format!("https://h/v1/{token}/mcp")),
            "https://h/v1/***/mcp"
        );
    }

    #[test]
    fn a_shape_anywhere_else_leaves_only_the_scheme() {
        let token = github_token();
        // In a parameter's name, where no value can be masked.
        assert_eq!(redact_url(&format!("https://h/mcp?{token}")), "https://***");
        // A URL that cannot be read, and might hold a secret.
        assert_eq!(redact_url("https://user:pass@"), "https://***");
        assert_eq!(redact_url("https://"), "https://");
    }

    #[test]
    fn each_url_in_a_text_is_redacted_and_the_rest_kept() {
        let text = "error sending request for url (https://u:p@h/mcp?api_key=k1): \
                    refused; see http://h/help. Then 'HTTPS://h/?token=t2', done.";
        assert_eq!(
            redact_urls(text),
            "error sending request for url (https://***:***@h/mcp?api_key=***): \
             refused; see http://h/help. Then 'https://h/?token=***', done."
        );
        let clean = "upstream 'x' is for an https:// upstream, and http://h/mcp answered 401";
        assert!(matches!(redact_urls(clean), Cow::Borrowed(t) if t == clean));
        assert_eq!(redact_urls("https://h/?key=v"), "https://h/?key=***");
        assert_eq!(
            redact_urls("at https://h/?token=t3."),
            "at https://h/?token=***."
        );
        assert_eq!(redact_urls(""), "");
    }
}
