// SPDX-License-Identifier: Apache-2.0
//! Resource URIs in normal form, so a pattern and an upstream agree on what a
//! URI names.
//!
//! An allowlist judges a URI by its text; an upstream serves it by what the
//! text means to it. If the two can read one URI differently, the allowlist
//! can pass what the upstream then serves from somewhere else:
//! `file:///srv/docs/%2e%2e/secret` names `/srv/secret`, yet starts with
//! `/srv/docs/`. [`normalize`] closes that gap:
//! - it rewrites the text into one canonical form, by RFC 3986 §6.2.2's
//!   syntax-based rules and the scheme-based ones §6.2.3 allows for the schemes
//!   that define them;
//! - it refuses whatever can still be read two ways: an encoded path
//!   separator, a backslash, a NUL, an empty segment inside the path, an escape
//!   of an escape.
//!
//! Whoever judges a URI by its [`Uri`] must also send the upstream that
//! [`Uri::as_str`], never the text it was given. Then the upstream receives
//! exactly what was judged, with no `..` left for it to resolve, lexically or
//! through a symlink.

use std::fmt;
use std::ops::Range;

/// Schemes whose host names no case, and which RFC 3986 §6.2.3 lets be
/// normalized by the scheme's own rules: a lowercased host, a dropped default
/// port, an empty path read as `/`. Every other scheme's authority is left as
/// written and compared as written, since a custom scheme's "host" is often a
/// name its server reads with case.
const HOST_CASE_INSENSITIVE: &[&str] = &["http", "https", "ws", "wss", "ftp", "file"];

/// A URI in normal form: what [`normalize`] returns, and the only form a
/// [`UriGlob`](crate::glob::UriGlob) matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Uri {
    text: String,
    /// Where the path starts: after `scheme:` or `scheme://authority`.
    path_start: usize,
    /// Where the path ends.
    path_end: usize,
    /// Each path segment, found once here so that matching the URI against
    /// many patterns never splits it again.
    segments: Vec<Range<usize>>,
    query: Option<Range<usize>>,
    fragment: Option<Range<usize>>,
}

impl Uri {
    /// The URI in normal form: what to match, and what to send upstream.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Everything before the path: `scheme:`, or `scheme://authority`.
    pub fn prefix(&self) -> &str {
        &self.text[..self.path_start]
    }

    /// The path, dot segments removed. It is empty only for a URI without an
    /// authority and without a path, such as `urn:` alone.
    pub fn path(&self) -> &str {
        &self.text[self.path_start..self.path_end]
    }

    /// The path's segments, split at each `/`: `/a/b` is `""`, `"a"`, `"b"`.
    pub fn segments(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.segments.iter().map(|r| &self.text[r.clone()])
    }

    /// The segment at `index`, counted as [`segments`](Self::segments) counts.
    pub(crate) fn segment(&self, index: usize) -> &str {
        &self.text[self.segments[index].clone()]
    }

    /// How many segments the path has: at least one, since an empty path is
    /// one empty segment.
    pub(crate) fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// The query, without its `?`, if the URI has one.
    pub fn query(&self) -> Option<&str> {
        self.query.clone().map(|r| &self.text[r])
    }

    /// The fragment, without its `#`, if the URI has one.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.clone().map(|r| &self.text[r])
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Why [`normalize`] refused a URI: each is something two readers could take
/// two ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refused {
    /// No `scheme:` to start it, so it is not an absolute URI.
    NoScheme,
    /// A `%` not followed by two hex digits.
    BadEscape,
    /// A backslash, which some readers take as a path separator.
    Backslash,
    /// A NUL, raw or as `%00`, where a C string would end.
    Nul,
    /// A control character.
    Control,
    /// `%2F` or `%5C` in the path: a separator to one reader, part of a name
    /// to another.
    EncodedSeparator,
    /// An empty segment inside the path (`a//b`), which a file system reads
    /// as `a/b` and a pattern would not.
    EmptySegment,
    /// `%25` before an escape of a dot, a separator, a NUL or another `%`, as
    /// in `%252e`: harmless decoded once, a traversal decoded twice. It is
    /// judged once the escapes of unreserved characters are decoded, so
    /// `%25%32%65` is `%252e` too.
    DoubleEncoded,
}

impl Refused {
    /// A short, stable name, for a deny rule or a log.
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::NoScheme => "no-scheme",
            Refused::BadEscape => "bad-escape",
            Refused::Backslash => "backslash",
            Refused::Nul => "nul",
            Refused::Control => "control-character",
            Refused::EncodedSeparator => "encoded-separator",
            Refused::EmptySegment => "empty-segment",
            Refused::DoubleEncoded => "double-encoded",
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refused::NoScheme => "has no scheme",
            Refused::BadEscape => "has a `%` that is not followed by two hex digits",
            Refused::Backslash => "holds a backslash",
            Refused::Nul => "holds a NUL",
            Refused::Control => "holds a control character",
            Refused::EncodedSeparator => "encodes a path separator (`%2F` or `%5C`)",
            Refused::EmptySegment => "has an empty segment inside its path (`//`)",
            Refused::DoubleEncoded => {
                "is percent-encoded twice (`%25` before an escaped dot, separator, NUL or `%`)"
            }
        })
    }
}

impl std::error::Error for Refused {}

/// Put `uri` in normal form, or refuse it.
///
/// The normal form, in order:
/// 1. The scheme is lowercased.
/// 2. In every part, an escape of an unreserved character (a letter, a digit,
///    `-`, `.`, `_`, `~`) is decoded, and every other escape's hex is
///    uppercased: `%7e` is `~`, `%3a` is `%3A`.
/// 3. The path's dot segments are removed (RFC 3986 §5.2.4), so `%2e%2e` counts
///    as `..` once decoded. A `..` above the root stops at the root.
/// 4. For the schemes in [`HOST_CASE_INSENSITIVE`]: the host is lowercased, a
///    default port (`:80`, `:443`, `:21`) is dropped, and an empty path with an
///    authority is `/`. For `file`, `file:/p` and `file://localhost/p` are
///    `file:///p` (RFC 8089).
///
/// Refused ([`Refused`]): a raw backslash, NUL or control character anywhere;
/// `%00` anywhere; `%2F`, `%5C` or `%25` before an escaped `.`, `/`, `\`, NUL
/// or `%` in the path, the last judged after step 2; an empty segment inside the path once dot segments are gone;
/// a malformed escape; and a URI with no scheme.
///
/// Normal form is a fixed point: normalizing a [`Uri::as_str`] gives it back.
pub fn normalize(uri: &str) -> Result<Uri, Refused> {
    for c in uri.chars() {
        match c {
            '\0' => return Err(Refused::Nul),
            '\\' => return Err(Refused::Backslash),
            c if c.is_control() => return Err(Refused::Control),
            _ => {}
        }
    }
    let (scheme, rest) = split_scheme(uri).ok_or(Refused::NoScheme)?;
    let scheme = scheme.to_ascii_lowercase();
    let by_scheme = HOST_CASE_INSENSITIVE.contains(&scheme.as_str());
    // The first `#` starts the fragment; the first `?` before it, the query.
    let (rest, fragment) = match rest.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (rest, None),
    };
    let (hier, query) = match rest.split_once('?') {
        Some((hier, query)) => (hier, Some(query)),
        None => (rest, None),
    };
    let (authority, path) = match hier.strip_prefix("//") {
        Some(after) => {
            let end = after.find('/').unwrap_or(after.len());
            (Some(&after[..end]), &after[end..])
        }
        None => (None, hier),
    };

    let mut authority = authority.map(|a| unescape(a, Part::Other)).transpose()?;
    let mut path = remove_dot_segments(&unescape(path, Part::Path)?);
    if by_scheme {
        if let Some(a) = authority.as_mut() {
            *a = normal_authority(a, &scheme);
            if path.is_empty() {
                path.push('/');
            }
        }
        if scheme == "file" {
            match authority.as_deref() {
                // `file:/p` is `file:///p`.
                None if path.starts_with('/') => authority = Some(String::new()),
                // `file://localhost/p` is `file:///p`.
                Some("localhost") => authority = Some(String::new()),
                _ => {}
            }
        }
    }
    // An empty segment inside the path, never the one before a leading `/` or
    // after a trailing one: `/` alone and a directory's trailing `/` are fine.
    let mut segments = segment_ranges(&path);
    if segments.len() > 2 && segments[1..segments.len() - 1].iter().any(|r| r.is_empty()) {
        return Err(Refused::EmptySegment);
    }

    let mut text = String::with_capacity(uri.len() + 2);
    text.push_str(&scheme);
    text.push(':');
    if let Some(authority) = &authority {
        text.push_str("//");
        text.push_str(authority);
    }
    let path_start = text.len();
    text.push_str(&path);
    let path_end = text.len();
    for range in &mut segments {
        *range = range.start + path_start..range.end + path_start;
    }
    let query = match query {
        Some(q) => {
            text.push('?');
            let start = text.len();
            text.push_str(&unescape(q, Part::Other)?);
            Some(start..text.len())
        }
        None => None,
    };
    let fragment = match fragment {
        Some(f) => {
            text.push('#');
            let start = text.len();
            text.push_str(&unescape(f, Part::Other)?);
            Some(start..text.len())
        }
        None => None,
    };
    Ok(Uri {
        text,
        path_start,
        path_end,
        segments,
        query,
        fragment,
    })
}

/// Where each of `path`'s `/`-separated segments lies in it.
fn segment_ranges(path: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::with_capacity(path.len() / 8 + 1);
    let mut start = 0;
    for (at, byte) in path.bytes().enumerate() {
        if byte == b'/' {
            ranges.push(start..at);
            start = at + 1;
        }
    }
    ranges.push(start..path.len());
    ranges
}

/// `scheme` and what follows its `:`, if `uri` starts with a scheme: a letter,
/// then letters, digits, `+`, `-` or `.` (RFC 3986 §3.1).
fn split_scheme(uri: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    (first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
    .then_some((scheme, rest))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Path,
    Other,
}

/// Decode each escape of an unreserved character and uppercase the rest, or
/// refuse the part. In the path, an escaped separator and an escaped escape
/// of a dot, separator or NUL are refused as well.
fn unescape(part: &str, which: Part) -> Result<String, Refused> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = part.as_bytes();
    let mut out = String::with_capacity(part.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            // Copy one whole character: `%` is ASCII, so every other byte run
            // between escapes starts on a character boundary.
            let c = part[i..].chars().next().expect("i is a char boundary");
            out.push(c);
            i += c.len_utf8();
            continue;
        }
        let byte = hex_pair(bytes.get(i + 1..i + 3)).ok_or(Refused::BadEscape)?;
        match byte {
            0 => return Err(Refused::Nul),
            b'/' | b'\\' if which == Part::Path => return Err(Refused::EncodedSeparator),
            b if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') => {
                out.push(char::from(b));
            }
            b => {
                out.push('%');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 0xF)]));
            }
        }
        i += 3;
    }
    // Judged on what this decode leaves, not on what it was given: the digits
    // after `%25` can be escapes themselves, and `%25%32%65` leaves `%252e`.
    if which == Part::Path && escaped_twice(&out) {
        return Err(Refused::DoubleEncoded);
    }
    Ok(out)
}

/// Whether `path` holds `%25` before an escape of a dot, a separator, a NUL or
/// another `%`: what a second decode, or a third, takes to one of them.
fn escaped_twice(path: &str) -> bool {
    path.as_bytes().windows(5).any(|w| {
        w[0] == b'%'
            && hex_pair(Some(&w[1..3])) == Some(b'%')
            && hex_pair(Some(&w[3..5])).is_some_and(|b| matches!(b, 0 | b'.' | b'/' | b'\\' | b'%'))
    })
}

/// The byte two hex digits spell, if `pair` is two hex digits.
fn hex_pair(pair: Option<&[u8]>) -> Option<u8> {
    let [hi, lo] = pair? else { return None };
    let digit = |d: u8| char::from(d).to_digit(16);
    Some((digit(*hi)? * 16 + digit(*lo)?) as u8)
}

/// RFC 3986 §5.2.4, "Remove Dot Segments", as written: `.` and `..` segments go,
/// each `..` with the segment before it, and nothing climbs above the root.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            // A.
            input = rest;
        } else if input.starts_with("/./") {
            // B.
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") || input == "/.." {
            // C: replace the prefix with "/", and drop the last output segment.
            input = if input == "/.." { "/" } else { &input[3..] };
            let cut = output.rfind('/').unwrap_or(0);
            output.truncate(cut);
        } else if input == "." || input == ".." {
            // D.
            input = "";
        } else {
            // E: move the first segment, with its leading "/", to the output.
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map_or(input.len(), |at| at + start);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

/// A `file`, `http`-like or `ftp` authority in normal form: the host lowercased
/// and a default port dropped. User info, which names someone, keeps its case.
fn normal_authority(authority: &str, scheme: &str) -> String {
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((user, hostport)) => (Some(user), hostport),
        None => (None, authority),
    };
    // The port follows the last `:` outside an IPv6 literal's brackets.
    let (host, port) = match hostport.rfind(':') {
        Some(at) if !hostport[at..].contains(']') => (&hostport[..at], Some(&hostport[at + 1..])),
        _ => (hostport, None),
    };
    let default_port = match scheme {
        "http" | "ws" => Some("80"),
        "https" | "wss" => Some("443"),
        "ftp" => Some("21"),
        _ => None,
    };
    let mut out = String::with_capacity(authority.len());
    if let Some(user) = userinfo {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(&host.to_ascii_lowercase());
    match port {
        Some(p) if Some(p) == default_port || p.is_empty() => {}
        Some(p) => {
            out.push(':');
            out.push_str(p);
        }
        None => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(uri: &str) -> String {
        match normalize(uri) {
            Ok(u) => u.as_str().to_string(),
            Err(e) => panic!("{uri:?} refused: {e}"),
        }
    }

    fn refused(uri: &str) -> Refused {
        match normalize(uri) {
            Ok(u) => panic!("{uri:?} accepted as {u}"),
            Err(e) => e,
        }
    }

    #[test]
    fn scheme_and_known_hosts_are_lowercased_and_custom_ones_kept() {
        assert_eq!(
            n("HTTPS://Api.Example.COM/V1/X"),
            "https://api.example.com/V1/X"
        );
        assert_eq!(n("File:///Srv/Docs/A.txt"), "file:///Srv/Docs/A.txt");
        // A custom scheme's authority is a name its server reads, with case.
        assert_eq!(n("Note://MyNotes/Today"), "note://MyNotes/Today");
        // User info keeps its case; only the host is lowercased.
        assert_eq!(n("https://Bob@Example.com/"), "https://Bob@example.com/");
    }

    #[test]
    fn unreserved_escapes_are_decoded_and_the_rest_uppercased() {
        assert_eq!(n("file:///srv/%7Ebob/%41%62c"), "file:///srv/~bob/Abc");
        assert_eq!(n("db://t/a%3ab%2cc"), "db://t/a%3Ab%2Cc");
        assert_eq!(n("db://t/a?x=%2f%3d"), "db://t/a?x=%2F%3D");
        // Non-ASCII passes through as written.
        assert_eq!(
            n("file:///srv/données/ツール"),
            "file:///srv/données/ツール"
        );
    }

    #[test]
    fn dot_segments_are_removed_as_rfc_3986_says() {
        // RFC 3986 §5.4's normal examples, as paths under one authority.
        assert_eq!(n("h://a/b/c/./../../g"), "h://a/g");
        assert_eq!(n("h://a/b/c/../d"), "h://a/b/d");
        assert_eq!(n("h://a/b/./c"), "h://a/b/c");
        assert_eq!(n("h://a/../../x"), "h://a/x");
        assert_eq!(n("h://a/b/.."), "h://a/");
        assert_eq!(n("h://a/b/."), "h://a/b/");
        // Escaped dots count once decoded.
        assert_eq!(n("file:///srv/docs/%2e%2E/x"), "file:///srv/x");
        assert_eq!(n("file:///srv/docs/.%2e/x"), "file:///srv/x");
        // Three dots are a name, not a dot segment.
        assert_eq!(n("file:///srv/.../x"), "file:///srv/.../x");
        // Without an authority, too. §5.2.4 leaves the `/` the `..` consumed.
        assert_eq!(n("note:a/../b"), "note:/b");
    }

    #[test]
    fn scheme_based_rules_apply_to_their_schemes_only() {
        assert_eq!(n("http://example.com:80"), "http://example.com/");
        assert_eq!(n("https://example.com:443/a"), "https://example.com/a");
        assert_eq!(
            n("https://example.com:8443/a"),
            "https://example.com:8443/a"
        );
        assert_eq!(n("https://example.com:/a"), "https://example.com/a");
        assert_eq!(n("https://[::1]:443/a"), "https://[::1]/a");
        assert_eq!(n("https://[::1]/a"), "https://[::1]/a");
        assert_eq!(n("file:/srv/a"), "file:///srv/a");
        assert_eq!(n("file://localhost/srv/a"), "file:///srv/a");
        assert_eq!(n("file://LOCALHOST/srv/a"), "file:///srv/a");
        assert_eq!(n("file://host/srv/a"), "file://host/srv/a");
        // Not for a custom scheme: its port and empty path are its own.
        assert_eq!(n("db://h:80"), "db://h:80");
    }

    #[test]
    fn query_and_fragment_are_kept_apart_from_the_path() {
        let u = normalize("https://h/a/b?x=1&y=%2e#Frag").unwrap();
        assert_eq!(u.prefix(), "https://h");
        assert_eq!(u.path(), "/a/b");
        assert_eq!(u.segments().collect::<Vec<_>>(), ["", "a", "b"]);
        assert_eq!(u.query(), Some("x=1&y=."));
        assert_eq!(u.fragment(), Some("Frag"));
        // A `?` after the `#` belongs to the fragment.
        let u = normalize("h://a/p#f?q").unwrap();
        assert_eq!((u.query(), u.fragment()), (None, Some("f?q")));
        // An escaped separator is fine outside the path.
        assert_eq!(
            n("h://a/p?next=%2Fetc%2Fpasswd"),
            "h://a/p?next=%2Fetc%2Fpasswd"
        );
        let opaque = normalize("urn:isbn:0451450523").unwrap();
        assert_eq!(
            (opaque.prefix(), opaque.path()),
            ("urn:", "isbn:0451450523")
        );
    }

    #[test]
    fn what_two_readers_could_read_two_ways_is_refused() {
        assert_eq!(refused("/srv/docs/a"), Refused::NoScheme);
        assert_eq!(refused("srv/docs"), Refused::NoScheme);
        assert_eq!(refused("1ab:/x"), Refused::NoScheme);
        assert_eq!(refused(""), Refused::NoScheme);
        assert_eq!(refused("file:///srv/a%2"), Refused::BadEscape);
        assert_eq!(refused("file:///srv/a%zz"), Refused::BadEscape);
        assert_eq!(refused("file:///srv/docs/..\\etc"), Refused::Backslash);
        assert_eq!(refused("file:///srv/a\0b"), Refused::Nul);
        assert_eq!(refused("file:///srv/a%00.txt"), Refused::Nul);
        assert_eq!(refused("h://a/p?x=%00"), Refused::Nul);
        assert_eq!(refused("file:///srv/a\nb"), Refused::Control);
        assert_eq!(
            refused("file:///srv/docs/..%2Fetc"),
            Refused::EncodedSeparator
        );
        assert_eq!(
            refused("file:///srv/docs/..%2fetc"),
            Refused::EncodedSeparator
        );
        assert_eq!(
            refused("file:///srv/docs/..%5Cetc"),
            Refused::EncodedSeparator
        );
        assert_eq!(refused("file:///srv//secret/x"), Refused::EmptySegment);
        assert_eq!(refused("h://a//x"), Refused::EmptySegment);
        assert_eq!(refused("file:////srv/x"), Refused::EmptySegment);
        assert_eq!(
            refused("file:///srv/docs/%252e%252e/x"),
            Refused::DoubleEncoded
        );
        assert_eq!(refused("file:///srv/docs/%252F"), Refused::DoubleEncoded);
        assert_eq!(refused("file:///srv/docs/%255c"), Refused::DoubleEncoded);
        assert_eq!(refused("file:///srv/docs/%2500"), Refused::DoubleEncoded);
        // The second escape's digits escaped, or some of them: decoded once
        // they spell `%252e`, which a second decode takes to `.`.
        assert_eq!(
            refused("file:///srv/docs/%25%32%65%25%32%65/%25%32%65%25%32%65/etc/passwd"),
            Refused::DoubleEncoded
        );
        assert_eq!(
            refused("file:///srv/docs/%25%32%66"),
            Refused::DoubleEncoded
        );
        assert_eq!(refused("file:///srv/docs/%252%65"), Refused::DoubleEncoded);
        assert_eq!(refused("file:///srv/docs/%25%35c"), Refused::DoubleEncoded);
        assert_eq!(
            refused("file:///srv/docs/%25%30%30"),
            Refused::DoubleEncoded
        );
        // Escaped three times: a third decode takes `%25252e` to `.`.
        assert_eq!(refused("file:///srv/docs/%25252e"), Refused::DoubleEncoded);
        assert_eq!(
            refused("file:///srv/docs/%25%32%35%32%65"),
            Refused::DoubleEncoded
        );
    }

    /// Every run of up to five pieces, each `%25` or a hex digit written raw
    /// or escaped: whatever of them is taken, decoding its path once, twice
    /// or three times more adds no separator, dot segment, backslash or NUL.
    #[test]
    fn no_escape_of_an_escape_is_left_to_decode_again() {
        const PIECES: [&str; 10] = ["%25", "2", "%32", "5", "%35", "e", "%65", "f", "%66", "a"];
        let mut runs = vec![String::new()];
        let mut taken = 0;
        for _ in 0..5 {
            runs = runs
                .iter()
                .flat_map(|run| PIECES.iter().map(move |piece| format!("{run}{piece}")))
                .collect();
            for run in &runs {
                let uri = format!("file:///srv/docs/{run}");
                let Ok(u) = normalize(&uri) else { continue };
                taken += 1;
                let mut path = u.path().to_string();
                for decodes in 1..=3 {
                    path = decode(&path);
                    let segments: Vec<&str> = path.split('/').collect();
                    assert!(
                        segments.len() == 4
                            && !path.contains(['\\', '\0'])
                            && !segments.iter().any(|s| *s == "." || *s == ".."),
                        "{uri} normalized to {u}, then decoded {decodes} more times to {path}"
                    );
                }
            }
        }
        assert!(taken > 50_000, "only {taken} runs were taken");
    }

    /// One percent-decode of `s`, as a reader downstream might do it.
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match hex_pair(bytes.get(i + 1..i + 3)).filter(|_| bytes[i] == b'%') {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn an_escaped_percent_before_anything_else_is_a_name() {
        assert_eq!(n("file:///srv/100%25/x"), "file:///srv/100%25/x");
        assert_eq!(n("file:///srv/a%2541"), "file:///srv/a%2541");
    }

    #[test]
    fn a_root_and_a_trailing_slash_are_not_empty_segments() {
        assert_eq!(n("https://h/"), "https://h/");
        assert_eq!(n("file:///srv/docs/"), "file:///srv/docs/");
        // A dot segment may leave one behind, and that is judged after.
        assert_eq!(n("file:///srv/docs/a/.."), "file:///srv/docs/");
    }

    #[test]
    fn normal_form_is_a_fixed_point() {
        for uri in [
            "HTTPS://Api.Example.COM:443",
            "file:/srv/%2e%2e/x",
            "note:a/../b?q=%3a#f",
            "urn:isbn:0451450523",
            "file://localhost/srv/%7Ebob",
            "db://t/a%3ab%2cc",
        ] {
            let once = normalize(uri).unwrap();
            let twice = normalize(once.as_str()).unwrap();
            assert_eq!(once, twice, "{uri}");
        }
    }
}
