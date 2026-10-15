// SPDX-License-Identifier: Apache-2.0
//! One glob engine, in two dialects.
//!
//! - **Names** ([`names`]): tools, servers, callers, role grants, argument
//!   values. `*` matches any run of characters.
//! - **URIs** ([`UriGlob`]): resources. `*` stays within one path segment, and
//!   a segment that is `**` alone crosses any number of them.
//!
//! Both match the same way. The wildcards split a pattern into fixed pieces:
//! the first is anchored at the start, the last at the end, and each one
//! between is taken at its leftmost match in what is left. Between pieces there
//! is only ever "any run", so the leftmost match is never wrong and nothing
//! backtracks. The URI dialect does this over segments, and matches each
//! segment by the names dialect, so a flaw in one is a flaw in both, and a fix
//! to one is a fix to both. Tools had such a flaw until 0.2.2: `*` was honoured
//! only at a pattern's ends.

use crate::uri::{self, Refused, Uri};
use std::fmt;

/// Whether `name` matches the glob `pattern`, as a whole.
///
/// `*` matches any run of characters, including none. It may appear anywhere in
/// the pattern, any number of times. It is the only wildcard: every other
/// character, `?` and `[` included, matches only itself, and matching is
/// case-sensitive. A pattern with no `*` is an exact match.
///
/// The stars split the pattern into literal pieces. The first piece must start
/// `name`, the last must end it, and the ones between must appear in order in
/// what is left, each taken at its leftmost match. With `*` as the only
/// wildcard, the leftmost match is never wrong, so nothing backtracks and the
/// cost stays linear in practice.
///
/// Matching compares whole UTF-8 pieces, so it is safe on any name: a piece only
/// ever matches at a character boundary, and every slice below is cut at one.
pub fn names(pattern: &str, name: &str) -> bool {
    let Some((first, after_first)) = pattern.split_once('*') else {
        return pattern == name;
    };
    let (middle, last) = after_first.rsplit_once('*').unwrap_or(("", after_first));
    // The first and last pieces are anchored, and must not overlap.
    let Some(rest) = name.strip_prefix(first) else {
        return false;
    };
    let Some(mut rest) = rest.strip_suffix(last) else {
        return false;
    };
    for piece in middle.split('*').filter(|p| !p.is_empty()) {
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    true
}

/// A resource-URI pattern, compiled once, from config.
///
/// A pattern is written as a URI whose `*`s are wildcards, and it is put in
/// normal form by the same [`uri::normalize`] as the URIs it judges, so
/// `FILE:///srv/docs/%7Ebob/*` and `file:///srv/docs/~bob/*` are one pattern.
/// - What comes before the path (`scheme:`, or `scheme://authority`) matches
///   by the names dialect: `https://*.example.com/**` takes any subdomain. It
///   can never reach into the path, since the authority ends at the first `/`.
/// - The path matches segment by segment. `*` within a segment matches within
///   that segment, and never matches an empty one, so `file:///srv/docs/*`
///   takes the files in `/srv/docs` and not `/srv/docs/` itself. A segment that
///   is `**` alone matches any run of whole segments, none included.
/// - A query or a fragment matches only a pattern that has one, by the names
///   dialect: `file:///srv/docs/*` never matches `file:///srv/docs/a?x=1`.
/// - `*` or `**` alone matches every URI.
#[derive(Debug, Clone)]
pub struct UriGlob {
    source: String,
    shape: Shape,
}

#[derive(Debug, Clone)]
enum Shape {
    Any,
    Uri {
        prefix: String,
        /// The path's segments, split into runs at each `**` segment: between
        /// two runs lies any run of segments.
        runs: Vec<Vec<String>>,
        query: Option<String>,
        fragment: Option<String>,
    },
}

impl UriGlob {
    /// Compile `pattern`, or say why it cannot be a URI.
    pub fn new(pattern: &str) -> Result<Self, Refused> {
        let shape = if pattern == "*" || pattern == "**" {
            Shape::Any
        } else {
            let normal = uri::normalize(pattern)?;
            Shape::Uri {
                prefix: normal.prefix().to_string(),
                runs: runs(normal.path().split('/')),
                query: normal.query().map(str::to_string),
                fragment: normal.fragment().map(str::to_string),
            }
        };
        Ok(UriGlob {
            source: pattern.to_string(),
            shape,
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether `uri`, already in normal form, matches.
    pub fn matches(&self, uri: &Uri) -> bool {
        match &self.shape {
            Shape::Any => true,
            Shape::Uri {
                prefix,
                runs,
                query,
                fragment,
            } => {
                names(prefix, uri.prefix())
                    && optional(query.as_deref(), uri.query())
                    && optional(fragment.as_deref(), uri.fragment())
                    && path_matches(runs, uri.segment_count(), |i| uri.segment(i))
            }
        }
    }

    /// Whether some URI matches both this pattern and `other`: whether two
    /// servers whose allowlists hold them could both serve one resource.
    ///
    /// Exact, not a guess: it searches pairs of positions in the two patterns
    /// for a string, or a path, both could take, by the same rules as
    /// [`matches`](Self::matches).
    pub fn overlaps(&self, other: &UriGlob) -> bool {
        match (&self.shape, &other.shape) {
            (Shape::Any, _) | (_, Shape::Any) => true,
            (
                Shape::Uri {
                    prefix: p1,
                    runs: r1,
                    query: q1,
                    fragment: f1,
                },
                Shape::Uri {
                    prefix: p2,
                    runs: r2,
                    query: q2,
                    fragment: f2,
                },
            ) => {
                patterns_overlap(p1, p2, false)
                    && optional_overlap(q1.as_deref(), q2.as_deref())
                    && optional_overlap(f1.as_deref(), f2.as_deref())
                    && paths_overlap(&flat(r1), &flat(r2))
            }
        }
    }
}

/// A path pattern's segments, with a whole-segment `**` as [`Seg::Any`].
#[derive(Clone, Copy)]
enum Seg<'a> {
    Any,
    One(&'a str),
}

/// `runs` back as one sequence, a `**` between each two.
fn flat(runs: &[Vec<String>]) -> Vec<Seg<'_>> {
    let mut segs = Vec::new();
    for (i, run) in runs.iter().enumerate() {
        if i > 0 {
            segs.push(Seg::Any);
        }
        segs.extend(run.iter().map(|s| Seg::One(s)));
    }
    segs
}

/// A query or fragment both patterns could take: both absent, or both present
/// and overlapping.
fn optional_overlap(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => patterns_overlap(a, b, false),
        _ => false,
    }
}

/// Whether some path matches both `p` and `q`. A search over pairs of
/// positions: a `**` may take no more segments, or take one the other
/// pattern takes (every segment pattern takes some segment); two segment
/// patterns may take one segment together if they overlap.
fn paths_overlap(p: &[Seg<'_>], q: &[Seg<'_>]) -> bool {
    let width = q.len() + 1;
    let mut seen = vec![false; (p.len() + 1) * width];
    let mut todo = vec![(0, 0)];
    while let Some((i, j)) = todo.pop() {
        if std::mem::replace(&mut seen[i * width + j], true) {
            continue;
        }
        if i == p.len() && j == q.len() {
            return true;
        }
        let (a, b) = (p.get(i).copied(), q.get(j).copied());
        if let Some(Seg::Any) = a {
            todo.push((i + 1, j));
        }
        if let Some(Seg::Any) = b {
            todo.push((i, j + 1));
        }
        match (a, b) {
            (Some(Seg::Any), Some(Seg::One(_))) => todo.push((i, j + 1)),
            (Some(Seg::One(_)), Some(Seg::Any)) => todo.push((i + 1, j)),
            (Some(Seg::One(a)), Some(Seg::One(b))) if segments_overlap(a, b) => {
                todo.push((i + 1, j + 1));
            }
            _ => {}
        }
    }
    false
}

/// Whether some segment matches both segment patterns: an empty one if both
/// are empty, since only an empty pattern takes it, and otherwise a
/// non-empty one both take by the names dialect.
fn segments_overlap(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        a.is_empty() && b.is_empty()
    } else {
        patterns_overlap(a, b, true)
    }
}

/// Whether some name matches both `p` and `q` in the names dialect: whether
/// two allowlists, one holding each, could both expose one tool or prompt.
/// Names are never empty, so neither is the name looked for.
pub fn names_overlap(p: &str, q: &str) -> bool {
    patterns_overlap(p, q, true)
}

/// Whether some name, non-empty if `nonempty`, matches both `p` and `q` in the
/// names dialect. A search over pairs of positions: a star may match nothing
/// more; a star takes the other's literal, or any character with the other's
/// star; equal literals are taken together.
fn patterns_overlap(p: &str, q: &str, nonempty: bool) -> bool {
    let p: Vec<char> = p.chars().collect();
    let q: Vec<char> = q.chars().collect();
    let width = q.len() + 1;
    // Each pair of positions, before and after a character has been taken.
    let mut seen = vec![[false; 2]; (p.len() + 1) * width];
    let mut todo = vec![(0, 0, false)];
    while let Some((i, j, taken)) = todo.pop() {
        if std::mem::replace(&mut seen[i * width + j][usize::from(taken)], true) {
            continue;
        }
        if i == p.len() && j == q.len() && (taken || !nonempty) {
            return true;
        }
        let (a, b) = (p.get(i).copied(), q.get(j).copied());
        if a == Some('*') {
            todo.push((i + 1, j, taken));
        }
        if b == Some('*') {
            todo.push((i, j + 1, taken));
        }
        match (a, b) {
            (Some('*'), Some('*')) => todo.push((i, j, true)),
            (Some('*'), Some(_)) => todo.push((i, j + 1, true)),
            (Some(_), Some('*')) => todo.push((i + 1, j, true)),
            (Some(a), Some(b)) if a == b => todo.push((i + 1, j + 1, true)),
            _ => {}
        }
    }
    false
}

impl fmt::Display for UriGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

/// Split pattern segments into runs at each segment that is `**` alone.
fn runs<'a>(segments: impl Iterator<Item = &'a str>) -> Vec<Vec<String>> {
    let mut runs = vec![Vec::new()];
    for segment in segments {
        if segment == "**" {
            runs.push(Vec::new());
        } else if let Some(run) = runs.last_mut() {
            run.push(segment.to_string());
        }
    }
    runs
}

/// A query or fragment: absent in both, or present in both and matching.
fn optional(pattern: Option<&str>, part: Option<&str>) -> bool {
    match (pattern, part) {
        (None, None) => true,
        (Some(pattern), Some(part)) => names(pattern, part),
        _ => false,
    }
}

/// Whether the `len` segments that `at` gives by index match `runs`: the
/// first run anchored at the start, the last at the end, and each between at
/// its leftmost place in what is left. The segments are read in place, never
/// collected.
fn path_matches<'a>(runs: &[Vec<String>], len: usize, at: impl Fn(usize) -> &'a str) -> bool {
    let Some((first, rest)) = runs.split_first() else {
        return len == 0;
    };
    let Some((last, middle)) = rest.split_last() else {
        // No `**`: one pattern segment for each segment.
        return first.len() == len && run_at(first, 0, &at);
    };
    if len < first.len() + last.len() || !run_at(first, 0, &at) {
        return false;
    }
    // The last run ends the path; the middle ones must fit between the two.
    let tail = len - last.len();
    if !run_at(last, tail, &at) {
        return false;
    }
    let mut from = first.len();
    for run in middle {
        match leftmost(run, from, tail, &at) {
            Some(start) => from = start + run.len(),
            None => return false,
        }
    }
    true
}

/// Whether `run` matches the segments starting at `start`, which the caller
/// has checked exist.
fn run_at<'a>(run: &[String], start: usize, at: &impl Fn(usize) -> &'a str) -> bool {
    run.iter()
        .enumerate()
        .all(|(i, pattern)| segment(pattern, at(start + i)))
}

/// Where `run` first matches wholly within segments `from..to`.
fn leftmost<'a>(
    run: &[String],
    from: usize,
    to: usize,
    at: &impl Fn(usize) -> &'a str,
) -> Option<usize> {
    let last_start = to.checked_sub(run.len())?;
    (from..=last_start).find(|&start| run_at(run, start, at))
}

/// One segment against one pattern segment: by the names dialect, except that
/// an empty segment is matched only by an empty pattern segment.
fn segment(pattern: &str, segment: &str) -> bool {
    if segment.is_empty() {
        pattern.is_empty()
    } else {
        names(pattern, segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::normalize;
    use proptest::prelude::*;

    fn glob(pattern: &str) -> UriGlob {
        UriGlob::new(pattern).unwrap_or_else(|e| panic!("{pattern:?}: {e}"))
    }

    fn matches(pattern: &str, uri: &str) -> bool {
        glob(pattern).matches(&normalize(uri).unwrap_or_else(|e| panic!("{uri:?}: {e}")))
    }

    #[test]
    fn a_star_stays_within_its_segment() {
        assert!(matches("file:///srv/docs/*", "file:///srv/docs/a.txt"));
        assert!(!matches("file:///srv/docs/*", "file:///srv/docs/sub/a.txt"));
        assert!(!matches("file:///srv/docs/*", "file:///srv/docs"));
        assert!(!matches("file:///srv/docs/*", "file:///srv/docs/"));
        assert!(matches("file:///srv/*/readme", "file:///srv/docs/readme"));
        assert!(matches("file:///srv/docs/*.md", "file:///srv/docs/a.md"));
        assert!(!matches(
            "file:///srv/docs/*.md",
            "file:///srv/docs/a.md.txt"
        ));
    }

    #[test]
    fn a_double_star_segment_crosses_any_number_of_segments() {
        let tree = "file:///srv/docs/**";
        assert!(matches(tree, "file:///srv/docs/a"));
        assert!(matches(tree, "file:///srv/docs/a/b/c"));
        // None included: the tree's root is in the tree.
        assert!(matches(tree, "file:///srv/docs"));
        assert!(!matches(tree, "file:///srv/other/a"));
        assert!(!matches(tree, "file:///srv/docsx/a"));
        let deep = "https://h/**/v1/*/items/**";
        assert!(matches(deep, "https://h/api/v1/users/items"));
        assert!(matches(deep, "https://h/v1/users/items/1/2"));
        assert!(!matches(deep, "https://h/v1/items"));
        // `**` inside a segment is a star within it.
        assert!(matches("note://n/a**b", "note://n/axyb"));
        assert!(!matches("note://n/a**b", "note://n/ax/yb"));
    }

    #[test]
    fn the_authority_matches_by_name_and_never_reaches_the_path() {
        assert!(matches(
            "https://*.example.com/**",
            "https://api.example.com/x"
        ));
        assert!(matches(
            "https://*.example.com/**",
            "HTTPS://API.Example.com/x"
        ));
        assert!(!matches(
            "https://*.example.com/**",
            "https://example.com.evil.net/x"
        ));
        assert!(!matches(
            "https://*.example.com/**",
            "https://evil.net/.example.com/x"
        ));
        // A default port is the same URI with or without it.
        assert!(matches("https://h/a", "https://h:443/a"));
        assert!(!matches("https://h/a", "https://h:8443/a"));
    }

    #[test]
    fn a_query_or_fragment_needs_a_pattern_that_has_one() {
        assert!(!matches("file:///srv/docs/*", "file:///srv/docs/a?x=1"));
        assert!(!matches("file:///srv/docs/*", "file:///srv/docs/a#top"));
        assert!(matches("db://t/rows?id=*", "db://t/rows?id=7"));
        assert!(!matches("db://t/rows?id=*", "db://t/rows"));
        assert!(!matches("db://t/rows?id=*", "db://t/rows?name=7"));
    }

    #[test]
    fn a_lone_star_or_double_star_matches_every_uri() {
        for pattern in ["*", "**"] {
            for uri in ["file:///etc/passwd", "urn:isbn:1", "https://h/a?b#c"] {
                assert!(matches(pattern, uri), "{pattern} {uri}");
            }
        }
    }

    #[test]
    fn patterns_are_normalized_like_uris_and_refused_like_them() {
        assert!(matches(
            "FILE:///srv/docs/%7Ebob/*",
            "file:///srv/docs/~bob/a"
        ));
        assert!(matches("file:/srv/docs/*", "file://localhost/srv/docs/a"));
        assert_eq!(UriGlob::new("/srv/docs/*").unwrap_err(), Refused::NoScheme);
        assert_eq!(
            UriGlob::new("file:///srv%2Fdocs/*").unwrap_err(),
            Refused::EncodedSeparator
        );
        assert_eq!(glob("file:///srv/docs/*").to_string(), "file:///srv/docs/*");
    }

    /// Paths under `/srv/docs/` that try to leave it. Each is refused, or
    /// normalizes to somewhere the pattern does not take.
    #[test]
    fn a_traversal_corpus_is_refused_or_unmatched() {
        let pattern = glob("file:///srv/docs/*");
        let corpus = [
            "file:///srv/docs/../secret",
            "file:///srv/docs/../../etc/passwd",
            "file:///srv/docs/%2e%2e/secret",
            "file:///srv/docs/%2E%2e/secret",
            "file:///srv/docs/.%2e/secret",
            "file:///srv/docs/%2e./secret",
            "file:///srv/docs/./../secret",
            "file:///srv/docs/a/../../secret",
            "file:///srv/docs/..",
            "file:///srv/docs/%2e%2e",
            "file:///srv/docs/%2e",
            "file:///srv/docs/a/..",
            "file:///srv/docs/.",
            "file:///srv/docs/..%2Fsecret",
            "file:///srv/docs/..%2fsecret",
            "file:///srv/docs/..%5Csecret",
            "file:///srv/docs/..\\secret",
            "file:///srv/docs/%252e%252e/secret",
            "file:///srv/docs/%252E%252E%252Fsecret",
            "file:///srv/docs/%25%32%65%25%32%65",
            "file:///srv/docs/%25%32%66secret",
            "file:///srv/docs/a%00.txt",
            "file:///srv/docs//etc/passwd",
            "file:///srv//docs/a",
            "file:///srv/docs/a?../../etc/passwd",
            "file://evil/srv/docs/a",
            "file:/srv/docs/../../etc/passwd",
        ];
        for uri in corpus {
            if let Ok(u) = normalize(uri) {
                assert!(!pattern.matches(&u), "{uri} normalized to {u} and matched");
            }
        }
    }

    /// Every pattern path of up to four segments against every path of up to
    /// four, over segments that exercise stars, double stars and empties,
    /// against a recursive reference.
    #[test]
    fn the_segment_dialect_agrees_with_a_reference_on_every_short_path() {
        fn reference(p: &[&str], s: &[&str]) -> bool {
            match p.split_first() {
                None => s.is_empty(),
                Some((&"**", rest)) => (0..=s.len()).any(|k| reference(rest, &s[k..])),
                Some((head, rest)) => {
                    !s.is_empty() && segment(head, s[0]) && reference(rest, &s[1..])
                }
            }
        }
        fn sequences<'a>(alphabet: &[&'a str], longest: usize) -> Vec<Vec<&'a str>> {
            let mut all = vec![Vec::new()];
            let mut last = vec![Vec::new()];
            for _ in 0..longest {
                last = last
                    .iter()
                    .flat_map(|s: &Vec<&'a str>| {
                        alphabet.iter().map(move |c| {
                            let mut t = s.clone();
                            t.push(*c);
                            t
                        })
                    })
                    .collect();
                all.extend(last.iter().cloned());
            }
            all
        }
        let patterns = sequences(&["", "a", "*", "**", "a*"], 4);
        let paths = sequences(&["", "a", "b", "ab"], 4);
        for p in &patterns {
            let compiled = runs(p.iter().copied());
            for s in &paths {
                assert_eq!(
                    path_matches(&compiled, s.len(), |i| s[i]),
                    reference(p, s),
                    "pattern {p:?} against {s:?}"
                );
            }
        }
    }

    #[test]
    fn long_inputs_match_in_bounded_time() {
        let started = std::time::Instant::now();
        // 10,000 segments, and a middle run that almost matches everywhere.
        let many = normalize(&format!("file:///{}", vec!["a"; 10_000].join("/"))).unwrap();
        let almost = glob(&format!("file:///**/{}/b/**", vec!["a"; 50].join("/")));
        assert!(!almost.matches(&many));
        assert!(glob("file:///**/a/**/a/**").matches(&many));
        // A thousand stars against a long name.
        let name = "a".repeat(100_000) + "b";
        assert!(names(&format!("*{}b", "a*".repeat(1_000)), &name));
        assert!(!names(&format!("*{}c", "a*".repeat(1_000)), &name));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn patterns_overlap_when_some_uri_matches_both() {
        let overlap = |a: &str, b: &str| {
            let (a, b) = (glob(a), glob(b));
            assert_eq!(a.overlaps(&b), b.overlaps(&a), "overlap is symmetric");
            a.overlaps(&b)
        };
        assert!(overlap("file:///shared/**", "file:///shared/docs/*"));
        assert!(overlap(
            "https://*.example.com/**",
            "https://api.example.com/v1/*"
        ));
        assert!(overlap("file:///a/*x", "file:///a/x*"));
        assert!(overlap("file:///a/**", "file:///a"));
        assert!(overlap("*", "urn:isbn:1"));
        assert!(overlap("db://t/rows?id=*", "db://t/rows?*=7"));
        assert!(!overlap("file:///a/*", "file:///b/*"));
        assert!(!overlap("file:///a/*.md", "file:///a/*.txt"));
        assert!(!overlap("file:///a/*", "file:///a/*/*"));
        assert!(!overlap("file:///a/*", "file:///a/"));
        assert!(!overlap("db://t/rows?id=*", "db://t/rows"));
        assert!(!overlap(
            "https://api.example.com/**",
            "http://api.example.com/**"
        ));
    }

    /// Every pair of name patterns of up to three characters over `a`, `b`
    /// and `*`, against a search for a name of up to five characters that
    /// both match.
    #[test]
    fn names_overlap_agrees_with_a_search_on_short_patterns() {
        fn all(alphabet: &[char], longest: usize) -> Vec<String> {
            let mut all = vec![String::new()];
            let mut last = vec![String::new()];
            for _ in 0..longest {
                last = last
                    .iter()
                    .flat_map(|s| {
                        alphabet.iter().map(move |c| {
                            let mut t = s.clone();
                            t.push(*c);
                            t
                        })
                    })
                    .collect();
                all.extend(last.iter().cloned());
            }
            all
        }
        let patterns = all(&['a', 'b', '*'], 3);
        let names_ = all(&['a', 'b'], 5);
        for p in &patterns {
            for q in &patterns {
                // What an allowlist asks: a name, never empty, both show.
                assert_eq!(names_overlap(p, q), patterns_overlap(p, q, true));
                for nonempty in [false, true] {
                    let found = names_
                        .iter()
                        .filter(|n| !nonempty || !n.is_empty())
                        .any(|n| names(p, n) && names(q, n));
                    assert_eq!(
                        patterns_overlap(p, q, nonempty),
                        found,
                        "{p:?} and {q:?}, nonempty {nonempty}"
                    );
                }
            }
        }
    }

    /// Every pair of path patterns of up to two segments against a search for
    /// a path of up to four segments that both match.
    #[test]
    fn paths_overlap_agrees_with_a_search_on_short_paths() {
        let alphabet = ["", "a", "b", "*", "a*", "**"];
        let mut patterns = vec![vec![]];
        for x in alphabet {
            patterns.push(vec![x]);
            for y in alphabet {
                patterns.push(vec![x, y]);
            }
        }
        let segments = ["", "a", "b", "ab", "ba"];
        let mut paths: Vec<Vec<&str>> = vec![vec![]];
        let mut last: Vec<Vec<&str>> = vec![vec![]];
        for _ in 0..4 {
            last = last
                .iter()
                .flat_map(|p| {
                    segments.iter().map(move |s| {
                        let mut t = p.clone();
                        t.push(*s);
                        t
                    })
                })
                .collect();
            paths.extend(last.iter().cloned());
        }
        let seg = |p: &[&'static str]| -> Vec<Seg<'static>> {
            p.iter()
                .map(|s| if *s == "**" { Seg::Any } else { Seg::One(s) })
                .collect()
        };
        for p in &patterns {
            let p_runs = runs(p.iter().copied());
            for q in &patterns {
                let q_runs = runs(q.iter().copied());
                let found = paths.iter().any(|path| {
                    path_matches(&p_runs, path.len(), |i| path[i])
                        && path_matches(&q_runs, path.len(), |i| path[i])
                });
                assert_eq!(paths_overlap(&seg(p), &seg(q)), found, "{p:?} and {q:?}");
            }
        }
    }

    proptest! {
        /// Whatever segments, dots and escapes a URI holds, a one-segment
        /// pattern takes it only if it resolves to one segment under the
        /// pattern's directory, and what would be sent upstream is that URI.
        #[test]
        fn a_one_segment_pattern_takes_only_what_resolves_to_one_segment_under_it(
            segments in prop::collection::vec(
                prop::sample::select(vec![
                    "srv", "docs", "a", ".", "..", "%2e", "%2E%2e", ".%2e", "%2e.", "",
                    "b%41", "%2F", "%5c", "%252e", "x y", "*", "~", "%7E",
                ]),
                0..8,
            ),
            leading in prop::sample::select(vec!["file:///", "file:/", "file://localhost/", "FILE:///"]),
        ) {
            let uri = format!("{leading}{}", segments.join("/"));
            let pattern = glob("file:///srv/docs/*");
            if let Ok(u) = normalize(&uri) {
                if pattern.matches(&u) {
                    let rest = u.path().strip_prefix("/srv/docs/");
                    prop_assert!(
                        rest.is_some_and(|r| !r.is_empty() && !r.contains('/')),
                        "{} normalized to {} and matched", uri, u
                    );
                    prop_assert_eq!(normalize(u.as_str()), Ok(u.clone()));
                }
            }
        }

        /// Normal form is a fixed point for anything shaped like a URI.
        #[test]
        fn normal_form_is_a_fixed_point_for_any_input(
            uri in "[a-zA-Z][a-zA-Z0-9+.-]{0,4}:(//[a-zA-Z0-9.@:%\\[\\]-]{0,10})?[a-zA-Z0-9./%?#~*-]{0,30}",
        ) {
            if let Ok(u) = normalize(&uri) {
                prop_assert_eq!(normalize(u.as_str()), Ok(u.clone()), "{}", uri);
            }
        }
    }
}
