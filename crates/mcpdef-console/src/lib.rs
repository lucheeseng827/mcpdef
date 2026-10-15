// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-console` — the console's built files, embedded.
//!
//! `npm run build` in `console/` writes them to `assets/`, each text file with
//! its brotli and gzip forms beside it, and the table in `assets.rs` that names
//! them. This crate holds the result, so `cargo build` needs no Node, and the
//! gateway's admin listener serves from it: [`get`] finds a file by its path.

/// One file of the built console.
#[derive(Debug)]
pub struct Asset {
    /// Its path as a request names it: `/index.html`, `/assets/index-….js`.
    pub path: &'static str,
    /// Its media type, as `Content-Type` says it.
    pub content_type: &'static str,
    /// A strong entity tag for it: the first half of its SHA-256, quoted.
    pub etag: &'static str,
    /// Whether its name changes when its content does, as Vite names what it
    /// emits under `/assets/`: a client may keep it for good.
    pub immutable: bool,
    /// The file as built.
    pub identity: &'static [u8],
    /// Its brotli form, when that is smaller.
    pub br: Option<&'static [u8]>,
    /// Its gzip form, when that is smaller.
    pub gzip: Option<&'static [u8]>,
}

include!("assets.rs");

/// The file at `path`, as a request names it, if the console has one.
pub fn get(path: &str) -> Option<&'static Asset> {
    ASSETS
        .binary_search_by(|asset| asset.path.cmp(path))
        .ok()
        .map(|i| &ASSETS[i])
}

/// The console's page, which the admin listener serves for `/` and for any
/// other path the console's router knows.
pub fn index() -> &'static Asset {
    get("/index.html").expect("the console's build has an index.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_names_files_that_are_there() {
        assert!(ASSETS.windows(2).all(|w| w[0].path < w[1].path));
        assert!(ASSETS.iter().all(|a| a.path.starts_with('/')));
        assert_eq!(index().content_type, "text/html; charset=utf-8");
        assert!(!index().immutable);
        assert!(get("/nothing").is_none());
    }

    #[test]
    fn each_compressed_form_is_smaller_than_the_file() {
        for asset in ASSETS {
            for form in [asset.br, asset.gzip].into_iter().flatten() {
                assert!(form.len() < asset.identity.len(), "{}", asset.path);
            }
        }
    }

    #[test]
    fn the_page_loads_nothing_inline() {
        let page = std::str::from_utf8(index().identity).unwrap();
        // Every script and stylesheet is a file of its own, as the admin
        // listener's content security policy wants.
        assert!(!page.contains("<style"), "{page}");
        for script in page.split("<script").skip(1) {
            let tag = &script[..script.find('>').unwrap()];
            assert!(tag.contains(" src=\""), "an inline script: {tag}");
        }
    }
}
