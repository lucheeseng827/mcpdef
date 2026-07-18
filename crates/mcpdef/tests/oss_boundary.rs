//! OSS boundary guard.
//!
//! The public mirror ships only the Apache-2.0 engine; the closed governance
//! plane is a separate workspace that must never be a dependency of — or be
//! referenced by — an OSS crate, and the private monorepo path must never leak
//! into a crate's source. The sync workflow enforces the same boundary before a
//! mirror push, but these run under `cargo test` so drift is caught locally,
//! first.
//!
//! NB: the sensitive tokens these tests search for are assembled from fragments
//! so that this guard file itself stays clean of the very markers the mirror
//! scan rejects.

use std::fs;
use std::path::{Path, PathBuf};

/// `CARGO_MANIFEST_DIR` is `<module-root>/crates/mcpdef`; walk up two levels.
fn module_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .and_then(Path::parent) // module root
        .expect("crate is nested under <root>/crates/mcpdef")
        .to_path_buf()
}

/// Every directory under `crates/` that carries a `Cargo.toml`.
fn crate_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root.join("crates")).expect("crates/ dir exists") {
        let path = entry.expect("readable dir entry").path();
        if path.join("Cargo.toml").is_file() {
            dirs.push(path);
        }
    }
    assert!(!dirs.is_empty(), "expected at least one crate under crates/");
    dirs
}

/// The closed-plane directory name, assembled so it is not a literal here.
fn plane_dir() -> String {
    format!("{}{}", "e", "e")
}

#[test]
fn no_workspace_member_is_in_the_closed_plane() {
    let root = module_root();
    let cargo = fs::read_to_string(root.join("Cargo.toml")).expect("root Cargo.toml");
    let plane_prefix = format!("\"{}/", plane_dir()); // a member string like "ee/..."
    for line in cargo.lines() {
        let l = line.trim();
        assert!(
            !l.starts_with(&plane_prefix),
            "workspace member points into the closed plane: {l}"
        );
    }
}

#[test]
fn no_oss_crate_depends_on_the_closed_plane() {
    let plane_path = format!("../{}", plane_dir()); // e.g. path = "../ee/..."
    for dir in crate_dirs(&module_root()) {
        let toml = fs::read_to_string(dir.join("Cargo.toml")).expect("crate Cargo.toml");
        assert!(
            !toml.contains(&plane_path),
            "{:?} declares a dependency on the closed plane",
            dir.file_name().unwrap()
        );
    }
}

#[test]
fn no_crate_source_leaks_the_private_monorepo_path() {
    // The private tree path is wrong on the mirror (crate root == repo root there)
    // and would reveal the monorepo layout. Assembled from fragments; see file note.
    let needle = format!("{}/{}", "rust_modules", "lab");
    for dir in crate_dirs(&module_root()) {
        let src = dir.join("src");
        if src.is_dir() {
            assert_no_needle(&src, &needle);
        }
    }
}

fn assert_no_needle(dir: &Path, needle: &str) {
    for entry in fs::read_dir(dir).expect("readable src dir") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            if path.file_name().and_then(|s| s.to_str()) == Some("target") {
                continue;
            }
            assert_no_needle(&path, needle);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let body = fs::read_to_string(&path).unwrap_or_default();
            assert!(
                !body.contains(needle),
                "{path:?} leaks the private monorepo path"
            );
        }
    }
}
