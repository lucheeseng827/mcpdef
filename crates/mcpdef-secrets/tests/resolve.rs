// SPDX-License-Identifier: Apache-2.0
//! Reading a secret from each place a `SecretRef` names, and never showing
//! what one holds.

use mcpdef_secrets::{ExposeSecret, SecretError, SecretRef, SecretString, MAX_FILE_BYTES};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

const VALUE: &str = "s3cret-Value_9f2";

fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn resolved(secret: &SecretRef) -> String {
    secret.resolve().unwrap().expose_secret().to_string()
}

#[test]
fn a_literal_is_its_own_value() {
    let literal = SecretRef::Literal(SecretString::from(VALUE));
    assert_eq!(resolved(&literal), VALUE);
}

/// The only test here that changes the environment, which every other test
/// in this binary only reads.
#[test]
fn a_variable_is_read_from_the_environment_each_time() {
    let name = "MCPDEF_SECRETS_TEST_TOKEN";
    let env = SecretRef::Env(name.into());
    std::env::set_var(name, VALUE);
    assert_eq!(resolved(&env), VALUE);
    std::env::set_var(name, "rotated");
    assert_eq!(resolved(&env), "rotated");

    std::env::remove_var(name);
    let unset = env.resolve().unwrap_err();
    assert!(matches!(unset, SecretError::Unset(_)));
    assert_eq!(
        unset.to_string(),
        "$MCPDEF_SECRETS_TEST_TOKEN: not set in MCPdef's environment"
    );

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::env::set_var(name, std::ffi::OsString::from_vec(vec![0xff, 0xfe]));
        let error = env.resolve().unwrap_err();
        std::env::remove_var(name);
        assert_eq!(
            error.to_string(),
            "$MCPDEF_SECRETS_TEST_TOKEN: not UTF-8 text"
        );
    }
}

#[test]
fn a_file_loses_one_line_ending_and_no_more() {
    let dir = tempfile::tempdir().unwrap();
    for (content, value) in [
        ("token", "token"),
        ("token\n", "token"),
        ("token\r\n", "token"),
        ("token\n\n", "token\n"),
        ("two\nlines\n", "two\nlines"),
        ("\n", ""),
        ("", ""),
    ] {
        let file = SecretRef::File(write(dir.path(), "secret", content));
        assert_eq!(resolved(&file), value, "{content:?}");
    }
}

#[test]
fn a_file_is_read_afresh_each_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "token", "first\n");
    let file = SecretRef::File(path.clone());
    assert_eq!(resolved(&file), "first");
    std::fs::write(&path, "rotated\n").unwrap();
    assert_eq!(resolved(&file), "rotated");
}

/// A file in /proc says it is empty, and holds more: all of it is read.
#[cfg(target_os = "linux")]
#[test]
fn a_file_that_holds_more_than_it_says_is_read_whole() {
    let status = std::path::Path::new("/proc/self/status");
    assert_eq!(std::fs::metadata(status).unwrap().len(), 0);
    let value = resolved(&SecretRef::File(status.into()));
    assert!(value.starts_with("Name:"), "{value}");
    assert!(value.contains("\nPid:"), "{value}");
}

#[test]
fn a_file_over_the_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let full = write(dir.path(), "full", "x".repeat(MAX_FILE_BYTES));
    assert_eq!(resolved(&SecretRef::File(full)).len(), MAX_FILE_BYTES);
    let over = write(dir.path(), "over", "x".repeat(MAX_FILE_BYTES + 1));
    let error = SecretRef::File(over.clone()).resolve().unwrap_err();
    assert!(matches!(error, SecretError::TooLarge(_)));
    assert_eq!(
        error.to_string(),
        format!("{}: over 64 KiB, more than a secret holds", over.display())
    );
    // The cap is on what the file holds, not on the value: a line ending
    // counts.
    let with_newline = write(
        dir.path(),
        "newline",
        format!("{}\n", "x".repeat(MAX_FILE_BYTES)),
    );
    assert!(matches!(
        SecretRef::File(with_newline).resolve(),
        Err(SecretError::TooLarge(_))
    ));
}

#[test]
fn a_file_that_is_not_text_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let binary = write(dir.path(), "key.der", [0x30, 0x82, 0xff, 0xfe]);
    let error = SecretRef::File(binary.clone()).resolve().unwrap_err();
    assert!(matches!(error, SecretError::NotText(_)));
    assert_eq!(
        error.to_string(),
        format!("{}: not UTF-8 text", binary.display())
    );
}

#[test]
fn a_missing_file_is_named() {
    let error = SecretRef::File("/nonexistent/mcpdef/secret".into())
        .resolve()
        .unwrap_err();
    assert!(matches!(error, SecretError::Read { .. }));
    assert!(
        error
            .to_string()
            .starts_with("/nonexistent/mcpdef/secret: No such file"),
        "{error}"
    );
}

#[test]
fn a_directory_is_not_a_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let error = SecretRef::File(dir.path().into()).resolve().unwrap_err();
    assert!(matches!(error, SecretError::NotAFile(_)), "{error}");
}

/// Opening a FIFO for reading waits until something opens it for writing:
/// a secret path that names one must be refused, not wait forever.
#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_waiting_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo, from coreutils");
    assert!(made.success());
    let (tx, rx) = mpsc::channel();
    let secret = SecretRef::File(fifo);
    std::thread::spawn(move || tx.send(secret.resolve().map(drop)));
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("resolve returned, rather than waiting on the FIFO");
    assert!(
        matches!(result, Err(SecretError::NotAFile(_))),
        "{result:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_file_others_can_read_is_warned_about() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "token", VALUE);
    let file = SecretRef::File(path.clone());
    for (mode, who) in [
        (0o600, None),
        (0o400, None),
        (0o640, Some("its group")),
        (0o604, Some("every user")),
        (0o644, Some("its group and every user")),
        (0o444, Some("its group and every user")),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let warning = file.warning();
        match who {
            None => assert_eq!(warning, None, "{mode:o}"),
            Some(who) => {
                let warning = warning.unwrap_or_default();
                assert!(
                    warning.starts_with(&format!(
                        "{} can be read by {who} (mode {mode:03o})",
                        path.display()
                    )),
                    "{mode:o}: {warning}"
                );
                assert!(warning.contains("chmod 600"), "{warning}");
            }
        }
        // A warning never stops the file being read.
        assert_eq!(resolved(&file), VALUE);
    }
    // Nothing to say of a file that cannot be looked at, nor of other kinds.
    assert_eq!(SecretRef::File("/nonexistent/x".into()).warning(), None);
    assert_eq!(SecretRef::Env("HOME".into()).warning(), None);
    assert_eq!(
        SecretRef::Literal(SecretString::from(VALUE)).warning(),
        None
    );
}

/// A struct that holds a secret the way a config does.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct Config {
    name: String,
    token: SecretRef,
}

#[test]
fn no_value_is_ever_printed() {
    let config: Config = toml::from_str(&format!("name = \"x\"\ntoken = \"{VALUE}\"")).unwrap();
    let resolved = config.token.resolve().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = SecretRef::File(write(dir.path(), "token", VALUE));
    let printed = [
        format!("{config:?}"),
        format!("{config:#?}"),
        format!("{:?}", config.token),
        format!("{}", config.token),
        format!("{resolved:?}"),
        format!("{:?}", file.resolve().unwrap()),
        format!("{file:?} {file}"),
    ];
    for text in printed {
        assert!(!text.contains(VALUE), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
    }
    // Nor does an error print what it could not use.
    let dir = tempfile::tempdir().unwrap();
    let binary = write(dir.path(), "bad", [VALUE.as_bytes(), &[0xff]].concat());
    let too_large = write(
        dir.path(),
        "large",
        VALUE.repeat(MAX_FILE_BYTES / VALUE.len() + 1),
    );
    for secret in [SecretRef::File(binary), SecretRef::File(too_large)] {
        let error = secret.resolve().unwrap_err();
        assert!(!format!("{error} {error:?}").contains("s3cret"), "{error}");
    }
}
