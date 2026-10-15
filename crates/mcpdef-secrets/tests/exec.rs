// SPDX-License-Identifier: Apache-2.0
//! A secret a command writes: the command's words, reaching it with no shell;
//! its output, read as a file is; and the limits a command is held to.

use mcpdef_secrets::{
    ExecProblem, ExposeSecret, SecretError, SecretRef, EXEC_TIMEOUT, MAX_OUTPUT_BYTES,
};
use std::time::{Duration, Instant};

fn exec(program: &str, args: &[&str]) -> SecretRef {
    SecretRef::Exec {
        program: program.into(),
        args: args.iter().map(|a| a.to_string()).collect(),
    }
}

fn resolved(secret: &SecretRef) -> String {
    secret.resolve().unwrap().expose_secret().to_string()
}

fn refusal(secret: &SecretRef) -> (String, ExecProblem) {
    match secret.resolve() {
        Err(error @ SecretError::Exec { .. }) => {
            let text = error.to_string();
            let SecretError::Exec { problem, .. } = error else {
                unreachable!()
            };
            (text, problem)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_command_s_output_is_the_value() {
    assert_eq!(resolved(&exec("printf", &["s3cret\\n"])), "s3cret");
    assert_eq!(
        resolved(&exec("printf", &["two\\nlines\\r\\n"])),
        "two\nlines"
    );
    // Its words reach it as they are: no shell expands or splits them.
    assert_eq!(
        resolved(&exec("printf", &["%s", "$HOME; echo *"])),
        "$HOME; echo *"
    );
    // It runs in MCPdef's environment.
    let path = std::env::var("PATH").unwrap();
    assert_eq!(resolved(&exec("printenv", &["PATH"])), path);
}

/// Nothing is on a command's standard input, so one that reads it gets its
/// end at once. Its error output goes nowhere: not to MCPdef's own.
#[cfg(target_os = "linux")]
#[test]
fn a_command_gets_no_input_and_its_errors_go_nowhere() {
    assert_eq!(resolved(&exec("cat", &[])), "");
    assert_eq!(
        resolved(&exec("readlink", &["/proc/self/fd/0", "/proc/self/fd/2"])),
        "/dev/null\n/dev/null"
    );
}

/// A command reads nothing, whatever MCPdef's own input is. MCPdef's input in
/// a test run is often /dev/null already, so this runs the test below again,
/// in a process whose input is a pipe held open, as a terminal would be.
#[cfg(target_os = "linux")]
#[test]
fn a_command_reads_nothing_even_when_mcpdef_has_input() {
    let mut run = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "a_command_reads_nothing", "--ignored"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let held = run.stdin.take();
    let output = run.wait_with_output().unwrap();
    drop(held);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{report}");
    assert!(report.contains("1 passed"), "{report}");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run by a_command_reads_nothing_even_when_mcpdef_has_input"]
fn a_command_reads_nothing() {
    assert_eq!(
        resolved(&exec("readlink", &["/proc/self/fd/0"])),
        "/dev/null"
    );
}

#[test]
fn a_command_that_fails_is_named_by_its_program_alone() {
    // Neither its arguments nor what it wrote, to either output, are shown.
    let script = "echo s3cret-out; echo s3cret-err >&2; exit 3";
    let (text, problem) = refusal(&exec("sh", &["-c", script, "s3cret-arg"]));
    assert_eq!(text, "(exec sh): exited with status 3");
    assert!(matches!(problem, ExecProblem::Exited(_)));

    let (text, _) = refusal(&exec("sh", &["-c", "kill -9 $$"]));
    assert_eq!(text, "(exec sh): was killed by signal 9");

    let (text, problem) = refusal(&exec("/nonexistent/mcpdef-secret-tool", &["s3cret"]));
    assert!(
        text.starts_with("(exec /nonexistent/mcpdef-secret-tool): could not start: No such file"),
        "{text}"
    );
    assert!(matches!(problem, ExecProblem::Start(_)));

    let (text, problem) = refusal(&exec("printf", &["\\377s3cret"]));
    assert_eq!(text, "(exec printf): wrote something other than UTF-8 text");
    assert!(matches!(problem, ExecProblem::NotText));
}

#[test]
fn a_command_may_write_up_to_the_cap_and_no_more() {
    assert_eq!(MAX_OUTPUT_BYTES, 64 * 1024);
    let dir = tempfile::tempdir().unwrap();
    let full = dir.path().join("full");
    std::fs::write(&full, "x".repeat(MAX_OUTPUT_BYTES + 1)).unwrap();
    let full = full.to_str().unwrap();
    let at_cap = exec("head", &["-c", &MAX_OUTPUT_BYTES.to_string(), full]);
    assert_eq!(resolved(&at_cap).len(), MAX_OUTPUT_BYTES);
    let over = exec("head", &["-c", &(MAX_OUTPUT_BYTES + 1).to_string(), full]);
    let (text, problem) = refusal(&over);
    assert_eq!(
        text,
        "(exec head): wrote over 64 KiB, more than a secret holds, and was stopped"
    );
    assert!(matches!(problem, ExecProblem::TooLarge));
}

/// A command that does not end is stopped after five seconds: the one test
/// here that takes them.
#[test]
fn a_command_has_five_seconds() {
    assert_eq!(EXEC_TIMEOUT, Duration::from_secs(5));
    let started = Instant::now();
    let (text, problem) = refusal(&exec("sleep", &["30"]));
    let took = started.elapsed();
    assert_eq!(
        text,
        "(exec sleep): had not ended within 5s, and was stopped"
    );
    assert!(matches!(problem, ExecProblem::TimedOut(EXEC_TIMEOUT)));
    assert!(
        took >= EXEC_TIMEOUT && took < EXEC_TIMEOUT + Duration::from_secs(2),
        "{took:?}"
    );
}

/// Each resolve runs the command again, so what it writes now is the value.
#[test]
fn a_command_is_run_afresh_each_time() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, "first\n").unwrap();
    let secret = exec("cat", &[file.to_str().unwrap()]);
    assert_eq!(resolved(&secret), "first");
    std::fs::write(&file, "rotated\n").unwrap();
    assert_eq!(resolved(&secret), "rotated");
}
