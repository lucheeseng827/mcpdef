// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-secrets` — where a secret comes from, and reading it when it is
//! needed.
//!
//! A config names a secret with a [`SecretRef`]: the value itself, written in
//! the config (a literal), an environment variable of MCPdef's own, a file, or
//! a command's output. In TOML the last three are inline tables, which say where
//! a value is without holding it:
//!
//! ```toml
//! client_key = { file = "/run/secrets/client.key" }  # a Kubernetes or Compose mount
//! client_key = { env = "MCPDEF_CLIENT_KEY" }         # MCPdef's own environment
//! client_key = { exec = ["op", "read", "op://infra/mcpdef/key"] }  # what a command writes
//! ```
//!
//! [`SecretRef::resolve`] reads the value as a [`SecretString`]: the memory
//! that holds it is wiped when it is dropped, and its `Debug` prints no value.
//! Nor does a `SecretRef`'s: its `Debug` and `Display` say where a value comes
//! from, never what it is, and so do the errors from reading one.

use serde::de::{self, Deserialize, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub use secrecy::{ExposeSecret, SecretString};

/// The most a secret file may hold: 64 KiB. A key or a token takes a few
/// kilobytes at most, so a larger file is not the one meant.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// The most a command may write for a secret: 64 KiB, as much as a file may
/// hold.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// How long a command has to write its secret and end: 5 s.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a secret's value comes from.
///
/// It parses from a plain string, the value itself, or from a table that
/// names where the value is: `{ env = "NAME" }`, `{ file = "/path" }` or
/// `{ exec = ["command", "argument", …] }`.
#[derive(Clone)]
#[non_exhaustive]
pub enum SecretRef {
    /// The value, written in the config itself.
    Literal(SecretString),
    /// An environment variable of MCPdef's own, read when the value is
    /// needed.
    Env(String),
    /// A file, read whole when the value is needed: a Kubernetes or Compose
    /// secret mount, say, or a file a secret manager's agent writes.
    File(PathBuf),
    /// A command, run when the value is needed, whose output is the value:
    /// a secret manager's CLI, say. Its arguments reach it as they are: no
    /// shell reads them.
    Exec { program: String, args: Vec<String> },
}

impl SecretRef {
    /// Read the value from where this names.
    ///
    /// A literal is the value itself. A variable, a file or a command is read
    /// now, and again at each call, so a file rotated in place is picked up.
    /// A file has to be a regular file, of at most [`MAX_FILE_BYTES`] of UTF-8
    /// text. One line ending at its end, `\n` or `\r\n`, is not part of the
    /// value: `echo` and most editors add one.
    ///
    /// A command is run with no shell, in MCPdef's environment, with nothing
    /// on its standard input and its error output thrown away, since that can
    /// hold what no log should. Its output is read as a file is, of at most
    /// [`MAX_OUTPUT_BYTES`]. It has [`EXEC_TIMEOUT`] to write it and end with
    /// status 0, and is stopped if it runs over, either way. This call waits for
    /// it: an async caller runs it where blocking is allowed.
    pub fn resolve(&self) -> Result<SecretString, SecretError> {
        match self {
            SecretRef::Literal(value) => Ok(value.clone()),
            SecretRef::Env(name) => match std::env::var(name) {
                Ok(mut value) => {
                    let secret = SecretString::from(value.as_str());
                    value.zeroize();
                    Ok(secret)
                }
                Err(std::env::VarError::NotPresent) => Err(SecretError::Unset(name.clone())),
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err(SecretError::EnvNotText(name.clone()))
                }
            },
            SecretRef::File(path) => read_file(path),
            SecretRef::Exec { program, args } => run(program, args, EXEC_TIMEOUT),
        }
    }

    /// Which kind of place it is: `literal`, `env`, `file` or `exec`. What a
    /// listing can show in place of a value.
    pub fn scheme(&self) -> &'static str {
        match self {
            SecretRef::Literal(_) => "literal",
            SecretRef::Env(_) => "env",
            SecretRef::File(_) => "file",
            SecretRef::Exec { .. } => "exec",
        }
    }

    /// The file, when the value is read from one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            SecretRef::File(path) => Some(path),
            _ => None,
        }
    }

    /// The variable, when the value is read from MCPdef's environment.
    pub fn var(&self) -> Option<&str> {
        match self {
            SecretRef::Env(name) => Some(name),
            _ => None,
        }
    }

    /// What an operator should hear about this secret, though it can be
    /// read: a file that users other than its owner can read too. `None` when
    /// there is nothing to say, and when the file cannot be looked at, which
    /// [`resolve`](Self::resolve) reports. A strict config refuses what this
    /// reports.
    pub fn warning(&self) -> Option<String> {
        match self {
            SecretRef::File(path) => readable_by_others(path),
            _ => None,
        }
    }
}

/// Where the value comes from, never what it is: `$NAME` for a variable, the
/// path of a file, `(exec PROGRAM)` for a command, and `(literal)` for a value
/// written in the config. A command's arguments are left out: they can hold
/// what no log should.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Literal(_) => f.write_str("(literal)"),
            SecretRef::Env(name) => write!(f, "${name}"),
            SecretRef::File(path) => write!(f, "{}", path.display()),
            SecretRef::Exec { program, .. } => write!(f, "(exec {program})"),
        }
    }
}

/// Leaves out a literal's value and a command's arguments, as `Display` does.
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Literal(value) => f.debug_tuple("Literal").field(value).finish(),
            SecretRef::Env(name) => f.debug_tuple("Env").field(name).finish(),
            SecretRef::File(path) => f.debug_tuple("File").field(path).finish(),
            SecretRef::Exec { program, args } => f
                .debug_struct("Exec")
                .field("program", program)
                .field("args", &format_args!("[{} hidden]", args.len()))
                .finish(),
        }
    }
}

/// Two literals are equal when their values are, so that a config whose
/// literal changed reads as changed.
impl PartialEq for SecretRef {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SecretRef::Literal(a), SecretRef::Literal(b)) => {
                a.expose_secret() == b.expose_secret()
            }
            (SecretRef::Env(a), SecretRef::Env(b)) => a == b,
            (SecretRef::File(a), SecretRef::File(b)) => a == b,
            (
                SecretRef::Exec { program, args },
                SecretRef::Exec {
                    program: other,
                    args: other_args,
                },
            ) => program == other && args == other_args,
            _ => false,
        }
    }
}

impl Eq for SecretRef {}

impl From<PathBuf> for SecretRef {
    fn from(path: PathBuf) -> Self {
        SecretRef::File(path)
    }
}

/// What a secret is, as a parse error says it.
const FORMS: &str = "the value as a string, { env = \"NAME\" }, { file = \"/path\" } or \
                     { exec = [\"command\", \"argument\"] }";

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SecretRefVisitor)
    }
}

struct SecretRefVisitor;

impl<'de> Visitor<'de> for SecretRefVisitor {
    type Value = SecretRef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a secret: {FORMS}")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<SecretRef, E> {
        Ok(SecretRef::Literal(SecretString::from(value)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut table: A) -> Result<SecretRef, A::Error> {
        let mut from = None;
        while let Some(key) = table.next_key::<String>()? {
            let place = match key.as_str() {
                "env" => SecretRef::Env(variable(table.next_value()?)?),
                "file" => SecretRef::File(file(table.next_value()?)?),
                "exec" => command(table.next_value_seed(Words)?)?,
                other => {
                    return Err(de::Error::custom(format!(
                        "`{other}` is not where a secret comes from: a secret is {FORMS}"
                    )))
                }
            };
            if from.replace(place).is_some() {
                return Err(de::Error::custom(
                    "a secret comes from one place: give one of `env`, `file` and `exec`",
                ));
            }
        }
        from.ok_or_else(|| de::Error::custom(format!("an empty table: a secret is {FORMS}")))
    }
}

/// An environment variable's name, as `env` gives it: one the environment
/// can hold.
fn variable<E: de::Error>(name: String) -> Result<String, E> {
    if name.is_empty() || name.contains(['=', '\0']) {
        return Err(E::custom(format!(
            "env = {name:?} names no environment variable"
        )));
    }
    Ok(name)
}

/// A file's path, as `file` gives it.
fn file<E: de::Error>(path: String) -> Result<PathBuf, E> {
    if path.is_empty() {
        return Err(E::custom("file = \"\" names no file"));
    }
    Ok(PathBuf::from(path))
}

/// What `exec` holds: a command's words, one string for each. A string, a
/// line for a shell, is refused with why, and without repeating it.
struct Words;

impl<'de> DeserializeSeed<'de> for Words {
    type Value = Vec<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<String>, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Words {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the command as an array, one string for each argument")
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Vec<String>, E> {
        Err(E::custom(
            "exec takes the command as an array, one element for each argument, since no \
             shell reads it: exec = [\"sops\", \"-d\", \"/path\"]",
        ))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut words: A) -> Result<Vec<String>, A::Error> {
        let mut argv = Vec::new();
        while let Some(word) = words.next_element()? {
            argv.push(word);
        }
        Ok(argv)
    }
}

/// A command, as `exec` gives it: the program, then each argument.
fn command<E: de::Error>(argv: Vec<String>) -> Result<SecretRef, E> {
    let Some((program, args)) = argv.split_first() else {
        return Err(E::custom("exec = [] names no command"));
    };
    if program.is_empty() {
        return Err(E::custom(
            "exec names no command: its first element is empty",
        ));
    }
    if argv.iter().any(|word| word.contains('\0')) {
        return Err(E::custom(
            "exec holds a NUL character, which no command's argument can",
        ));
    }
    Ok(SecretRef::Exec {
        program: program.clone(),
        args: args.to_vec(),
    })
}

/// Read a secret file: see [`SecretRef::resolve`].
fn read_file(path: &Path) -> Result<SecretString, SecretError> {
    let failed = |source: std::io::Error| SecretError::Read {
        path: path.to_owned(),
        source,
    };
    let not_a_file = || SecretError::NotAFile(path.to_owned());
    // Opening a FIFO waits for a writer, so what the path names is looked at
    // before it is opened, and what was opened after.
    if !std::fs::metadata(path).map_err(failed)?.is_file() {
        return Err(not_a_file());
    }
    let mut file = File::open(path).map_err(failed)?;
    let meta = file.metadata().map_err(failed)?;
    if !meta.is_file() {
        return Err(not_a_file());
    }
    let size = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    let bytes = read_capped(&mut file, size, MAX_FILE_BYTES).map_err(failed)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(SecretError::TooLarge(path.to_owned()));
    }
    text(&bytes).ok_or_else(|| SecretError::NotText(path.to_owned()))
}

/// Read `from` to its end, into a buffer that holds `size` bytes to begin
/// with, and one more to find the end. More room is made as it is needed, and
/// the old buffer wiped: one grown in place would leave copies behind. What is
/// read is wiped when dropped. Reading stops a byte past `cap`, which tells what
/// reached the cap from what went over it.
fn read_capped(from: &mut impl Read, size: usize, cap: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; size.min(cap) + 1]);
    let mut len = 0;
    loop {
        if len == buf.len() {
            if len > cap {
                break;
            }
            let mut bigger = Zeroizing::new(vec![0u8; (2 * len).min(cap + 1)]);
            bigger[..len].copy_from_slice(&buf[..len]);
            buf = bigger;
        }
        match from.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(len);
    Ok(buf)
}

/// Bytes read for a secret, as its value: UTF-8 text, less one line ending at
/// its end. `None` for bytes that are not text.
fn text(bytes: &[u8]) -> Option<SecretString> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text
        .strip_suffix('\n')
        .map_or(text, |line| line.strip_suffix('\r').unwrap_or(line));
    Some(SecretString::from(text))
}

/// Run a secret's command, and read what it writes: see
/// [`SecretRef::resolve`].
fn run(program: &str, args: &[String], timeout: Duration) -> Result<SecretString, SecretError> {
    let failed = |problem| SecretError::Exec {
        program: program.to_owned(),
        problem,
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| failed(ExecProblem::Start(e)))?;
    let deadline = Instant::now() + timeout;
    let mut output = child.stdout.take().expect("stdout is piped");
    // Read on a thread of its own, so that a command that neither writes nor
    // ends can be stopped at the deadline.
    let reading = move || read_capped(&mut output, 1024, MAX_OUTPUT_BYTES);
    let reader = match std::thread::Builder::new().spawn(reading) {
        Ok(reader) => reader,
        Err(e) => return Err(stop(&mut child, failed(ExecProblem::Read(e)))),
    };
    if poll_until(deadline, || reader.is_finished().then_some(())).is_none() {
        return Err(stop(&mut child, failed(ExecProblem::TimedOut(timeout))));
    }
    let bytes = match reader.join() {
        Ok(Ok(bytes)) if bytes.len() <= MAX_OUTPUT_BYTES => bytes,
        Ok(Ok(_)) => return Err(stop(&mut child, failed(ExecProblem::TooLarge))),
        Ok(Err(e)) => return Err(stop(&mut child, failed(ExecProblem::Read(e)))),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    match poll_until(deadline, || child.try_wait().transpose()) {
        Some(Ok(status)) if status.success() => {}
        Some(Ok(status)) => return Err(failed(ExecProblem::Exited(status))),
        Some(Err(e)) => return Err(stop(&mut child, failed(ExecProblem::Read(e)))),
        None => return Err(stop(&mut child, failed(ExecProblem::TimedOut(timeout)))),
    }
    text(&bytes).ok_or_else(|| failed(ExecProblem::NotText))
}

/// Kill a command that overran, reap it, and hand back why.
fn stop(child: &mut Child, why: SecretError) -> SecretError {
    let _ = child.kill();
    let _ = child.wait();
    why
}

/// What `ready` answers once it answers, or `None` if it has not by
/// `deadline`. It is asked at once, then at intervals that double from 50 µs
/// to 5 ms: a command that ends at once is seen at once, and one that takes
/// seconds is seen within 5 ms, for 200 wakings a second. A channel would wake
/// this the moment the output is read, but adds 21 KB to MCPdef's binary.
fn poll_until<T>(deadline: Instant, mut ready: impl FnMut() -> Option<T>) -> Option<T> {
    let mut pause = Duration::from_micros(50);
    loop {
        if let Some(answer) = ready() {
            return Some(answer);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(pause.min(left));
        pause = (pause * 2).min(Duration::from_millis(5));
    }
}

/// Who besides its owner can read the file at `path`, as a warning.
#[cfg(unix)]
fn readable_by_others(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    let who = exposed(meta.mode(), meta.uid(), own_uid())?;
    Some(format!(
        "{} can be read by {who} (mode {:03o}): make it readable by MCPdef's user alone, \
         with `chmod 600`, or let root own it and MCPdef's group alone read it, with \
         `chmod 640`",
        path.display(),
        meta.mode() & 0o777
    ))
}

/// Who besides its owner can read a file of `mode` that user `owner` owns,
/// for MCPdef running as user `me`, where that is known: its group, every
/// user, or both. `None` when no one else can.
///
/// A group root gives a file to is not counted when MCPdef does not run as
/// root, since that group is then how MCPdef reads it. A Kubernetes Secret
/// volume is such a file, whose owner is root and which the kubelet makes
/// readable by the pod's `fsGroup` whatever its mode, and so is a key in
/// Debian's `ssl-cert` group. PostgreSQL judges its key file much the same
/// way.
#[cfg(unix)]
fn exposed(mode: u32, owner: u32, me: Option<u32>) -> Option<&'static str> {
    let every_user = mode & 0o004 != 0;
    let granted = owner == 0 && !every_user && me.is_some_and(|me| me != 0);
    match (mode & 0o040 != 0 && !granted, every_user) {
        (false, false) => None,
        (true, false) => Some("its group"),
        (false, true) => Some("every user"),
        (true, true) => Some("its group and every user"),
    }
}

/// The user MCPdef runs as, where the system says: on Linux, the owner of
/// `/proc/self`, which is the process's effective user.
#[cfg(unix)]
fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|meta| meta.uid())
}

#[cfg(not(unix))]
fn readable_by_others(_: &Path) -> Option<String> {
    None
}

/// Why a secret could not be read. The message names where it was read
/// from, never what it holds.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The variable is not set.
    #[error("${0}: not set in MCPdef's environment")]
    Unset(String),
    /// The variable is set, to something that is not UTF-8 text.
    #[error("${0}: not UTF-8 text")]
    EnvNotText(String),
    /// The file could not be opened, or read.
    #[error("{}: {source}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The path names something besides a regular file: a directory, a
    /// FIFO, a device.
    #[error("{}: not a regular file", .0.display())]
    NotAFile(PathBuf),
    /// The file holds more than [`MAX_FILE_BYTES`].
    #[error(
        "{}: over {} KiB, more than a secret holds",
        .0.display(),
        MAX_FILE_BYTES / 1024
    )]
    TooLarge(PathBuf),
    /// The file is not UTF-8 text.
    #[error("{}: not UTF-8 text", .0.display())]
    NotText(PathBuf),
    /// The command gave no secret. Only its program is named: its arguments
    /// and what it wrote, to either output, are left out.
    #[error("(exec {program}): {problem}")]
    Exec {
        program: String,
        problem: ExecProblem,
    },
}

/// Why a command gave no secret.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecProblem {
    /// It could not be started: not found, say, or not executable.
    Start(io::Error),
    /// It had not ended by the timeout, and was stopped.
    TimedOut(Duration),
    /// It wrote more than [`MAX_OUTPUT_BYTES`], and was stopped.
    TooLarge,
    /// It ended with a status other than 0.
    Exited(ExitStatus),
    /// What it wrote is not UTF-8 text.
    NotText,
    /// Its output could not be read, for want of a thread to read it, say, or
    /// its status could not be learnt. It was stopped.
    Read(io::Error),
}

impl fmt::Display for ExecProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecProblem::Start(e) => write!(f, "could not start: {e}"),
            ExecProblem::TimedOut(limit) => {
                write!(f, "had not ended within {limit:?}, and was stopped")
            }
            ExecProblem::TooLarge => write!(
                f,
                "wrote over {} KiB, more than a secret holds, and was stopped",
                MAX_OUTPUT_BYTES / 1024
            ),
            ExecProblem::Exited(status) => {
                #[cfg(unix)]
                if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(status) {
                    return write!(f, "was killed by signal {signal}");
                }
                match status.code() {
                    Some(code) => write!(f, "exited with status {code}"),
                    None => write!(f, "ended: {status}"),
                }
            }
            ExecProblem::NotText => f.write_str("wrote something other than UTF-8 text"),
            ExecProblem::Read(e) => write!(f, "could not be read: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Debug)]
    struct Holder {
        secret: SecretRef,
    }

    fn parse(value: &str) -> Result<SecretRef, String> {
        toml::from_str::<Holder>(&format!("secret = {value}"))
            .map(|holder| holder.secret)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn each_form_parses() {
        let literal = parse("\"s3cret-value\"").unwrap();
        assert_eq!(literal.scheme(), "literal");
        assert_eq!(literal.resolve().unwrap().expose_secret(), "s3cret-value");
        assert_eq!(
            parse("{ env = \"MCPDEF_X\" }"),
            Ok(SecretRef::Env("MCPDEF_X".into()))
        );
        assert_eq!(
            parse("{ file = \"/run/secrets/x\" }"),
            Ok(SecretRef::File("/run/secrets/x".into()))
        );
        // A multi-line string, as a PEM key written in the config would be.
        let pem = parse("\"\"\"\nline one\nline two\n\"\"\"").unwrap();
        assert_eq!(
            pem.resolve().unwrap().expose_secret(),
            "line one\nline two\n"
        );
    }

    #[test]
    fn a_table_that_is_not_a_secret_says_what_one_is() {
        for (value, says) in [
            (
                "{ path = \"/x\" }",
                "`path` is not where a secret comes from",
            ),
            (
                "{ env = \"A\", file = \"/x\" }",
                "give one of `env`, `file` and `exec`",
            ),
            ("{}", "an empty table"),
            ("{ env = \"\" }", "names no environment variable"),
            ("{ env = \"A=B\" }", "names no environment variable"),
            ("{ file = \"\" }", "names no file"),
            ("{ env = 5 }", "invalid type: integer `5`"),
            (
                "5",
                "a secret: the value as a string, { env = \"NAME\" }, { file = \"/path\" } or \
                 { exec = [\"command\", \"argument\"] }",
            ),
        ] {
            let error = parse(value).unwrap_err();
            assert!(error.contains(says), "{value}: {error}");
        }
    }

    #[test]
    fn it_shows_where_a_value_comes_from_and_never_the_value() {
        let literal = SecretRef::Literal(SecretString::from("s3cret-value"));
        let env = SecretRef::Env("MCPDEF_X".into());
        let file = SecretRef::File("/run/secrets/x".into());
        assert_eq!(literal.to_string(), "(literal)");
        assert_eq!(env.to_string(), "$MCPDEF_X");
        assert_eq!(file.to_string(), "/run/secrets/x");
        assert_eq!(format!("{env:?}"), "Env(\"MCPDEF_X\")");
        assert_eq!(format!("{file:?}"), "File(\"/run/secrets/x\")");
        assert!(!format!("{literal:?}").contains("s3cret"));
        assert_eq!((env.var(), env.path()), (Some("MCPDEF_X"), None));
        assert_eq!(
            (file.var(), file.path()),
            (None, Some(Path::new("/run/secrets/x")))
        );
        assert_eq!((literal.var(), literal.path()), (None, None));
    }

    #[test]
    fn literals_are_equal_when_their_values_are() {
        let literal = |value: &str| SecretRef::Literal(SecretString::from(value));
        assert_eq!(literal("a"), literal("a"));
        assert_ne!(literal("a"), literal("b"));
        assert_ne!(literal("A"), SecretRef::Env("A".into()));
        assert_ne!(SecretRef::Env("A".into()), SecretRef::File("A".into()));
        assert_eq!(
            SecretRef::from(PathBuf::from("/x")),
            SecretRef::File("/x".into())
        );
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_command_parses_from_its_words_alone() {
        assert_eq!(
            parse("{ exec = [\"sops\", \"-d\", \"/etc/x.yaml\"] }"),
            Ok(SecretRef::Exec {
                program: "sops".into(),
                args: argv(&["-d", "/etc/x.yaml"]),
            })
        );
        for (value, says) in [
            (
                "{ exec = \"sops -d /etc/x.yaml\" }",
                "exec takes the command as an array, one element for each argument",
            ),
            (
                "{ exec = 5 }",
                "invalid type: integer `5`, expected the command as an array, one string for each \
                 argument",
            ),
            (
                "{ exec = [\"sops\", 5] }",
                "invalid type: integer `5`, expected a string",
            ),
            ("{ exec = [] }", "exec = [] names no command"),
            ("{ exec = [\"\", \"-d\"] }", "its first element is empty"),
            (
                "{ exec = [\"sops\", \"a\\u0000b\"] }",
                "holds a NUL character",
            ),
            (
                "{ exec = [\"sops\"], file = \"/x\" }",
                "give one of `env`, `file` and `exec`",
            ),
        ] {
            let error = parse(value).unwrap_err();
            assert!(error.contains(says), "{value}: {error}");
        }
    }

    #[test]
    fn a_command_is_shown_by_its_program_alone() {
        let exec = SecretRef::Exec {
            program: "op".into(),
            args: argv(&["read", "--token", "s3cret"]),
        };
        assert_eq!(exec.to_string(), "(exec op)");
        assert_eq!(
            format!("{exec:?}"),
            "Exec { program: \"op\", args: [3 hidden] }"
        );
        assert_eq!(exec.scheme(), "exec");
        assert_eq!(
            (exec.var(), exec.path(), exec.warning()),
            (None, None, None)
        );
        let other = SecretRef::Exec {
            program: "op".into(),
            args: argv(&["read", "--token", "other"]),
        };
        assert_ne!(exec, other);
        assert_eq!(exec, exec.clone());
    }

    /// Long enough for a command to start and write, short enough for a test.
    const QUICK: Duration = Duration::from_millis(400);

    fn problem(result: Result<SecretString, SecretError>) -> ExecProblem {
        match result {
            Err(SecretError::Exec { problem, .. }) => problem,
            other => panic!("{other:?}"),
        }
    }

    /// A command that neither writes nor ends is killed at the deadline, and
    /// reaped: no process, not even a zombie, is left behind.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_that_does_not_end_is_stopped_at_the_deadline_and_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("echo $$ > {}; exec sleep 30", pid_file.display());
        let started = Instant::now();
        let result = run("sh", &argv(&["-c", &script]), QUICK);
        let took = started.elapsed();
        assert!(matches!(problem(result), ExecProblem::TimedOut(QUICK)));
        assert!(
            took >= QUICK && took < QUICK + Duration::from_secs(2),
            "{took:?}"
        );
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));
        assert!(!proc.exists(), "{} is still there", proc.display());
    }

    /// One that closes its output and goes on is stopped too.
    #[test]
    fn a_command_that_closes_its_output_but_does_not_end_is_stopped() {
        let started = Instant::now();
        let result = run("sh", &argv(&["-c", "exec >&-; exec sleep 30"]), QUICK);
        assert!(matches!(problem(result), ExecProblem::TimedOut(QUICK)));
        assert!(started.elapsed() < QUICK + Duration::from_secs(2));
    }

    /// Output past the cap stops the command then, not at the deadline.
    #[test]
    fn a_command_that_writes_past_the_cap_is_stopped_at_once() {
        let started = Instant::now();
        let result = run("yes", &[], Duration::from_secs(30));
        assert!(matches!(problem(result), ExecProblem::TooLarge));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_root_gives_the_file_to_is_how_mcpdef_reads_it_unless_it_is_root() {
        const FILE: u32 = 0o100_000;
        // A Kubernetes Secret volume under the pod's fsGroup, and a key in
        // Debian's ssl-cert group: root owns them, and MCPdef, not root, reads
        // them through their group.
        assert_eq!(exposed(FILE | 0o440, 0, Some(65532)), None);
        assert_eq!(exposed(FILE | 0o640, 0, Some(1000)), None);
        // Not when every user can read it anyway...
        assert_eq!(
            exposed(FILE | 0o444, 0, Some(65532)),
            Some("its group and every user")
        );
        assert_eq!(exposed(FILE | 0o404, 0, Some(65532)), Some("every user"));
        // ...nor when MCPdef runs as root, which needs no group to read it...
        assert_eq!(exposed(FILE | 0o640, 0, Some(0)), Some("its group"));
        // ...nor when who MCPdef runs as is not known...
        assert_eq!(exposed(FILE | 0o640, 0, None), Some("its group"));
        // ...nor for a file a user other than root owns.
        assert_eq!(exposed(FILE | 0o640, 1000, Some(1000)), Some("its group"));
        assert_eq!(exposed(FILE | 0o640, 1001, Some(1000)), Some("its group"));
        assert_eq!(exposed(FILE | 0o600, 1000, Some(1000)), None);
        assert_eq!(exposed(FILE | 0o604, 1000, Some(1000)), Some("every user"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_mcpdef_knows_the_user_it_runs_as() {
        // The second of /proc/self/status's user ids is the effective one.
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let effective: u32 = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            .and_then(|id| id.parse().ok())
            .unwrap();
        assert_eq!(own_uid(), Some(effective));
    }
}
