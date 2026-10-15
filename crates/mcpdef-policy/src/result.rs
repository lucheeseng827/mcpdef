// SPDX-License-Identifier: Apache-2.0
//! What a `transform` rule does to a result: a tool call's, or a read's.
//!
//! A result reaches the model's context. A rule can redact the secrets a
//! detector finds in it, mask or remove what a path names in the JSON it
//! carries, and cut its text blocks short. Every edit is made to JSON values,
//! never to serialized text, so the result stays valid JSON, and so does
//! every text block that held JSON, unless a cut shortens it.
//!
//! - **The JSON a result carries** is its `structuredContent`, and each text
//!   block, or text content of a read, that holds a JSON object or array. A
//!   path's steps are object keys, and `*` takes every element of an array
//!   or every value of an object.
//! - **The mirror.** A text block that holds the `structuredContent` as JSON,
//!   as the spec says a tool's SHOULD, is not edited: when the structure
//!   changes, the block is written again from it, so the two agree.
//! - **The schema.** An edit of the `structuredContent` is checked against
//!   the tool's `outputSchema`. One the schema may not allow cannot apply: a
//!   string it constrains beyond its type, a key it requires, or a place it
//!   describes in a way this does not follow (a pattern of keys, `allOf`, a
//!   union whose branch it cannot tell, a reference outside the schema).
//!
//! As with arguments, an edit that cannot apply fails its rule, and what went
//! wrong names types and paths, never values. A key the result holds, and the
//! rule's path did not name, is data: a reason shows it as `*`, unless the
//! `outputSchema` names it. A key is never redacted, so a secret in one fails
//! a redaction.

use crate::transform::kind;
use serde_json::{Map, Value};
use std::ops::Range;

/// One edit of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultEdit {
    /// Every secret the detector finds in a string of the result becomes
    /// `[REDACTED:<the detector's rule>]`.
    Redact,
    /// The string at this path, in the JSON the result carries, becomes
    /// `[REDACTED:<the rule's name>]`. A path that holds nothing is left so,
    /// and one that holds anything but a string cannot apply: masked, it
    /// would change its type, and left, it would show.
    Mask(String),
    /// This path, in the JSON the result carries, is taken out. Its last
    /// step names a key.
    Remove(String),
    /// Each text block keeps at most this many bytes of its text, and a
    /// marker says how long it was. A mirror keeps to its structure.
    Truncate(usize),
}

/// What a detector found in a string: where, by which of its rules, and
/// whether it is a secret, which redaction replaces, or something else, which
/// no rewrite of the text makes safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// In bytes, on character boundaries.
    pub range: Range<usize>,
    pub rule: &'static str,
    pub secret: bool,
}

/// What finds the secrets in a string, in the order of the string, never
/// overlapping, kept to be shared: a borrowed one is any
/// `Fn(&str) -> Vec<Detected>`.
pub type Detector = dyn Fn(&str) -> Vec<Detected> + Send + Sync;

/// A detector as a pass borrows it.
type Find<'d> = dyn Fn(&str) -> Vec<Detected> + 'd;

/// Why the secrets of a result were not redacted, so that it is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unredacted {
    /// The detector found what is no secret, under this rule.
    Unsafe(&'static str),
    /// A secret, under this rule, that could not be redacted: why, by path,
    /// never by value.
    Kept(&'static str, String),
}

/// Redact every secret `detect` finds in a string of `result`, each as
/// `[REDACTED:<its rule>]`, keeping to `schema`, the tool's `outputSchema`:
/// the rules it found, in the order it first found them. Anything else it
/// finds refuses the result, as does a secret it cannot redact: one in a key,
/// or anywhere `detect` still finds one in the result written out as JSON,
/// such as an image's base64. So a result that passes holds nothing `detect`
/// finds. Refused, the result is left half done: the caller sends none of
/// it.
pub fn redact_result(
    result: &mut Value,
    schema: Option<&Value>,
    detect: &dyn Fn(&str) -> Vec<Detected>,
) -> Result<Vec<&'static str>, Unredacted> {
    let mirrors = mirrors(result);
    let mut found = Vec::new();
    let mut changes = Vec::new();
    let redacted = redact(result, &mirrors, detect, true, &mut found, &mut changes);
    let fault = match redacted {
        Ok(_) => match checked(result, schema, &changes) {
            Ok(()) => {
                if !changes.is_empty() {
                    write_mirrors(result, &mirrors);
                }
                match left_in(result, detect) {
                    None => return Ok(found),
                    Some(fault) => fault,
                }
            }
            Err(why) => Fault::Kept(found.first().copied().unwrap_or("secret"), why),
        },
        Err(fault) => fault,
    };
    Err(match fault {
        Fault::Unsafe(rule) => Unredacted::Unsafe(rule),
        Fault::Kept(rule, why) | Fault::Cannot(rule, why) => Unredacted::Kept(rule, why),
    })
}

/// Make `edits`, those of the rule named `rule`, to `result`, in order, each
/// to what the one before it left, keeping to `schema`: whether any changed
/// it, or why one cannot apply. `detect` finds the secrets `Redact` replaces;
/// without one, a `Redact` cannot apply.
pub(crate) fn apply(
    edits: &[ResultEdit],
    rule: &str,
    result: &mut Value,
    schema: Option<&Value>,
    detect: Option<&Find<'_>>,
) -> Result<bool, String> {
    let mirrors = mirrors(result);
    let mut changed = false;
    // Whether the structure changed: only then are the mirrors written
    // again, so a mirror otherwise keeps the upstream's own text.
    let mut restructured = false;
    for edit in edits {
        let mut changes = Vec::new();
        let edited = match edit {
            ResultEdit::Redact => {
                let detect = detect.ok_or("no secret detector is configured")?;
                redact(
                    result,
                    &mirrors,
                    detect,
                    false,
                    &mut Vec::new(),
                    &mut changes,
                )
            }
            ResultEdit::Mask(path) => paths(result, &mirrors, path, Op::Mask(rule), &mut changes),
            ResultEdit::Remove(path) => paths(result, &mirrors, path, Op::Remove, &mut changes),
            ResultEdit::Truncate(max) => Ok(truncate(result, &mirrors, *max)),
        };
        changed |= edited.map_err(|fault| match fault {
            Fault::Unsafe(found) => format!("its detector found what is no secret ({found})"),
            Fault::Kept(_, why) | Fault::Cannot(_, why) => why,
        })?;
        checked(result, schema, &changes)?;
        restructured |= !changes.is_empty();
    }
    if restructured {
        write_mirrors(result, &mirrors);
    }
    Ok(changed)
}

/// Why an edit stopped.
enum Fault {
    /// The detector found what is no secret, under this rule.
    Unsafe(&'static str),
    /// A secret, under this rule, that redaction did not make go away.
    Kept(&'static str, String),
    /// An edit that cannot apply, and why. The rule is the detector's, for a
    /// redaction, and otherwise unread.
    Cannot(&'static str, String),
}

/// A step of a path into a value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// A key the rule's path named.
    Key(String),
    /// A key the result holds, reached by a `*` or by a walk of every value:
    /// data, which a reason does not show.
    Found(String),
    Index(usize),
}

impl Step {
    /// The key the step takes, if it takes one.
    fn key(&self) -> Option<&str> {
        match self {
            Step::Key(key) | Step::Found(key) => Some(key),
            Step::Index(_) => None,
        }
    }
}

/// A path into the `structuredContent` as a reason shows it: a found key
/// as its name where `schema`, the tool's `outputSchema`, names it as a
/// property, and as `*` where not.
fn show(schema: &Value, path: &[Step]) -> String {
    let mut at = Some(schema);
    let mut steps = Vec::with_capacity(path.len());
    for step in path {
        let holder = at.and_then(|s| container(schema, s, step, 0));
        let named = |key: &str| {
            holder
                .and_then(|h| h.get("properties"))
                .is_some_and(|p| p.get(key).is_some())
        };
        steps.push(match step {
            Step::Found(key) if named(key) => Step::Key(key.clone()),
            other => other.clone(),
        });
        at = holder.and_then(|h| child(h, step));
    }
    show_from("structuredContent", &steps)
}

/// A path from `root`, where the JSON is, as a reason shows it: its steps
/// joined by dots, a found key as `*`.
fn show_from(root: &str, path: &[Step]) -> String {
    let mut shown = root.to_string();
    for step in path {
        shown.push('.');
        match step {
            Step::Key(key) => shown.push_str(key),
            Step::Found(_) => shown.push('*'),
            Step::Index(index) => shown.push_str(&index.to_string()),
        }
    }
    shown
}

/// What an edit did to the `structuredContent`, for its schema to judge.
enum Change {
    /// The string at this path is now this one.
    Replaced(Vec<Step>, String),
    /// The key at the end of this path was taken out.
    Removed(Vec<Step>),
}

/// Where a text block's text is in a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// `content[i].text`.
    Content(usize),
    /// `content[i].resource.text`, an embedded resource's.
    Embedded(usize),
    /// `contents[i].text`, a read's.
    Read(usize),
}

impl Block {
    /// Where the block's text is, as a reason shows it.
    fn label(self) -> String {
        match self {
            Block::Content(i) => format!("content.{i}.text"),
            Block::Embedded(i) => format!("content.{i}.resource.text"),
            Block::Read(i) => format!("contents.{i}.text"),
        }
    }

    fn text(self, result: &Value) -> Option<&str> {
        let at = match self {
            Block::Content(i) => result.get("content")?.get(i)?.get("text"),
            Block::Embedded(i) => result.get("content")?.get(i)?.get("resource")?.get("text"),
            Block::Read(i) => result.get("contents")?.get(i)?.get("text"),
        };
        at?.as_str()
    }

    fn text_mut(self, result: &mut Value) -> Option<&mut String> {
        let at = match self {
            Block::Content(i) => result.get_mut("content")?.get_mut(i)?.get_mut("text"),
            Block::Embedded(i) => result
                .get_mut("content")?
                .get_mut(i)?
                .get_mut("resource")?
                .get_mut("text"),
            Block::Read(i) => result.get_mut("contents")?.get_mut(i)?.get_mut("text"),
        };
        match at? {
            Value::String(text) => Some(text),
            _ => None,
        }
    }
}

/// Every text block of `result`.
fn blocks(result: &Value) -> Vec<Block> {
    let items = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .len()
    };
    let content = (0..items("content")).flat_map(|i| [Block::Content(i), Block::Embedded(i)]);
    let contents = (0..items("contents")).map(Block::Read);
    content
        .chain(contents)
        .filter(|block| block.text(result).is_some())
        .collect()
}

/// The text blocks that mirror the `structuredContent`: each holds it, as
/// JSON.
fn mirrors(result: &Value) -> Vec<Block> {
    let Some(structured) = result.get("structuredContent") else {
        return Vec::new();
    };
    blocks(result)
        .into_iter()
        .filter(|block| matches!(block, Block::Content(_)))
        .filter(|block| {
            block
                .text(result)
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
                .is_some_and(|held| &held == structured)
        })
        .collect()
}

/// Write each mirror again from the `structuredContent`, laid out as it was.
fn write_mirrors(result: &mut Value, mirrors: &[Block]) {
    let Some(structured) = result.get("structuredContent").cloned() else {
        return;
    };
    for block in mirrors {
        if let Some(text) = block.text_mut(result) {
            *text = json_text(text, &structured);
        }
    }
}

/// The JSON object or array `text` holds, if it holds one.
fn json_in(text: &str) -> Option<Value> {
    match serde_json::from_str(text) {
        Ok(value @ (Value::Object(_) | Value::Array(_))) => Some(value),
        _ => None,
    }
}

/// `value` as JSON text, spread over lines when `was`, the text it replaces,
/// was.
fn json_text(was: &str, value: &Value) -> String {
    let text = if was.contains('\n') {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    text.unwrap_or_default()
}

/// How many times a string is searched again after its secrets are
/// replaced: a replacement beside other text could make a new match.
const ROUNDS: usize = 3;

/// Redact what `detect` finds in `text`: its secrets, and, when `strict`,
/// anything else it finds refuses. Whether it changed.
fn redact_text(
    text: &mut String,
    detect: &Find<'_>,
    strict: bool,
    found: &mut Vec<&'static str>,
) -> Result<bool, Fault> {
    let mut changed = false;
    for _ in 0..ROUNDS {
        let hits: Vec<Detected> = detect(text)
            .into_iter()
            .filter(|hit| strict || hit.secret)
            .collect();
        if hits.is_empty() {
            return Ok(changed);
        }
        if let Some(unsafe_hit) = hits.iter().find(|hit| !hit.secret) {
            return Err(Fault::Unsafe(unsafe_hit.rule));
        }
        for hit in hits.iter().rev() {
            if text.get(hit.range.clone()).is_none() {
                return Err(Fault::Kept(
                    hit.rule,
                    "its detector placed a secret off the text".into(),
                ));
            }
            text.replace_range(hit.range.clone(), &format!("[REDACTED:{}]", hit.rule));
        }
        for hit in &hits {
            if !found.contains(&hit.rule) {
                found.push(hit.rule);
            }
        }
        changed = true;
    }
    match detect(text).into_iter().find(|hit| strict || hit.secret) {
        None => Ok(changed),
        Some(hit) => Err(Fault::Kept(
            hit.rule,
            "a secret is still found once redacted".into(),
        )),
    }
}

/// What `each_string` calls on a string, with its path.
type Visit<'v> = dyn FnMut(&mut String, &[Step]) -> Result<(), Fault> + 'v;

/// Call `f` on every string in `value`, with its path from `at`, except
/// where `skip` says a path is not to be entered.
fn each_string(
    value: &mut Value,
    at: &mut Vec<Step>,
    skip: &dyn Fn(&[Step]) -> bool,
    f: &mut Visit<'_>,
) -> Result<(), Fault> {
    match value {
        Value::String(text) => f(text, at),
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                at.push(Step::Index(index));
                if !skip(at) {
                    each_string(item, at, skip, f)?;
                }
                at.pop();
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                at.push(Step::Found(key.clone()));
                if !skip(at) {
                    each_string(item, at, skip, f)?;
                }
                at.pop();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Whether a path into a result is one the redaction of its strings leaves
/// to a pass of its own (the structure, the text blocks), or passes over
/// (an image's, an audio clip's or a blob's base64, in a tool result, a
/// read, or a prompt's messages).
fn apart(at: &[Step]) -> bool {
    let key = |step: &Step, names: &[&str]| step.key().is_some_and(|k| names.contains(&k));
    match at {
        [first] => key(first, &["structuredContent"]),
        [first, Step::Index(_), last] => {
            (key(first, &["content"]) && key(last, &["text", "data"]))
                || (key(first, &["contents"]) && key(last, &["text", "blob"]))
        }
        [first, Step::Index(_), middle, last] => {
            (key(first, &["content"]) && key(middle, &["resource"]) && key(last, &["text", "blob"]))
                || (key(first, &["messages"]) && key(middle, &["content"]) && key(last, &["data"]))
        }
        [first, Step::Index(_), middle, resource, last] => {
            key(first, &["messages"])
                && key(middle, &["content"])
                && key(resource, &["resource"])
                && key(last, &["blob"])
        }
        _ => false,
    }
}

/// Redact every secret in `result`'s strings: its `structuredContent`'s,
/// its text blocks' (in the values of one that holds JSON), and every other
/// but the base64 of an image, audio or blob. Mirrors are written again from
/// the structure, not redacted. Whether anything changed.
fn redact(
    result: &mut Value,
    mirrors: &[Block],
    detect: &Find<'_>,
    strict: bool,
    found: &mut Vec<&'static str>,
    changes: &mut Vec<Change>,
) -> Result<bool, Fault> {
    let mut changed = false;
    if let Some(map) = result.as_object() {
        for (key, value) in map {
            keys_clean(key, "the result", detect, strict)?;
            let root = match key.as_str() {
                "structuredContent" => "`structuredContent`",
                _ => "the result",
            };
            each_key(value, &mut |key| keys_clean(key, root, detect, strict))?;
        }
    }
    if let Some(structured) = result.get_mut("structuredContent") {
        each_string(structured, &mut Vec::new(), &|_| false, &mut |text, at| {
            if redact_text(text, detect, strict, found)? {
                changes.push(Change::Replaced(at.to_vec(), text.clone()));
                changed = true;
            }
            Ok(())
        })?;
    }
    for block in blocks(result) {
        if mirrors.contains(&block) {
            continue;
        }
        let Some(text) = block.text_mut(result) else {
            continue;
        };
        match json_in(text) {
            Some(mut value) => {
                let root = format!("`{}`", block.label());
                each_key(&value, &mut |key| keys_clean(key, &root, detect, strict))?;
                let mut redacted = false;
                each_string(&mut value, &mut Vec::new(), &|_| false, &mut |leaf, _| {
                    redacted |= redact_text(leaf, detect, strict, found)?;
                    Ok(())
                })?;
                if redacted {
                    *text = json_text(text, &value);
                    changed = true;
                }
            }
            None => changed |= redact_text(text, detect, strict, found)?,
        }
    }
    each_string(result, &mut Vec::new(), &apart, &mut |text, _| {
        changed |= redact_text(text, detect, strict, found)?;
        Ok(())
    })?;
    Ok(changed)
}

/// Call `f` on every key of every object in `value`.
fn each_key(value: &Value, f: &mut dyn FnMut(&str) -> Result<(), Fault>) -> Result<(), Fault> {
    match value {
        Value::Array(items) => items.iter().try_for_each(|item| each_key(item, f)),
        Value::Object(map) => map.iter().try_for_each(|(key, item)| {
            f(key)?;
            each_key(item, f)
        }),
        _ => Ok(()),
    }
}

/// Whether `key`, a key of an object in `root`, holds nothing `detect`
/// finds: a secret or, when `strict`, anything. A key is not redacted:
/// renamed, it could meet another, and the schema names the keys it allows.
fn keys_clean(key: &str, root: &str, detect: &Find<'_>, strict: bool) -> Result<(), Fault> {
    let hits: Vec<Detected> = detect(key)
        .into_iter()
        .filter(|hit| strict || hit.secret)
        .collect();
    if let Some(hit) = hits.iter().find(|hit| !hit.secret) {
        return Err(Fault::Unsafe(hit.rule));
    }
    match hits.first() {
        None => Ok(()),
        Some(hit) => Err(Fault::Kept(
            hit.rule,
            format!("a key in {root} holds a secret, and MCPdef does not redact a key"),
        )),
    }
}

/// What `detect` still finds in `result` written out as JSON, where the
/// redaction of its strings does not reach: the base64 of an image, an
/// audio clip or a blob, a number, or a match that runs across strings.
fn left_in(result: &Value, detect: &Find<'_>) -> Option<Fault> {
    let hits = detect(&result.to_string());
    if let Some(hit) = hits.iter().find(|hit| !hit.secret) {
        return Some(Fault::Unsafe(hit.rule));
    }
    hits.first().map(|hit| {
        Fault::Kept(
            hit.rule,
            "it is found in the result as a whole, outside the strings MCPdef redacts".into(),
        )
    })
}

/// What a path edit does at each place its path names.
#[derive(Clone, Copy)]
enum Op<'r> {
    /// Put `[REDACTED:<rule>]` in place of a string.
    Mask(&'r str),
    /// Take the key out.
    Remove,
}

/// Make a path edit to the JSON `result` carries: its `structuredContent`,
/// and each text block, not a mirror, that holds JSON. Whether it changed.
fn paths(
    result: &mut Value,
    mirrors: &[Block],
    path: &str,
    op: Op<'_>,
    changes: &mut Vec<Change>,
) -> Result<bool, Fault> {
    let steps: Vec<&str> = path.split('.').collect();
    let mut changed = false;
    if let Some(structured) = result.get_mut("structuredContent") {
        changed |= edit_at(structured, "structuredContent", &steps, op, changes)?;
    }
    for block in blocks(result) {
        if mirrors.contains(&block) {
            continue;
        }
        let Some(text) = block.text_mut(result) else {
            continue;
        };
        if let Some(mut value) = json_in(text) {
            if edit_at(&mut value, &block.label(), &steps, op, &mut Vec::new())? {
                *text = json_text(text, &value);
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// Make a path edit to `value`, the JSON at `root`, at every place `steps`
/// names in it.
fn edit_at(
    value: &mut Value,
    root: &str,
    steps: &[&str],
    op: Op<'_>,
    changes: &mut Vec<Change>,
) -> Result<bool, Fault> {
    let mut places = Vec::new();
    places_in(value, steps, &mut Vec::new(), &mut places);
    let mut changed = false;
    for place in places {
        match op {
            Op::Mask(rule) => match place_mut(value, &place) {
                Some(Value::String(text)) => {
                    let token = mask(rule);
                    if *text != token {
                        *text = token.clone();
                        changes.push(Change::Replaced(place, token));
                        changed = true;
                    }
                }
                None | Some(Value::Null) => {}
                Some(other) => {
                    let why = format!(
                        "`{}` is {}, not a string",
                        show_from(root, &place),
                        kind(other)
                    );
                    return Err(Fault::Cannot("", why));
                }
            },
            Op::Remove => {
                let Some((Some(key), parent)) = place.split_last().map(|(l, p)| (l.key(), p))
                else {
                    continue;
                };
                let removed = match place_mut(value, parent) {
                    Some(Value::Object(object)) => object.remove(key).is_some(),
                    _ => false,
                };
                if removed {
                    changes.push(Change::Removed(place));
                    changed = true;
                }
            }
        }
    }
    Ok(changed)
}

/// The places `steps` names in `value`, as paths from `at`. `*` names every
/// element of an array and every value of an object. A key that is not there,
/// or a step through anything that is neither, names nothing.
fn places_in(value: &Value, steps: &[&str], at: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    let Some((first, rest)) = steps.split_first() else {
        out.push(at.clone());
        return;
    };
    let mut each = |step: Step, item: &Value| {
        at.push(step);
        places_in(item, rest, at, out);
        at.pop();
    };
    match (*first, value) {
        ("*", Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                each(Step::Index(index), item);
            }
        }
        ("*", Value::Object(map)) => {
            for (key, item) in map {
                each(Step::Found(key.clone()), item);
            }
        }
        (key, Value::Object(map)) => {
            if let Some(item) = map.get(key) {
                each(Step::Key(key.to_string()), item);
            }
        }
        _ => {}
    }
}

/// The value at `path` in `value`.
fn place_mut<'v>(value: &'v mut Value, path: &[Step]) -> Option<&'v mut Value> {
    path.iter().try_fold(value, |value, step| match step {
        Step::Key(key) | Step::Found(key) => value.get_mut(key.as_str()),
        Step::Index(index) => value.get_mut(*index),
    })
}

/// What a mask puts in place of a string: the rule's name, less what could
/// end a JSON string written out by hand.
fn mask(rule: &str) -> String {
    let name: String = rule
        .chars()
        .filter(|c| !matches!(c, '"' | '\\') && !c.is_control())
        .collect();
    format!("[REDACTED:{name}]")
}

/// Cut each text block, but the mirrors, to `max` bytes, at a character
/// boundary, and say how long it was. Whether any was cut.
fn truncate(result: &mut Value, mirrors: &[Block], max: usize) -> bool {
    let mut changed = false;
    for block in blocks(result) {
        if mirrors.contains(&block) {
            continue;
        }
        let Some(text) = block.text_mut(result) else {
            continue;
        };
        if text.len() > max {
            let total = text.len();
            let mut end = max;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str(&format!(
                "\n[MCPdef cut this text from {total} bytes to {end}]"
            ));
            changed = true;
        }
    }
    changed
}

/// Whether the `structuredContent` of `result`, as `changes` left it, still
/// keeps to `schema`, the tool's `outputSchema`, at every place they touched.
fn checked(result: &Value, schema: Option<&Value>, changes: &[Change]) -> Result<(), String> {
    let Some(schema) = schema else {
        return Ok(());
    };
    for change in changes {
        let (path, verdict) = match change {
            Change::Replaced(path, text) => (path, string_at(schema, path, text)),
            Change::Removed(path) => {
                let left = path
                    .split_last()
                    .and_then(|(_, parent)| {
                        result
                            .get("structuredContent")
                            .and_then(|s| place(s, parent))
                    })
                    .and_then(Value::as_object)
                    .map_or(0, Map::len);
                (path, removal_at(schema, path, left))
            }
        };
        match verdict {
            Some(true) => {}
            Some(false) => {
                let what = match change {
                    Change::Replaced(..) => "changing",
                    Change::Removed(_) => "removing",
                };
                return Err(format!(
                    "{what} `{}` would break the tool's outputSchema",
                    show(schema, path)
                ));
            }
            None => {
                return Err(format!(
                    "the tool's outputSchema at `{}` is not one MCPdef can check",
                    show(schema, path)
                ))
            }
        }
    }
    Ok(())
}

/// The value at `path` in `value`.
fn place<'v>(value: &'v Value, path: &[Step]) -> Option<&'v Value> {
    path.iter().try_fold(value, |value, step| match step {
        Step::Key(key) | Step::Found(key) => value.get(key.as_str()),
        Step::Index(index) => value.get(*index),
    })
}

/// A schema that allows anything.
const ANYTHING: Value = Value::Bool(true);

/// How many references, or nested unions, a check follows before it gives up.
const DEPTH: usize = 16;

/// Keywords whose meaning a check does not follow: a schema that has one
/// cannot be checked.
const UNFOLLOWED: &[&str] = &[
    "allOf",
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "$dynamicRef",
    "$recursiveRef",
    "unevaluatedProperties",
    "unevaluatedItems",
];

/// Keywords that constrain a string's value: a changed string may not keep
/// to them.
const VALUED: &[&str] = &[
    "enum",
    "const",
    "pattern",
    "format",
    "contentEncoding",
    "contentMediaType",
    "contentSchema",
];

/// `schema` with its local `$ref`s followed, from `root`.
fn resolve<'s>(root: &'s Value, mut schema: &'s Value) -> Option<&'s Value> {
    for _ in 0..DEPTH {
        match schema.get("$ref").and_then(Value::as_str) {
            Some(reference) => schema = root.pointer(reference.strip_prefix('#')?)?,
            None => return Some(schema),
        }
    }
    None
}

/// Whether `schema`'s `type` lets a value be `kind`.
fn typed(schema: &Value, kind: &str) -> bool {
    match schema.get("type") {
        None => true,
        Some(Value::String(t)) => t == kind || (kind == "integer" && t == "number"),
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some(kind)),
        Some(_) => false,
    }
}

/// The schema `schema` gives a value that a `step` is taken into: the one
/// branch of a union that could be such a value. `None` when it cannot tell.
fn container<'s>(
    root: &'s Value,
    schema: &'s Value,
    step: &Step,
    depth: usize,
) -> Option<&'s Value> {
    let schema = resolve(root, schema)?;
    let shaped_as_one = schema.is_object() || schema.is_boolean();
    if !shaped_as_one || depth > DEPTH || UNFOLLOWED.iter().any(|k| schema.get(k).is_some()) {
        return None;
    }
    let union = schema.get("anyOf").or_else(|| schema.get("oneOf"));
    let Some(branches) = union else {
        return Some(schema);
    };
    let shaped = [
        "properties",
        "additionalProperties",
        "required",
        "items",
        "prefixItems",
    ];
    if shaped.iter().any(|k| schema.get(k).is_some()) {
        return None;
    }
    let kind = match step {
        Step::Key(_) | Step::Found(_) => "object",
        Step::Index(_) => "array",
    };
    let mut fits = branches
        .as_array()?
        .iter()
        .filter_map(|branch| resolve(root, branch))
        .filter(|branch| branch.is_object() && typed(branch, kind));
    let one = fits.next()?;
    if fits.next().is_some() {
        return None;
    }
    container(root, one, step, depth + 1)
}

/// The schema of the value `step` reaches in a value `schema` describes.
fn child<'s>(schema: &'s Value, step: &Step) -> Option<&'s Value> {
    match schema {
        Value::Bool(true) => return Some(&ANYTHING),
        Value::Bool(false) => return None,
        _ => {}
    }
    let rest = |key: &str| match schema.get(key) {
        None | Some(Value::Bool(true)) => Some(&ANYTHING),
        Some(Value::Bool(false)) => None,
        Some(other) => Some(other),
    };
    match step {
        Step::Key(key) | Step::Found(key) => {
            match schema.get("properties").and_then(|p| p.get(key.as_str())) {
                Some(sub) => Some(sub),
                None if schema.get("patternProperties").is_some() => None,
                None => rest("additionalProperties"),
            }
        }
        Step::Index(index) => {
            match schema.get("prefixItems").and_then(|p| p.get(*index)) {
                Some(sub) => Some(sub),
                // An older schema's tuple: `items` is a list.
                None => match schema.get("items") {
                    Some(Value::Array(tuple)) => match tuple.get(*index) {
                        Some(sub) => Some(sub),
                        None => rest("additionalItems"),
                    },
                    _ => rest("items"),
                },
            }
        }
    }
}

/// The schema at `path` from `root`.
fn schema_at<'s>(root: &'s Value, path: &[Step]) -> Option<&'s Value> {
    path.iter().try_fold(root, |schema, step| {
        child(container(root, schema, step, 0)?, step)
    })
}

/// Whether the schema at `path` lets the string there be `text`: `None`
/// when it cannot tell.
fn string_at(root: &Value, path: &[Step], text: &str) -> Option<bool> {
    allows_string(root, schema_at(root, path)?, text, 0)
}

fn allows_string(root: &Value, schema: &Value, text: &str, depth: usize) -> Option<bool> {
    let schema = resolve(root, schema)?;
    match schema {
        Value::Bool(allowed) => return Some(*allowed),
        Value::Object(_) => {}
        _ => return None,
    }
    if depth > DEPTH || UNFOLLOWED.iter().any(|k| schema.get(k).is_some()) {
        return None;
    }
    let verdicts = |key: &str| -> Option<Vec<Option<bool>>> {
        let branches = schema.get(key)?.as_array()?;
        Some(
            branches
                .iter()
                .map(|branch| allows_string(root, branch, text, depth + 1))
                .collect(),
        )
    };
    if let Some(any) = verdicts("anyOf") {
        if !any.contains(&Some(true)) {
            return if any.contains(&None) {
                None
            } else {
                Some(false)
            };
        }
    }
    if let Some(one) = verdicts("oneOf") {
        if one.contains(&None) {
            return None;
        }
        if one.iter().filter(|v| **v == Some(true)).count() != 1 {
            return Some(false);
        }
    }
    if !typed(schema, "string") || VALUED.iter().any(|k| schema.get(k).is_some()) {
        return Some(false);
    }
    let length = text.chars().count() as u64;
    let below = schema
        .get("minLength")
        .and_then(Value::as_u64)
        .is_some_and(|min| length < min);
    let above = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .is_some_and(|max| length > max);
    Some(!below && !above)
}

/// Whether the schema lets the key at the end of `path` be taken out of the
/// object that held it, which has `left` keys now: `None` when it cannot
/// tell.
fn removal_at(root: &Value, path: &[Step], left: usize) -> Option<bool> {
    let (step, parent) = path.split_last()?;
    let key = step.key()?;
    let schema = container(root, schema_at(root, parent)?, step, 0)?;
    if *schema == ANYTHING {
        return Some(true);
    }
    if schema.get("dependentRequired").is_some() || schema.get("dependencies").is_some() {
        return None;
    }
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|k| k.as_str() == Some(key)));
    let too_few = schema
        .get("minProperties")
        .and_then(Value::as_u64)
        .is_some_and(|min| (left as u64) < min);
    Some(!required && !too_few)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A detector of `AKIA` followed by eight capitals, as a secret, and of
    /// `ignore all`, as what is no secret.
    fn detector() -> Box<Detector> {
        Box::new(|text: &str| {
            let mut found = Vec::new();
            let mut from = 0;
            while let Some(at) = text[from..].find("AKIA") {
                let start = from + at;
                let end = start + 12;
                if text
                    .get(start..end)
                    .is_some_and(|t| t[4..].chars().all(|c| c.is_ascii_uppercase()))
                {
                    found.push(Detected {
                        range: start..end,
                        rule: "aws-access-key",
                        secret: true,
                    });
                    from = end;
                } else {
                    from = start + 4;
                }
            }
            if let Some(at) = text.find("ignore all") {
                found.push(Detected {
                    range: at..at + 10,
                    rule: "ignore-previous-instructions",
                    secret: false,
                });
            }
            found.sort_by_key(|d| d.range.start);
            found
        })
    }

    fn key() -> String {
        ["AKIA", "ABCDEFGH"].concat()
    }

    /// A tool result: `structured`, a text block mirroring it, and `text`.
    fn tool_result(structured: Value, text: &str) -> Value {
        json!({
            "content": [
                { "type": "text", "text": structured.to_string() },
                { "type": "text", "text": text },
            ],
            "structuredContent": structured,
            "isError": false,
        })
    }

    fn mirror_agrees(result: &Value) -> bool {
        let text = result["content"][0]["text"].as_str().unwrap();
        serde_json::from_str::<Value>(text).unwrap() == result["structuredContent"]
    }

    fn edited(edits: &[ResultEdit], mut result: Value, schema: Option<&Value>) -> (Value, bool) {
        let detect = detector();
        let changed = apply(edits, "no-secrets", &mut result, schema, Some(&*detect)).unwrap();
        (result, changed)
    }

    #[test]
    fn redact_replaces_each_secret_in_every_string_and_the_mirror_follows() {
        let key = key();
        let result = json!({
            "content": [
                { "type": "text", "text": json!({ "token": key }).to_string() },
                { "type": "text", "text": format!("key {key} and {key}") },
                { "type": "text", "text": json!({ "nested": [format!("x{key}")] }).to_string() },
                { "type": "image", "data": key, "mimeType": "image/png" },
                { "type": "resource_link", "uri": format!("file:///{key}"), "name": "n" },
            ],
            "structuredContent": { "token": key },
        });
        let (out, changed) = edited(&[ResultEdit::Redact], result, None);
        assert!(changed);
        let token = "[REDACTED:aws-access-key]";
        assert_eq!(out["structuredContent"], json!({ "token": token }));
        assert!(mirror_agrees(&out));
        assert_eq!(
            out["content"][1]["text"],
            format!("key {token} and {token}")
        );
        // A block that held JSON holds it still, redacted in its values.
        let nested: Value =
            serde_json::from_str(out["content"][2]["text"].as_str().unwrap()).unwrap();
        assert_eq!(nested, json!({ "nested": [format!("x{token}")] }));
        // The base64 of an image is passed over; a link's URI is not.
        assert_eq!(out["content"][3]["data"], key);
        assert_eq!(out["content"][4]["uri"], format!("file:///{token}"));
    }

    #[test]
    fn redact_leaves_what_is_no_secret_and_a_clean_result_as_it_was() {
        let result = tool_result(json!({ "a": "ignore all of it" }), "plain");
        let (out, changed) = edited(&[ResultEdit::Redact], result.clone(), None);
        assert_eq!((out, changed), (result, false));
    }

    #[test]
    fn redact_result_refuses_what_is_no_secret_and_names_the_rules_it_redacted() {
        let detect = detector();
        let mut result = tool_result(json!({ "a": key() }), &format!("{} ok", key()));
        assert_eq!(
            redact_result(&mut result, None, &*detect),
            Ok(vec!["aws-access-key"])
        );
        assert!(!result.to_string().contains(&key()));
        assert!(mirror_agrees(&result));
        let mut injected = tool_result(json!({ "a": key() }), "now ignore all of it");
        assert_eq!(
            redact_result(&mut injected, None, &*detect),
            Err(Unredacted::Unsafe("ignore-previous-instructions"))
        );
    }

    #[test]
    fn a_secret_redaction_makes_again_is_kept_and_refuses() {
        // A detector that finds its own replacement, in the one string it
        // reads: redaction never ends.
        let stubborn: Box<Detector> = Box::new(|text: &str| {
            let range = match text.find("REDACTED") {
                Some(at) => at..at + 8,
                None if text == "anything" => 0..text.len(),
                None => return Vec::new(),
            };
            vec![Detected {
                range,
                rule: "loop",
                secret: true,
            }]
        });
        let result = json!({ "content": [{ "type": "text", "text": "anything" }] });
        let still = "a secret is still found once redacted".to_string();
        assert_eq!(
            redact_result(&mut result.clone(), None, &*stubborn),
            Err(Unredacted::Kept("loop", still.clone()))
        );
        assert_eq!(
            apply(
                &[ResultEdit::Redact],
                "r",
                &mut result.clone(),
                None,
                Some(&*stubborn)
            ),
            Err(still)
        );
    }

    #[test]
    fn redact_without_a_detector_cannot_apply() {
        let mut result = tool_result(json!({ "a": 1 }), "x");
        assert_eq!(
            apply(&[ResultEdit::Redact], "r", &mut result, None, None),
            Err("no secret detector is configured".into())
        );
    }

    #[test]
    fn mask_puts_the_rules_name_in_place_of_each_string_its_path_names() {
        let structured = json!({
            "users": [{ "email": "a@x", "age": 3 }, { "email": "b@x" }, { "name": "c" }],
            "owner": { "email": null },
        });
        let (out, changed) = edited(
            &[
                ResultEdit::Mask("users.*.email".into()),
                ResultEdit::Mask("owner.email".into()),
            ],
            tool_result(structured, "{\"users\": [{\"email\": \"z@x\"}]}"),
            None,
        );
        assert!(changed);
        let masked = "[REDACTED:no-secrets]";
        assert_eq!(
            out["structuredContent"],
            json!({
                "users": [{ "email": masked, "age": 3 }, { "email": masked }, { "name": "c" }],
                "owner": { "email": null },
            })
        );
        assert!(mirror_agrees(&out));
        // A block that holds JSON is edited as the structure is, and stays laid
        // out on one line, as it came.
        assert_eq!(
            out["content"][1]["text"],
            json!({ "users": [{ "email": masked }] }).to_string()
        );
    }

    #[test]
    fn mask_of_what_is_no_string_cannot_apply_and_says_where_not_what() {
        let result = tool_result(json!({ "user": { "pin": 1234 } }), "x");
        let mut out = result.clone();
        let detect = detector();
        let why = apply(
            &[ResultEdit::Mask("user.pin".into())],
            "r",
            &mut out,
            None,
            Some(&*detect),
        )
        .unwrap_err();
        assert_eq!(
            why,
            "`structuredContent.user.pin` is a number, not a string"
        );
        assert!(!why.contains("1234"));
    }

    #[test]
    fn remove_takes_out_each_key_its_path_names_and_nothing_else() {
        let (out, changed) = edited(
            &[ResultEdit::Remove("items.*.secret".into())],
            tool_result(
                json!({ "items": [{ "secret": "s", "id": 1 }, { "id": 2 }], "secret": "kept" }),
                "x",
            ),
            None,
        );
        assert!(changed);
        assert_eq!(
            out["structuredContent"],
            json!({ "items": [{ "id": 1 }, { "id": 2 }], "secret": "kept" })
        );
        assert!(mirror_agrees(&out));
        // A path that names nothing changes nothing, and is no failure.
        let (same, changed) = edited(
            &[
                ResultEdit::Remove("nowhere.near".into()),
                ResultEdit::Mask("id.deeper".into()),
            ],
            tool_result(json!({ "id": 1 }), "x"),
            None,
        );
        assert!(!changed);
        assert_eq!(same, tool_result(json!({ "id": 1 }), "x"));
    }

    #[test]
    fn truncate_cuts_each_text_block_at_a_character_boundary_but_the_mirror() {
        let structured = json!({ "long": "x".repeat(40) });
        let result = json!({
            "content": [
                { "type": "text", "text": structured.to_string() },
                { "type": "text", "text": "ééééé" },
                { "type": "resource", "resource": { "uri": "file:///a", "text": "0123456789" } },
            ],
            "structuredContent": structured,
        });
        let (out, changed) = edited(&[ResultEdit::Truncate(5)], result, None);
        assert!(changed);
        assert!(mirror_agrees(&out));
        assert_eq!(
            out["content"][1]["text"],
            "éé\n[MCPdef cut this text from 10 bytes to 4]"
        );
        assert_eq!(
            out["content"][2]["resource"]["text"],
            "01234\n[MCPdef cut this text from 10 bytes to 5]"
        );
        let short = json!({ "contents": [{ "uri": "file:///a", "text": "abc" }] });
        assert_eq!(
            edited(&[ResultEdit::Truncate(5)], short.clone(), None),
            (short, false)
        );
        // A mirror is written again only when its structure changes: while a
        // text is cut, it keeps the upstream's own layout.
        let layout = "{\"b\": 1, \"a\": 2}";
        let kept = json!({
            "content": [
                { "type": "text", "text": layout },
                { "type": "text", "text": "0123456789" },
            ],
            "structuredContent": { "a": 2, "b": 1 },
        });
        let (out, changed) = edited(&[ResultEdit::Truncate(5)], kept, None);
        assert!(changed);
        assert_eq!(out["content"][0]["text"], layout);
    }

    #[test]
    fn a_reads_text_contents_take_every_edit() {
        let result = json!({ "contents": [
            { "uri": "file:///a.json", "mimeType": "application/json",
              "text": json!({ "password": "p", "key": key() }).to_string() },
            { "uri": "file:///b", "blob": key() },
        ] });
        let (out, _) = edited(
            &[ResultEdit::Redact, ResultEdit::Remove("password".into())],
            result,
            None,
        );
        let held: Value =
            serde_json::from_str(out["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(held, json!({ "key": "[REDACTED:aws-access-key]" }));
        assert_eq!(out["contents"][1]["blob"], key());
    }

    #[test]
    fn an_edit_the_output_schema_may_not_allow_cannot_apply() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] },
                "id": { "type": "string" },
                "email": { "type": "string", "format": "email" },
                "short": { "type": "string", "maxLength": 4 },
                "note": { "anyOf": [{ "type": "string" }, { "type": "null" }] },
                "user": { "$ref": "#/$defs/user" },
                "odd": { "allOf": [{ "type": "string" }] },
            },
            "required": ["id"],
            "$defs": { "user": { "type": "object", "properties": { "name": { "type": "string" } } } },
        });
        let structured = json!({
            "state": "open", "id": "1", "email": "a@x", "short": "abcd",
            "note": "n", "user": { "name": "u" }, "odd": "o", "extra": "e",
        });
        let attempt = |edit: ResultEdit| {
            let mut result = tool_result(structured.clone(), "x");
            let detect = detector();
            apply(&[edit], "r", &mut result, Some(&schema), Some(&*detect))
        };
        for fine in ["note", "user.name", "extra"] {
            assert_eq!(attempt(ResultEdit::Mask(fine.into())), Ok(true), "{fine}");
        }
        assert_eq!(attempt(ResultEdit::Remove("note".into())), Ok(true));
        for (edit, why) in [
            (
                ResultEdit::Mask("state".into()),
                "changing `structuredContent.state` would break the tool's outputSchema",
            ),
            (
                ResultEdit::Mask("email".into()),
                "changing `structuredContent.email` would break the tool's outputSchema",
            ),
            (
                ResultEdit::Mask("short".into()),
                "changing `structuredContent.short` would break the tool's outputSchema",
            ),
            (
                ResultEdit::Remove("id".into()),
                "removing `structuredContent.id` would break the tool's outputSchema",
            ),
            (
                ResultEdit::Mask("odd".into()),
                "the tool's outputSchema at `structuredContent.odd` is not one MCPdef can check",
            ),
        ] {
            assert_eq!(attempt(edit), Err(why.into()));
        }
    }

    #[test]
    fn a_union_is_followed_into_the_one_branch_that_could_hold_the_step() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": { "anyOf": [{ "$ref": "#/$defs/user" }, { "type": "null" }] },
                "either": { "oneOf": [{ "type": "object", "properties": {} }, { "type": "object" }] },
            },
            "$defs": { "user": { "type": "object", "properties": { "token": { "type": "string" } }, "required": ["token"] } },
        });
        let structured = json!({ "user": { "token": "t" }, "either": { "token": "t" } });
        let attempt = |edit: ResultEdit| {
            let mut result = tool_result(structured.clone(), "x");
            apply(&[edit], "r", &mut result, Some(&schema), None)
        };
        assert_eq!(attempt(ResultEdit::Mask("user.token".into())), Ok(true));
        assert_eq!(
            attempt(ResultEdit::Remove("user.token".into())),
            Err(
                "removing `structuredContent.user.token` would break the tool's outputSchema"
                    .into()
            )
        );
        assert_eq!(
            attempt(ResultEdit::Mask("either.token".into())),
            Err("the tool's outputSchema at `structuredContent.either.token` is not one MCPdef can check".into())
        );
    }

    #[test]
    fn a_redaction_the_schema_may_not_allow_refuses_the_result() {
        let schema = json!({ "type": "object", "properties": { "key": { "type": "string", "pattern": "^AKIA" } } });
        let detect = detector();
        let mut result = tool_result(json!({ "key": key() }), "x");
        assert_eq!(
            redact_result(&mut result, Some(&schema), &*detect),
            Err(Unredacted::Kept(
                "aws-access-key",
                "changing `structuredContent.key` would break the tool's outputSchema".into()
            ))
        );
    }

    #[test]
    fn a_prompts_base64_is_passed_over_and_a_secret_in_it_refuses() {
        let detect = detector();
        for held in [
            json!({ "type": "image", "data": key(), "mimeType": "image/png" }),
            json!({ "type": "resource", "resource": { "uri": "file:///k", "blob": key() } }),
        ] {
            let prompt = json!({ "messages": [{ "role": "user", "content": held }] });
            let mut out = prompt.clone();
            assert_eq!(
                redact_result(&mut out, None, &*detect),
                Err(Unredacted::Kept(
                    "aws-access-key",
                    "it is found in the result as a whole, outside the strings MCPdef redacts"
                        .into()
                ))
            );
            // As a tool result's: a redaction inside the base64 would break it.
            assert_eq!(out, prompt);
        }
        // A prompt's text is redacted.
        let mut text = json!({ "messages": [{ "role": "user",
            "content": { "type": "text", "text": format!("use {}", key()) } }] });
        assert_eq!(
            redact_result(&mut text, None, &*detect),
            Ok(vec!["aws-access-key"])
        );
        assert_eq!(
            text["messages"][0]["content"]["text"],
            "use [REDACTED:aws-access-key]"
        );
    }

    #[test]
    fn a_schema_that_is_no_schema_cannot_be_checked() {
        let why = "the tool's outputSchema at `structuredContent.a` is not one MCPdef can check";
        for schema in [json!("nonsense"), json!(7), json!([])] {
            for edit in [ResultEdit::Mask("a".into()), ResultEdit::Remove("a".into())] {
                let mut result = tool_result(json!({ "a": "x" }), "x");
                assert_eq!(
                    apply(&[edit], "r", &mut result, Some(&schema), None),
                    Err(why.into()),
                    "{schema}"
                );
            }
        }
    }

    #[test]
    fn a_masks_name_holds_nothing_that_could_end_a_string_by_hand() {
        assert_eq!(mask("a\"b\\c\nd"), "[REDACTED:abcd]");
    }

    #[test]
    fn a_secret_in_a_key_is_not_redacted_and_fails_the_redaction() {
        let detect = detector();
        let secret = key();
        let held = json!({ "users": { secret.clone(): { "name": "n" } } });
        for (result, root) in [
            (tool_result(held.clone(), "x"), "`structuredContent`"),
            (
                json!({ "content": [{ "type": "text", "text": held.to_string() }] }),
                "`content.0.text`",
            ),
            (
                json!({ "content": [], "_meta": held.clone() }),
                "the result",
            ),
        ] {
            let why = apply(
                &[ResultEdit::Redact],
                "r",
                &mut result.clone(),
                None,
                Some(&*detect),
            )
            .unwrap_err();
            assert_eq!(
                why,
                format!("a key in {root} holds a secret, and MCPdef does not redact a key")
            );
            assert_eq!(
                redact_result(&mut result.clone(), None, &*detect),
                Err(Unredacted::Kept("aws-access-key", why))
            );
        }
        // Strict, a key that holds what is no secret refuses as such; a
        // transform's redaction looks for secrets only, in keys as in strings.
        let injected = json!({ "content": [], "structuredContent": { "ignore all": 1 } });
        assert_eq!(
            redact_result(&mut injected.clone(), None, &*detect),
            Err(Unredacted::Unsafe("ignore-previous-instructions"))
        );
        assert_eq!(
            apply(
                &[ResultEdit::Redact],
                "r",
                &mut injected.clone(),
                None,
                Some(&*detect)
            ),
            Ok(false)
        );
    }

    #[test]
    fn redact_result_refuses_a_secret_where_redaction_does_not_reach() {
        let detect = detector();
        let image =
            json!({ "content": [{ "type": "image", "data": key(), "mimeType": "image/png" }] });
        // A transform passes the base64 of an image over...
        assert_eq!(
            apply(
                &[ResultEdit::Redact],
                "r",
                &mut image.clone(),
                None,
                Some(&*detect)
            ),
            Ok(false)
        );
        // ...and inspect's redaction refuses what it still finds there, as
        // `enforce` would.
        assert_eq!(
            redact_result(&mut image.clone(), None, &*detect),
            Err(Unredacted::Kept(
                "aws-access-key",
                "it is found in the result as a whole, outside the strings MCPdef redacts".into()
            ))
        );
    }

    #[test]
    fn a_reason_shows_a_key_the_result_holds_as_a_star_unless_the_schema_names_it() {
        let detect = detector();
        let email = "alice@example.com";
        // A key a `*` reached is data.
        let mut result = tool_result(json!({ "users": { email: { "pin": 1234 } } }), "x");
        let why = apply(
            &[ResultEdit::Mask("users.*.pin".into())],
            "r",
            &mut result,
            None,
            Some(&*detect),
        )
        .unwrap_err();
        assert_eq!(
            why,
            "`structuredContent.users.*.pin` is a number, not a string"
        );
        // So is every key a redaction walks, but one the schema names.
        let schema = json!({
            "type": "object",
            "properties": {
                "token": { "type": "string", "pattern": "^AKIA" },
                "by_user": {
                    "type": "object",
                    "additionalProperties": { "type": "string", "pattern": "^AKIA" },
                },
            },
        });
        for (structured, shown) in [
            (json!({ "token": key() }), "structuredContent.token"),
            (
                json!({ "by_user": { email: key() } }),
                "structuredContent.by_user.*",
            ),
        ] {
            let mut result = tool_result(structured, "x");
            let why = apply(
                &[ResultEdit::Redact],
                "r",
                &mut result,
                Some(&schema),
                Some(&*detect),
            )
            .unwrap_err();
            assert_eq!(
                why,
                format!("changing `{shown}` would break the tool's outputSchema")
            );
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Words, some of them a secret to the test detector, one of them no
        /// secret but what it finds, and some that a JSON string escapes.
        fn words() -> impl Strategy<Value = String> {
            let word = prop_oneof![
                Just(key()),
                Just("ignore all".to_string()),
                "[a-zA-Z0-9]{0,6}",
                Just("\"".to_string()),
                Just("\\".to_string()),
                Just("\n".to_string()),
                Just("é".to_string()),
            ];
            prop::collection::vec(word, 0..5).prop_map(|words| words.join(" "))
        }

        /// A key: now and then a secret.
        fn key_name() -> impl Strategy<Value = String> {
            prop_oneof![4 => "[a-c]", 1 => Just(key())]
        }

        /// A JSON value of such strings, and of numbers, booleans and null,
        /// under such keys.
        fn value() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                words().prop_map(Value::from),
                any::<i64>().prop_map(Value::from),
                any::<bool>().prop_map(Value::from),
                Just(Value::Null),
            ];
            leaf.prop_recursive(3, 24, 4, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
                    prop::collection::btree_map(key_name(), inner, 0..4)
                        .prop_map(|map| Value::Object(map.into_iter().collect())),
                ]
            })
        }

        /// A tool result: a structure, its mirror or not, and text blocks,
        /// some of them JSON.
        fn tool_result() -> impl Strategy<Value = Value> {
            let text = prop_oneof![words(), value().prop_map(|v| v.to_string())];
            (value(), any::<bool>(), prop::collection::vec(text, 0..3)).prop_map(
                |(structured, mirrored, texts)| {
                    let mut content: Vec<Value> = texts
                        .into_iter()
                        .map(|text| json!({ "type": "text", "text": text }))
                        .collect();
                    if mirrored {
                        content
                            .insert(0, json!({ "type": "text", "text": structured.to_string() }));
                    }
                    json!({ "content": content, "structuredContent": structured })
                },
            )
        }

        fn path() -> impl Strategy<Value = String> {
            prop::collection::vec(
                prop_oneof![Just("a"), Just("b"), Just("c"), Just("*")],
                1..4,
            )
            .prop_map(|steps| steps.join("."))
        }

        fn edit() -> impl Strategy<Value = ResultEdit> {
            prop_oneof![
                Just(ResultEdit::Redact),
                path().prop_map(ResultEdit::Mask),
                path()
                    .prop_filter("a removal ends in a key", |p| !p.ends_with('*'))
                    .prop_map(ResultEdit::Remove),
                (1usize..40).prop_map(ResultEdit::Truncate),
            ]
        }

        /// Every string in `value`, its keys among them, but under a JSON
        /// text, which `json_in` reads apart.
        fn strings(value: &Value, out: &mut Vec<String>) {
            match value {
                Value::String(text) => out.push(text.clone()),
                Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
                Value::Object(map) => map.iter().for_each(|(key, item)| {
                    out.push(key.clone());
                    strings(item, out);
                }),
                _ => {}
            }
        }

        /// Whether a key of `result`, or of the JSON a text block holds, is a
        /// secret.
        fn a_key_holds_one(result: &Value) -> bool {
            let mut all = Vec::new();
            strings(result, &mut all);
            let mut keys = Vec::new();
            let mut walk = |value: &Value| {
                let mut stack = vec![value.clone()];
                while let Some(value) = stack.pop() {
                    match value {
                        Value::Array(items) => stack.extend(items),
                        Value::Object(map) => {
                            keys.extend(map.keys().cloned());
                            stack.extend(map.into_iter().map(|(_, item)| item));
                        }
                        _ => {}
                    }
                }
            };
            walk(result);
            for text in &all {
                if let Some(held) = json_in(text) {
                    walk(&held);
                }
            }
            keys.contains(&key())
        }

        /// Whether the detector finds a secret, or, `strict`, anything, in a
        /// string or a key of `result`, or of the JSON a text block holds.
        fn finds(result: &Value, strict: bool) -> bool {
            let detect = detector();
            let mut all = Vec::new();
            strings(result, &mut all);
            for text in all.clone() {
                if let Some(held) = json_in(&text) {
                    strings(&held, &mut all);
                }
            }
            all.iter()
                .any(|text| detect(text).iter().any(|hit| strict || hit.secret))
        }

        proptest! {
            /// Whatever the result and the edits: what comes out is JSON, each
            /// mirror holds the structure, each block that held JSON holds it
            /// still unless a cut shortened it, and once a redaction ran no
            /// secret is left. An edit that cannot apply names no value.
            #[test]
            fn a_result_stays_json_and_its_mirror_agrees(
                result in tool_result(),
                edits in prop::collection::vec(edit(), 1..4),
            ) {
                let detect = detector();
                let mut out = result.clone();
                match apply(&edits, "r", &mut out, None, Some(&*detect)) {
                    Ok(changed) => {
                        prop_assert_eq!(changed, out != result);
                        let text = serde_json::to_string(&out).unwrap();
                        prop_assert_eq!(&serde_json::from_str::<Value>(&text).unwrap(), &out);
                        for block in mirrors(&result) {
                            let held: Value =
                                serde_json::from_str(block.text(&out).unwrap()).unwrap();
                            prop_assert_eq!(&held, &out["structuredContent"]);
                        }
                        if !edits.iter().any(|e| matches!(e, ResultEdit::Truncate(_))) {
                            for block in blocks(&result) {
                                if json_in(block.text(&result).unwrap()).is_some() {
                                    prop_assert!(json_in(block.text(&out).unwrap()).is_some());
                                }
                            }
                        }
                        if edits.contains(&ResultEdit::Redact) {
                            prop_assert!(!finds(&out, false), "{}", out);
                        }
                    }
                    Err(why) => prop_assert!(!why.contains("AKIA"), "{}", why),
                }
            }

            /// Redaction as inspect makes it: either nothing it finds is left,
            /// and the mirrors agree, or it found what is no secret, or a
            /// secret in a key.
            #[test]
            fn redaction_leaves_nothing_or_refuses(result in tool_result()) {
                let detect = detector();
                let mut out = result.clone();
                match redact_result(&mut out, None, &*detect) {
                    Ok(rules) => {
                        prop_assert!(!finds(&out, true), "{}", out);
                        prop_assert_eq!(rules.is_empty(), out == result);
                        for block in mirrors(&result) {
                            let held: Value =
                                serde_json::from_str(block.text(&out).unwrap()).unwrap();
                            prop_assert_eq!(&held, &out["structuredContent"]);
                        }
                    }
                    Err(Unredacted::Unsafe(rule)) => {
                        prop_assert_eq!(rule, "ignore-previous-instructions");
                        prop_assert!(finds(&result, true));
                    }
                    // A secret it cannot redact is one in a key, and the
                    // reason does not show it.
                    Err(Unredacted::Kept(rule, why)) => {
                        prop_assert_eq!(rule, "aws-access-key");
                        prop_assert!(a_key_holds_one(&result), "{}", result);
                        prop_assert!(!why.contains("AKIA"), "{}", why);
                    }
                }
            }
        }
    }
}
