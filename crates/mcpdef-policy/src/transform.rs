// SPDX-License-Identifier: Apache-2.0
//! What a `transform` rule does to a tool call's arguments. What it does to
//! a result is [`crate::ResultEdit`]'s.
//!
//! Admission does not change: `allow` and `deny` rules still take the first
//! match. The `transform` rules are a pass of their own, before it: mutate,
//! then validate. Every one that matches applies, in config order, and each
//! matches the arguments as the rules before it left them, so admission and the
//! upstream both see what the pass made. The tool's name is not an argument,
//! and no rule can change it.
//!
//! An edit that cannot apply (a number to clamp that is a string, a path
//! through something other than an object) fails its rule: the call is denied
//! under the rule's name, unless the rule skips. What went wrong names types
//! and paths, never values.

use crate::result::ResultEdit;
use mcpdef_core::Decision;
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;

/// What a `transform` rule does to a call it matches: to its arguments, before
/// admission, and to its result, before inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    /// The edits of the arguments, in order, each made to what the one before
    /// it left.
    pub edits: Vec<ArgEdit>,
    /// The edits of the result, in order, likewise.
    pub result: Vec<ResultEdit>,
    /// What becomes of the call when an edit cannot apply.
    pub on_error: OnError,
}

/// One edit of the arguments, at a dotted `path` of object keys, as an
/// [`ArgMatch`](crate::ArgMatch) addresses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgEdit {
    pub path: String,
    pub op: EditOp,
}

/// What an [`ArgEdit`] does at its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOp {
    /// Put this value there, whatever is there already. The objects on the
    /// way are made where they are missing.
    Set(Value),
    /// Put this value there when nothing is: the path is absent, or holds
    /// null, as [`ArgOp::Exists`](crate::ArgOp::Exists) sees it.
    Default(Value),
    /// Take the path out, if it is there.
    Remove,
    /// Hold the number there within these bounds: one below `min` becomes
    /// `min`, and one above `max` becomes `max`, as the rule writes them. A
    /// path that holds nothing is left so.
    Clamp {
        min: Option<Number>,
        max: Option<Number>,
    },
}

/// What becomes of a call when one of a rule's edits cannot apply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnError {
    /// It is denied under the rule's name: the arguments are not the shape
    /// the rule was written for, and they are not sent on as they are.
    #[default]
    Deny,
    /// The rule is skipped: the call keeps the arguments the rules before it
    /// left, and goes on.
    Skip,
}

/// What the `transform` rules did to one call's arguments, or to its result.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Transformed {
    /// The rules that fired, by name, in order: each matched the call and
    /// applied, whether or not it changed a value.
    pub fired: Vec<String>,
    /// Whether the arguments, or the result, changed.
    pub changed: bool,
    /// The rules that could not apply and were skipped, each with why.
    pub skipped: Vec<(String, String)>,
    /// The denial, when a rule that denies could not apply. The rules after
    /// it did not run.
    pub refused: Option<Decision>,
}

impl Transform {
    /// Make every edit to `args`, in order: whether any changed them, or why
    /// one cannot apply. Absent arguments (null) are an empty object to an
    /// edit that adds a value.
    pub(crate) fn apply(&self, args: &mut Value) -> Result<bool, String> {
        let mut changed = false;
        for edit in &self.edits {
            changed |= edit.apply(args)?;
        }
        Ok(changed)
    }
}

impl ArgEdit {
    fn apply(&self, args: &mut Value) -> Result<bool, String> {
        let keys: Vec<&str> = self.path.split('.').collect();
        let Some((last, on_the_way)) = keys.split_last() else {
            return Ok(false);
        };
        match &self.op {
            EditOp::Set(value) => {
                let Some(object) = holder(args, on_the_way, true)? else {
                    return Ok(false);
                };
                let changed = object.get(*last) != Some(value);
                object.insert((*last).to_string(), value.clone());
                Ok(changed)
            }
            EditOp::Default(value) => {
                let Some(object) = holder(args, on_the_way, true)? else {
                    return Ok(false);
                };
                if object.get(*last).is_none_or(Value::is_null) {
                    object.insert((*last).to_string(), value.clone());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            EditOp::Remove => match holder(args, on_the_way, false)? {
                Some(object) => Ok(object.remove(*last).is_some()),
                None => Ok(false),
            },
            EditOp::Clamp { min, max } => {
                let Some(object) = holder(args, on_the_way, false)? else {
                    return Ok(false);
                };
                match object.get_mut(*last) {
                    None | Some(Value::Null) => Ok(false),
                    Some(Value::Number(n)) => Ok(clamp(n, min.as_ref(), max.as_ref())),
                    Some(other) => Err(format!("`{}` is {}, not a number", self.path, kind(other))),
                }
            }
        }
    }
}

/// The object that holds a path's last key, reached through `keys`. Where
/// one of them holds nothing, it is made an empty object when `make`, and
/// otherwise there is no holder. A step through anything but an object
/// cannot apply.
fn holder<'v>(
    args: &'v mut Value,
    keys: &[&str],
    make: bool,
) -> Result<Option<&'v mut Map<String, Value>>, String> {
    if args.is_null() {
        if !make {
            return Ok(None);
        }
        *args = Value::Object(Map::new());
    }
    let mut object = match args {
        Value::Object(object) => object,
        other => return Err(format!("the arguments are {}, not an object", kind(other))),
    };
    for (at, key) in keys.iter().enumerate() {
        if object.get(*key).is_none_or(Value::is_null) {
            if !make {
                return Ok(None);
            }
            object.insert((*key).to_string(), Value::Object(Map::new()));
        }
        object = match object.get_mut(*key) {
            Some(Value::Object(inner)) => inner,
            Some(other) => {
                return Err(format!(
                    "`{}` is {}, not an object",
                    keys[..=at].join("."),
                    kind(other)
                ))
            }
            None => return Ok(None),
        };
    }
    Ok(Some(object))
}

/// Bring `n` within `min` and `max`: whether it moved.
fn clamp(n: &mut Number, min: Option<&Number>, max: Option<&Number>) -> bool {
    if let Some(min) = min {
        if compare(n, min) == Ordering::Less {
            *n = min.clone();
            return true;
        }
    }
    if let Some(max) = max {
        if compare(n, max) == Ordering::Greater {
            *n = max.clone();
            return true;
        }
    }
    false
}

/// How two JSON numbers compare: exactly when both are integers, and as
/// `f64` otherwise. A JSON number is never NaN.
fn compare(a: &Number, b: &Number) -> Ordering {
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => a
            .as_f64()
            .zip(b.as_f64())
            .and_then(|(a, b)| a.partial_cmp(&b))
            .unwrap_or(Ordering::Equal),
    }
}

fn integer(n: &Number) -> Option<i128> {
    n.as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from))
}

/// What a value is, for a reason that must not say what it holds.
pub(crate) fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn edit(path: &str, op: EditOp) -> Transform {
        Transform {
            edits: vec![ArgEdit {
                path: path.into(),
                op,
            }],
            result: Vec::new(),
            on_error: OnError::Deny,
        }
    }

    fn clamp_to(min: Option<Value>, max: Option<Value>) -> EditOp {
        let number = |v: Value| match v {
            Value::Number(n) => n,
            other => panic!("{other} is not a number"),
        };
        EditOp::Clamp {
            min: min.map(number),
            max: max.map(number),
        }
    }

    /// `args` after `transform`, and whether it said they changed.
    fn after(transform: &Transform, mut args: Value) -> (Value, bool) {
        let changed = transform.apply(&mut args).unwrap();
        (args, changed)
    }

    #[test]
    fn set_puts_a_value_there_and_makes_the_objects_on_the_way() {
        let set = edit("target.env", EditOp::Set(json!("staging")));
        assert_eq!(
            after(&set, json!({ "target": { "env": "prod" }, "n": 1 })),
            (json!({ "target": { "env": "staging" }, "n": 1 }), true)
        );
        assert_eq!(
            after(&set, json!({ "n": 1 })),
            (json!({ "target": { "env": "staging" }, "n": 1 }), true)
        );
        // Absent arguments, or null ones, are an empty object to it.
        assert_eq!(
            after(&set, Value::Null),
            (json!({ "target": { "env": "staging" } }), true)
        );
        assert_eq!(
            after(&set, json!({ "target": null })),
            (json!({ "target": { "env": "staging" } }), true)
        );
        // The value it sets already there: nothing changed.
        assert_eq!(
            after(&set, json!({ "target": { "env": "staging" } })),
            (json!({ "target": { "env": "staging" } }), false)
        );
    }

    #[test]
    fn default_fills_in_only_what_holds_nothing() {
        let default = edit("limit", EditOp::Default(json!(50)));
        assert_eq!(after(&default, json!({})), (json!({ "limit": 50 }), true));
        assert_eq!(
            after(&default, json!({ "limit": null })),
            (json!({ "limit": 50 }), true)
        );
        for held in [json!(0), json!(false), json!(""), json!(500), json!([])] {
            let args = json!({ "limit": held });
            assert_eq!(after(&default, args.clone()), (args, false));
        }
    }

    #[test]
    fn remove_takes_a_path_out_if_it_is_there() {
        let remove = edit("auth.token", EditOp::Remove);
        assert_eq!(
            after(&remove, json!({ "auth": { "token": "t", "user": "u" } })),
            (json!({ "auth": { "user": "u" } }), true)
        );
        for args in [
            json!({ "auth": {} }),
            json!({}),
            json!({ "auth": null }),
            Value::Null,
        ] {
            assert_eq!(after(&remove, args.clone()), (args, false));
        }
    }

    #[test]
    fn clamp_holds_a_number_within_its_bounds() {
        let clamp = edit("per_page", clamp_to(Some(json!(1)), Some(json!(100))));
        for (sent, kept, changed) in [
            (json!(500), json!(100), true),
            (json!(0), json!(1), true),
            (json!(-7), json!(1), true),
            (json!(50), json!(50), false),
            (json!(100), json!(100), false),
            (json!(1), json!(1), false),
            // A bound is written as the rule writes it: an integer here.
            (json!(150.5), json!(100), true),
            (json!(99.5), json!(99.5), false),
        ] {
            assert_eq!(
                after(&clamp, json!({ "per_page": sent.clone() })),
                (json!({ "per_page": kept }), changed),
                "{sent}"
            );
        }
        // A bound written with a fraction is kept with it.
        let clamp = edit("ratio", clamp_to(None, Some(json!(0.5))));
        assert_eq!(
            after(&clamp, json!({ "ratio": 3 })),
            (json!({ "ratio": 0.5 }), true)
        );
        // Nothing there, nothing to clamp.
        let clamp = edit("per_page", clamp_to(None, Some(json!(100))));
        for args in [json!({}), json!({ "per_page": null }), Value::Null] {
            assert_eq!(after(&clamp, args.clone()), (args, false));
        }
    }

    #[test]
    fn clamp_compares_integers_exactly() {
        // As f64 the two are one number; as integers the value is above.
        let clamp = edit("n", clamp_to(None, Some(json!(9_007_199_254_740_992_i64))));
        assert_eq!(
            after(&clamp, json!({ "n": 9_007_199_254_740_993_i64 })),
            (json!({ "n": 9_007_199_254_740_992_i64 }), true)
        );
        let clamp = edit("n", clamp_to(Some(json!(0)), None));
        assert_eq!(
            after(&clamp, json!({ "n": u64::MAX })),
            (json!({ "n": u64::MAX }), false)
        );
        assert_eq!(
            after(&clamp, json!({ "n": i64::MIN })),
            (json!({ "n": 0 }), true)
        );
    }

    #[test]
    fn an_edit_that_cannot_apply_says_why_by_type_and_path() {
        let cases = [
            (
                edit("per_page", clamp_to(None, Some(json!(100)))),
                json!({ "per_page": "500" }),
                "`per_page` is a string, not a number",
            ),
            (
                edit("target.env", EditOp::Set(json!("staging"))),
                json!({ "target": "prod-db" }),
                "`target` is a string, not an object",
            ),
            (
                edit("a.b.c", EditOp::Remove),
                json!({ "a": { "b": [1, 2] } }),
                "`a.b` is an array, not an object",
            ),
            (
                edit("a", EditOp::Default(json!(1))),
                json!(["a"]),
                "the arguments are an array, not an object",
            ),
            (
                edit("flag", clamp_to(Some(json!(0)), None)),
                json!({ "flag": true }),
                "`flag` is a boolean, not a number",
            ),
        ];
        for (transform, mut args, why) in cases {
            assert_eq!(transform.apply(&mut args), Err(why.to_string()));
        }
    }

    #[test]
    fn why_never_holds_a_value() {
        let secret = "s3cret-value-9f3a";
        let cases = [
            (
                edit("token", clamp_to(None, Some(json!(1)))),
                json!({ "token": secret }),
            ),
            (
                edit("token.inner", EditOp::Set(json!(1))),
                json!({ "token": secret }),
            ),
            (edit("x", EditOp::Remove), json!(secret)),
        ];
        for (transform, mut args) in cases {
            let why = transform.apply(&mut args).unwrap_err();
            assert!(!why.contains(secret), "{why}");
        }
    }

    #[test]
    fn edits_apply_in_order_each_to_what_the_last_left() {
        let transform = Transform {
            edits: vec![
                ArgEdit {
                    path: "limit".into(),
                    op: EditOp::Default(json!(500)),
                },
                ArgEdit {
                    path: "limit".into(),
                    op: clamp_to(None, Some(json!(100))),
                },
                ArgEdit {
                    path: "debug".into(),
                    op: EditOp::Remove,
                },
            ],
            result: Vec::new(),
            on_error: OnError::Deny,
        };
        assert_eq!(
            after(&transform, json!({ "debug": true })),
            (json!({ "limit": 100 }), true)
        );
    }

    use proptest::prelude::*;

    /// A JSON value of up to three levels, over the keys `a`, `b` and `c`,
    /// whose strings all begin `v-`, so a reason that holds one shows.
    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            (-1e6f64..1e6).prop_map(Value::from),
            "[a-z]{0,6}".prop_map(|s| Value::String(format!("v-{s}"))),
        ];
        leaf.prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
                prop::collection::btree_map(prop::sample::select(vec!["a", "b", "c"]), inner, 0..3)
                    .prop_map(|m| Value::Object(
                        m.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
                    )),
            ]
        })
    }

    fn path() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 1..4)
            .prop_map(|keys| keys.join("."))
    }

    fn op() -> impl Strategy<Value = EditOp> {
        let bound = prop_oneof![
            any::<i32>().prop_map(Number::from),
            (-1e3f64..1e3).prop_map(|f| Number::from_f64(f).unwrap()),
        ];
        prop_oneof![
            value().prop_map(EditOp::Set),
            value().prop_map(EditOp::Default),
            Just(EditOp::Remove),
            (prop::option::of(bound.clone()), prop::option::of(bound)).prop_map(|(min, max)| {
                // A config never has `min` above `max`.
                match (min, max) {
                    (Some(lo), Some(hi)) if compare(&lo, &hi) == Ordering::Greater => {
                        EditOp::Clamp {
                            min: Some(hi),
                            max: Some(lo),
                        }
                    }
                    (min, max) => EditOp::Clamp { min, max },
                }
            }),
        ]
    }

    /// What is at `path` in `args`, if anything.
    fn at<'a>(args: &'a Value, path: &str) -> Option<&'a Value> {
        path.split('.').try_fold(args, |v, key| v.get(key))
    }

    proptest! {
        /// Whatever the arguments, an edit either holds afterwards or fails
        /// with a reason that names no value; `changed` says whether they
        /// changed; and a skipping rule that fails leaves them as they were.
        #[test]
        fn an_edit_holds_or_fails_without_a_value(args in value(), path in path(), op in op()) {
            let transform = Transform {
                edits: vec![ArgEdit { path: path.clone(), op: op.clone() }],
                result: Vec::new(),
                on_error: OnError::Skip,
            };
            let mut edited = args.clone();
            match transform.apply(&mut edited) {
                Ok(changed) => {
                    prop_assert_eq!(changed, edited != args);
                    match &op {
                        EditOp::Set(v) => prop_assert_eq!(at(&edited, &path), Some(v)),
                        EditOp::Default(v) => {
                            let before = at(&args, &path).filter(|b| !b.is_null());
                            prop_assert_eq!(at(&edited, &path), Some(before.unwrap_or(v)));
                        }
                        EditOp::Remove => prop_assert_eq!(at(&edited, &path), None),
                        EditOp::Clamp { min, max } => {
                            if let Some(Value::Number(n)) = at(&edited, &path) {
                                if let Some(min) = min {
                                    prop_assert!(compare(n, min) != Ordering::Less);
                                }
                                if let Some(max) = max {
                                    prop_assert!(compare(n, max) != Ordering::Greater);
                                }
                            } else {
                                prop_assert_eq!(&edited, &args);
                            }
                        }
                    }
                }
                Err(why) => {
                    prop_assert!(!why.contains("v-"), "{}", why);
                    // Through the pass, a rule that skips keeps nothing.
                    let rules = crate::PolicyRules::new(vec![crate::Rule {
                        name: "r".into(),
                        effect: crate::Effect::Transform(transform.clone()),
                        agents: None,
                        servers: None,
                        tools: None,
                        uris: None,
                        prompts: None,
                        args: vec![],
                    }]);
                    let mut kept = args.clone();
                    let done = rules.transform("a", "s", "t", &mut kept);
                    prop_assert_eq!(&kept, &args);
                    prop_assert!(done.fired.is_empty() && done.skipped.len() == 1);
                }
            }
        }
    }
}
