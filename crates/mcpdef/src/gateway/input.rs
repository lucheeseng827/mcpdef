//! Multi round-trip requests (2026-07-28, SEP-2322). A server that needs more
//! from the client before it can answer a `tools/call`, a `resources/read` or
//! a `prompts/get` (something from the user, a completion from the client's
//! model, the client's roots) answers with an `InputRequiredResult`. The
//! client then sends the request again, under a new id, with its
//! `inputResponses` and the `requestState` it was given.
//!
//! To a modern upstream, MCPdef declares the capabilities under which it may
//! ask, as the client declared them ([`wire::input_capabilities`]). It passes
//! the interim result back as it came, when the client can answer it, and
//! records it under [`INPUT_REQUIRED`]. The retry is a new request, routed and
//! governed as any other: it meets every gate itself.
use mcpdef_audit::Attrs;
use mcpdef_core::wire::{self, WireModel, SPEC_2026_07_28};
use mcpdef_core::Message;
use serde_json::Value;

/// The rule an interim result is recorded under: on an allowed record when it
/// was passed back, on a denied one when it was refused.
pub(super) const INPUT_REQUIRED: &str = "input-required";

/// What becomes of an upstream's answer.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Interim {
    /// A final answer, handled as ever.
    Final,
    /// An interim result the client can answer: passed back as it came.
    Relay,
    /// One it cannot, and why, to follow the name of what was asked for.
    Refuse(String),
}

/// Judge `resp`, the upstream's answer to a request sent in `era` by a client
/// that can be asked for `offered` ([`wire::input_capabilities`]).
///
/// A legacy client cannot read an interim result at all, not even one that
/// holds only `requestState`, so it is refused one.
pub(super) fn interim(resp: &Message, era: WireModel, offered: &Value) -> Interim {
    let Some(result) = resp.result.as_ref() else {
        return Interim::Final;
    };
    if !wire::input_required(result) {
        return Interim::Final;
    }
    if era != WireModel::Modern {
        return Interim::Refuse(format!(
            "asked for input, which MCPdef passes on only to a {SPEC_2026_07_28} client"
        ));
    }
    match wire::unanswerable_input(result, offered) {
        None => Interim::Relay,
        Some(why) => Interim::Refuse(format!("asked for input the client cannot give: {why}")),
    }
}

/// The record of an interim result passed back, beside `attrs`.
pub(super) fn relayed(attrs: Attrs) -> Attrs {
    Attrs {
        rule: Some(INPUT_REQUIRED.into()),
        ..attrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::Id;
    use serde_json::json;

    fn answer(result: Value) -> Message {
        Message::result(Id::Num(1), result)
    }

    #[test]
    fn a_final_answer_is_left_alone() {
        let offered = json!({ "elicitation": {} });
        for result in [
            json!({ "content": [] }),
            json!({ "resultType": "complete" }),
        ] {
            assert_eq!(
                interim(&answer(result), WireModel::Modern, &offered),
                Interim::Final
            );
        }
        let error = Message::error(Id::Num(1), -32000, "no");
        assert_eq!(interim(&error, WireModel::Modern, &offered), Interim::Final);
    }

    #[test]
    fn an_interim_result_goes_to_a_modern_client_that_can_answer_it() {
        let asks = answer(json!({
            "resultType": "input_required",
            "inputRequests": { "name": { "method": "elicitation/create", "params": { "message": "?" } } },
            "requestState": "s",
        }));
        assert_eq!(
            interim(&asks, WireModel::Modern, &json!({ "elicitation": {} })),
            Interim::Relay
        );
        assert_eq!(
            interim(&asks, WireModel::Modern, &json!({ "sampling": {} })),
            Interim::Refuse(
                "asked for input the client cannot give: its input request 'name' is \
                 `elicitation/create`, which the client did not declare it can answer"
                    .into()
            )
        );
    }

    #[test]
    fn a_legacy_client_is_refused_even_state_alone() {
        let retry = answer(json!({ "resultType": "input_required", "requestState": "s" }));
        assert_eq!(
            interim(&retry, WireModel::Modern, &json!({})),
            Interim::Relay
        );
        assert_eq!(
            interim(&retry, WireModel::Legacy, &json!({})),
            Interim::Refuse(
                "asked for input, which MCPdef passes on only to a 2026-07-28 client".into()
            )
        );
    }
}
