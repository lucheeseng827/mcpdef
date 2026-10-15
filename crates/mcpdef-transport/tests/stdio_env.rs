// SPDX-License-Identifier: Apache-2.0
//! What a stdio child is given of MCPdef's environment: all of it, but for
//! the variables MCPdef reads secrets from, which it withholds.

use mcpdef_secrets::SecretString;
use mcpdef_transport::{StdioChild, Transport};

/// A child that answers at once with what it sees of three variables, then
/// waits to be closed.
fn reporter() -> Vec<String> {
    let script = r#"printf '{"jsonrpc":"2.0","id":1,"result":{"secret":"%s","plain":"%s","injected":"%s"}}\n' "${MCPDEF_TEST_SECRET-unset}" "${MCPDEF_TEST_PLAIN-unset}" "${MCPDEF_TEST_INJECTED-unset}"; read -r _"#;
    ["sh", "-c", script].map(String::from).to_vec()
}

/// What `child` saw, as `[secret, plain, injected]`.
async fn seen(mut child: StdioChild) -> [String; 3] {
    let report = child.recv().await.unwrap().expect("a report");
    let result = report.result.expect("a result");
    ["secret", "plain", "injected"].map(|k| result[k].as_str().unwrap_or_default().to_string())
}

/// The only test here: it sets variables of the process's environment.
#[tokio::test]
async fn a_withheld_variable_reaches_a_child_only_when_its_env_sets_it() {
    std::env::set_var("MCPDEF_TEST_SECRET", "s3cret");
    std::env::set_var("MCPDEF_TEST_PLAIN", "plain");
    let withheld = ["MCPDEF_TEST_SECRET".to_string()];
    let injected = [("MCPDEF_TEST_INJECTED".to_string(), "set".to_string())];

    // Without withholding, a child inherits everything.
    let child = StdioChild::spawn_with_env(&reporter(), &injected).unwrap();
    assert_eq!(seen(child).await, ["s3cret", "plain", "set"]);

    let injected = [(
        "MCPDEF_TEST_INJECTED".to_string(),
        SecretString::from("set"),
    )];
    let child = StdioChild::spawn_withholding(&reporter(), &injected, &withheld).unwrap();
    assert_eq!(seen(child).await, ["unset", "plain", "set"]);

    // A server's own env sets it all the same.
    let explicit = [(
        "MCPDEF_TEST_SECRET".to_string(),
        SecretString::from("given"),
    )];
    let child = StdioChild::spawn_withholding(&reporter(), &explicit, &withheld).unwrap();
    assert_eq!(seen(child).await, ["given", "plain", "unset"]);
}
