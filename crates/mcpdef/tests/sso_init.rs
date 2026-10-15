// SPDX-License-Identifier: Apache-2.0
//! `mcpdef sso init`, through the real binary:
//!   * a golden file per provider: what to set at the provider, and the
//!     config;
//!   * what it prints is a config, comments and all, that `mcpdef validate`
//!     takes once a server is added;
//!   * `--write` merges it into a config file, keeping what the file held,
//!     comments included, and a `.bak` of it; it refuses, writing nothing,
//!     where a sign-in is configured already, where the config's own
//!     `public_url` or `[identity]` say otherwise, and without an issuer or
//!     a console URL.

use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const PROVIDERS: [&str; 7] = [
    "keycloak",
    "entra",
    "okta",
    "google",
    "authentik",
    "generic",
    "saml-broker",
];
const PUBLIC_URL: &str = "https://mcpdef.example.com:7879";
const SERVER: &str = "\n[[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n";

fn mcpdef(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Compare with the golden file, or write it when blessing (`.golden`: the
/// repository ignores `*.txt`).
fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/sso")
        .join(format!("{name}.golden"));
    if std::env::var_os("MCPDEF_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("no golden file {}: run with MCPDEF_BLESS=1", path.display()));
    assert_eq!(
        actual,
        expected,
        "`mcpdef sso init --provider {name}` no longer prints {}",
        path.display()
    );
}

#[test]
fn each_provider_prints_its_steps_and_a_config_validate_takes() {
    let dir = tempfile::tempdir().unwrap();
    for provider in PROVIDERS {
        let out = mcpdef(&[
            "sso",
            "init",
            "--provider",
            provider,
            "--public-url",
            PUBLIC_URL,
            "--config",
            "/nonexistent/mcpdef.toml",
        ]);
        assert!(out.status.success(), "{provider}: {}", said(&out));
        let printed = String::from_utf8(out.stdout).unwrap();
        golden(provider, &printed);
        assert!(
            printed.lines().all(|l| l.chars().count() <= 100),
            "{provider}: a line over 100 columns"
        );
        // All of it is TOML, its prose in comments: with a server, a config.
        let config = dir.path().join(format!("{provider}.toml"));
        std::fs::write(&config, format!("{printed}{SERVER}")).unwrap();
        let checked = mcpdef(&["validate", "--config", config.to_str().unwrap()]);
        assert!(checked.status.success(), "{provider}: {}", said(&checked));
    }
    let unknown = mcpdef(&[
        "sso",
        "init",
        "--provider",
        "azure",
        "--config",
        "/nonexistent",
    ]);
    assert!(!unknown.status.success());
    assert!(
        said(&unknown).contains("no provider \"azure\": name one of keycloak, entra, okta"),
        "{}",
        said(&unknown)
    );
}

/// A config with an admin listener, a certificate map and comments.
const BEFORE: &str = "# The gateway.\n[gateway]\nlisten = \"127.0.0.1:7878\"\n\n\
                      [gateway.admin]\nenabled = true # the console\n\n\
                      [[identity.cert_map]]\nidentity = \"spiffe://example.org/ops\"\nroles = [\"console:admin\"]\n\
                      \n[[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n";

#[test]
fn write_merges_into_the_config_and_keeps_what_it_held() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    std::fs::write(&config, BEFORE).unwrap();
    let write = |args: &[&str]| {
        let mut all = vec![
            "sso",
            "init",
            "--write",
            "--config",
            config.to_str().unwrap(),
        ];
        all.extend_from_slice(args);
        mcpdef(&all)
    };

    // Without an issuer, or a console URL: nothing written.
    let out = write(&["--provider", "okta", "--public-url", PUBLIC_URL]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("--write needs --issuer"),
        "{}",
        said(&out)
    );
    let out = write(&[
        "--provider",
        "okta",
        "--issuer",
        "https://acme.okta.com/oauth2/default",
    ]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("--write needs the console's URL"),
        "{}",
        said(&out)
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), BEFORE);
    assert!(!dir.path().join("mcpdef.toml.bak").exists());

    // Merged: the comments, the listener and the certificate map kept.
    let out = write(&[
        "--provider",
        "okta",
        "--issuer",
        "https://acme.okta.com/oauth2/default",
        "--public-url",
        PUBLIC_URL,
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("1. Applications > Create App Integration"),
        "{}",
        said(&out)
    );
    let after = std::fs::read_to_string(&config).unwrap();
    for kept in [
        "# The gateway.",
        "enabled = true # the console",
        "identity = \"spiffe://example.org/ops\"",
    ] {
        assert!(after.contains(kept), "{kept:?} lost:\n{after}");
    }
    for added in [
        "public_url = \"https://mcpdef.example.com:7879\"",
        "issuer = \"https://acme.okta.com/oauth2/default\"",
        "client_secret = { env = \"MCPDEF_OIDC_CLIENT_SECRET\" }",
        "subject_claim = \"preferred_username\"",
        "value = \"mcpdef-admins\"",
    ] {
        assert!(after.contains(added), "{added:?} not written:\n{after}");
    }
    // The file as it was, in place, its one new key aside; what is added
    // comes after it.
    assert!(
        after
            .replace("public_url = \"https://mcpdef.example.com:7879\"\n", "")
            .starts_with(BEFORE),
        "{after}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("mcpdef.toml.bak")).unwrap(),
        BEFORE
    );
    let checked = mcpdef(&["validate", "--config", config.to_str().unwrap()]);
    assert!(checked.status.success(), "{}\n{after}", said(&checked));

    // Again: a sign-in is configured already, and the file is left as it is.
    let out = write(&[
        "--provider",
        "keycloak",
        "--issuer",
        "https://kc.example/realms/ops",
    ]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("has [gateway.admin.oidc] already"),
        "{}",
        said(&out)
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), after);
}

#[test]
fn write_refuses_what_the_config_says_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    let cases = [
        (
            "[gateway.admin]\npublic_url = \"https://console.acme.internal\"\n",
            "public_url is \"https://console.acme.internal\", and --public-url",
        ),
        (
            "[identity]\nsubject_claim = \"email\"\n",
            "[identity] subject_claim is \"email\", and Keycloak reads it from \"preferred_username\"",
        ),
    ];
    let issuer = "https://kc.example/realms/ops";
    for (set, refusal, issuer) in cases
        .into_iter()
        .map(|(set, refusal)| (set, refusal, issuer))
        .chain([(
            "",
            "the config, merged, would be refused, so it is left as it is",
            "http://kc.example/realms/ops",
        )])
    {
        let text = format!("{set}{SERVER}");
        std::fs::write(&config, &text).unwrap();
        let out = mcpdef(&[
            "sso",
            "init",
            "--write",
            "--config",
            config.to_str().unwrap(),
            "--provider",
            "keycloak",
            "--issuer",
            issuer,
            "--public-url",
            PUBLIC_URL,
        ]);
        assert!(!out.status.success(), "{set}");
        assert!(said(&out).contains(refusal), "{set}: {}", said(&out));
        assert_eq!(std::fs::read_to_string(&config).unwrap(), text);
    }
}

#[test]
fn write_leaves_how_the_mcp_listener_reads_its_callers() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    // [gateway.auth] takes the agents' tokens, read by [identity]'s defaults:
    // their subject from `sub`, their roles from `roles`.
    let text = format!(
        "[gateway.auth]\nenabled = true\nissuer = \"https://kc.example/realms/ops\"\n\
         resource = \"https://mcp.example.com/mcp\"\n\
         jwks_uri = \"https://kc.example/realms/ops/protocol/openid-connect/certs\"\n{SERVER}"
    );
    let write = |provider: &str| {
        std::fs::write(&config, &text).unwrap();
        mcpdef(&[
            "sso",
            "init",
            "--write",
            "--config",
            config.to_str().unwrap(),
            "--provider",
            provider,
            "--issuer",
            "https://kc.example/realms/ops",
            "--public-url",
            PUBLIC_URL,
        ])
    };

    // Keycloak's [identity] reads other claims: refused, nothing written.
    let out = write("keycloak");
    assert!(!out.status.success());
    for said_so in [
        "[gateway.auth] reads its callers' tokens by [identity] too, and Keycloak's [identity] \
         would change it: subject_claim \"sub\" → \"preferred_username\", roles_claims [\"roles\"] → ",
        "set [identity] by hand, to claims both listeners can read",
    ] {
        assert!(said(&out).contains(said_so), "{}", said(&out));
    }
    assert_eq!(std::fs::read_to_string(&config).unwrap(), text);

    // A provider whose claims are the ones read now: written.
    let out = write("generic");
    assert!(out.status.success(), "{}", said(&out));
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains("[gateway.admin.oidc]"), "{written}");
    assert!(!written.contains("subject_claim"), "{written}");
    let checked = mcpdef(&["validate", "--config", config.to_str().unwrap()]);
    assert!(checked.status.success(), "{}", said(&checked));
}
