// SPDX-License-Identifier: Apache-2.0
//! `mcpdef sso init --provider <name>`: the config that signs people in to
//! the console at an identity provider, and what to set at the provider, for
//! each provider whose tokens MCPdef knows: the redirect URIs, the scopes,
//! and which claim carries roles or groups.
//!
//! What it prints is TOML, its prose in comments, so it can be read, or
//! appended to a config as it is. `--write` merges it into the config file
//! instead: everything else the file holds is kept, comments included, a
//! `.bak` holds the file as it was, and nothing is written that `mcpdef
//! validate` would refuse, nor over a sign-in already configured.

use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// The providers `sso init` writes a config for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Keycloak,
    Entra,
    Okta,
    Google,
    Authentik,
    Generic,
    /// A SAML identity provider, through a broker that speaks OpenID Connect
    /// to MCPdef: Keycloak, as written here.
    SamlBroker,
}

/// The variable the client's secret is read from.
pub const SECRET_VAR: &str = "MCPDEF_OIDC_CLIENT_SECRET";

impl Provider {
    pub const ALL: [Provider; 7] = [
        Provider::Keycloak,
        Provider::Entra,
        Provider::Okta,
        Provider::Google,
        Provider::Authentik,
        Provider::Generic,
        Provider::SamlBroker,
    ];

    /// As `--provider` names it.
    pub fn name(self) -> &'static str {
        match self {
            Provider::Keycloak => "keycloak",
            Provider::Entra => "entra",
            Provider::Okta => "okta",
            Provider::Google => "google",
            Provider::Authentik => "authentik",
            Provider::Generic => "generic",
            Provider::SamlBroker => "saml-broker",
        }
    }

    /// The provider `name` is, if it is one.
    pub fn parse(name: &str) -> Option<Provider> {
        Provider::ALL.into_iter().find(|p| p.name() == name)
    }

    fn title(self) -> &'static str {
        match self {
            Provider::Keycloak => "Keycloak",
            Provider::Entra => "Microsoft Entra ID",
            Provider::Okta => "Okta",
            Provider::Google => "Google",
            Provider::Authentik => "authentik",
            Provider::Generic => "an OpenID Connect provider",
            Provider::SamlBroker => "a SAML identity provider, through Keycloak as its broker",
        }
    }

    /// An issuer of the provider's, shown when none is given.
    pub fn example_issuer(self) -> &'static str {
        match self {
            Provider::Keycloak | Provider::SamlBroker => "https://keycloak.example.com/realms/ops",
            Provider::Entra => {
                "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
            }
            Provider::Okta => "https://example.okta.com/oauth2/default",
            Provider::Google => "https://accounts.google.com",
            Provider::Authentik => "https://authentik.example.com/application/o/mcpdef/",
            Provider::Generic => "https://idp.example.com",
        }
    }
}

/// What `sso init` is given.
pub struct Init {
    pub provider: Provider,
    pub issuer: Option<String>,
    pub client_id: String,
    /// The console's origin: `--public-url`, else the config's.
    pub public_url: Option<String>,
}

/// How a provider's ID tokens name someone and give their roles.
struct Identity {
    /// `None`: `sub`, the default.
    subject_claim: Option<&'static str>,
    roles_claims: Vec<String>,
    /// A claim, the value it holds, and the console role it gives.
    role_map: Vec<(&'static str, &'static str, &'static str)>,
    scopes: &'static [&'static str],
}

/// The groups `role_map` maps, one per console role.
const GROUPS: [(&str, &str); 3] = [
    ("mcpdef-viewers", "console:viewer"),
    ("mcpdef-operators", "console:operator"),
    ("mcpdef-admins", "console:admin"),
];

fn groups(claim: &'static str) -> Vec<(&'static str, &'static str, &'static str)> {
    GROUPS
        .iter()
        .map(|(group, role)| (claim, *group, *role))
        .collect()
}

impl Init {
    fn issuer(&self) -> &str {
        self.issuer
            .as_deref()
            .unwrap_or(self.provider.example_issuer())
    }

    fn public_url(&self) -> &str {
        self.public_url
            .as_deref()
            .unwrap_or("https://mcpdef.example.com:7879")
            .trim_end_matches('/')
    }

    fn identity(&self) -> Identity {
        match self.provider {
            Provider::Keycloak => Identity {
                subject_claim: Some("preferred_username"),
                roles_claims: vec![format!("resource_access.{}.roles", self.client_id)],
                role_map: vec![],
                scopes: &["profile", "email"],
            },
            Provider::Entra => Identity {
                subject_claim: Some("oid"),
                roles_claims: vec![],
                role_map: vec![
                    ("roles", "MCPdef.Viewer", "console:viewer"),
                    ("roles", "MCPdef.Operator", "console:operator"),
                    ("roles", "MCPdef.Admin", "console:admin"),
                ],
                scopes: &["profile", "email"],
            },
            Provider::Okta => Identity {
                subject_claim: Some("preferred_username"),
                roles_claims: vec![],
                role_map: groups("groups"),
                scopes: &["profile", "email", "groups"],
            },
            Provider::Google => Identity {
                subject_claim: Some("email"),
                roles_claims: vec![],
                role_map: vec![("hd", "example.com", "console:viewer")],
                scopes: &["profile", "email"],
            },
            Provider::Authentik | Provider::SamlBroker => Identity {
                subject_claim: Some("preferred_username"),
                roles_claims: vec![],
                role_map: groups("groups"),
                scopes: &["profile", "email"],
            },
            Provider::Generic => Identity {
                subject_claim: None,
                roles_claims: vec!["roles".to_string()],
                role_map: groups("groups"),
                scopes: &["profile", "email"],
            },
        }
    }

    /// What to set at the provider, in order.
    pub fn steps(&self) -> Vec<String> {
        let redirect = format!("{}/callback", self.public_url());
        let logout = format!("{}/", self.public_url());
        let client = &self.client_id;
        let secret = format!("its secret goes in {SECRET_VAR}, where MCPdef runs");
        let groups = "groups mcpdef-viewers, mcpdef-operators and mcpdef-admins, each giving \
                      the console role role_map says";
        match self.provider {
            Provider::Keycloak => vec![
                format!(
                    "Clients > Create client: OpenID Connect, client ID {client}, client \
                     authentication on, the standard flow alone; {secret}."
                ),
                format!(
                    "Valid redirect URIs: {redirect}. Valid post logout redirect URIs: {logout}."
                ),
                "The client's roles: console:viewer, console:operator and console:admin, \
                 given to groups or people."
                    .to_string(),
                format!(
                    "The client's dedicated scope > Add mapper > By configuration > User Client \
                     Role: client ID {client}, token claim name resource_access.{client}.roles, \
                     multivalued on, add to ID token on (Keycloak puts client roles in the \
                     access token alone, by default)."
                ),
            ],
            Provider::Entra => vec![
                format!(
                    "App registrations > New registration: a Web redirect URI, {redirect}, and \
                     {logout} beside it, for signing out. Its Application (client) ID is \
                     client_id, and its Directory (tenant) ID is in the issuer."
                ),
                format!("Certificates & secrets > New client secret: {secret}."),
                "App roles: MCPdef.Viewer, MCPdef.Operator and MCPdef.Admin, for users and \
                 groups, which role_map gives their console roles."
                    .to_string(),
                "Enterprise applications > the app > Users and groups: assign people, or \
                 groups, to the roles."
                    .to_string(),
            ],
            Provider::Okta => vec![
                format!(
                    "Applications > Create App Integration: OIDC, Web Application, the \
                     authorization code grant; sign-in redirect URI {redirect}, sign-out \
                     redirect URI {logout}; {secret}."
                ),
                "Security > API > Authorization Servers > default > Claims: groups, in the ID \
                 token, with the groups scope, its value the groups whose names start with \
                 mcpdef-."
                    .to_string(),
                format!("Directory > Groups: the {groups}; assign them to the app."),
            ],
            Provider::Google => vec![
                format!(
                    "Google Cloud console > APIs & Services > Credentials > Create OAuth client \
                     ID: a Web application, its authorized redirect URI {redirect}; {secret}."
                ),
                "OAuth consent screen: Internal, so that only your Workspace's people sign in."
                    .to_string(),
                "Google's ID tokens carry no groups: hd, the Workspace domain (set yours \
                 below), gives console:viewer. Operators and admins sign in by a client \
                 certificate, or through a broker that reads Google's groups (saml-broker's \
                 Keycloak)."
                    .to_string(),
                "Google has no end-session endpoint: signing out ends the console's session \
                 alone."
                    .to_string(),
            ],
            Provider::Authentik => vec![
                format!(
                    "Applications > Providers > Create: OAuth2/OpenID Provider, a confidential \
                     client, redirect URI {redirect}, a signing key (RS256, never none); \
                     {secret}."
                ),
                "Applications > Create: one named mcpdef, with that provider: its slug is in \
                 the issuer, which ends in a slash."
                    .to_string(),
                format!("Directory > Groups: the {groups}; bind them to the application."),
            ],
            Provider::Generic => vec![
                format!(
                    "Register a confidential client, client ID {client}, for the authorization \
                     code flow with PKCE (S256); {secret}."
                ),
                format!("Its redirect URI: {redirect}; its post-logout redirect URI: {logout}."),
                "ID tokens signed with RS256, RS384, RS512, PS256, ES256 or ES384, carrying the \
                 person's roles in a roles claim, or their groups in a groups claim (add the \
                 scope that asks for it to scopes), mapped below."
                    .to_string(),
            ],
            Provider::SamlBroker => vec![
                "In Keycloak, the broker: Identity providers > SAML v2.0, from the SAML \
                 identity provider's metadata, its NameID persistent or the e-mail address."
                    .to_string(),
                "Its mappers: the SAML attribute that holds groups (memberOf, groups) to a \
                 Keycloak group, one each for mcpdef-viewers, mcpdef-operators and \
                 mcpdef-admins."
                    .to_string(),
                format!(
                    "Clients > Create client: OpenID Connect, client ID {client}, client \
                     authentication on; redirect URI {redirect}, post logout redirect URI \
                     {logout}; {secret}."
                ),
                "The client's dedicated scope > Add mapper > Group Membership: token claim \
                 groups, full group path off, add to ID token on."
                    .to_string(),
                "Optionally, Authentication > browser > Identity Provider Redirector, set to \
                 the SAML provider, so people go straight to it."
                    .to_string(),
            ],
        }
    }

    /// The config: `[gateway.admin] public_url` when given, then
    /// `[gateway.admin.oidc]` and `[identity]`.
    pub fn config(&self) -> String {
        let identity = self.identity();
        let mut out = String::new();
        if let Some(url) = &self.public_url {
            out.push_str(&format!("[gateway.admin]\npublic_url = {url:?}\n\n"));
        } else {
            out.push_str(&format!(
                "[gateway.admin]\n# The console's origin, as its users reach it.\npublic_url = {:?}\n\n",
                self.public_url()
            ));
        }
        let scopes: Vec<String> = identity.scopes.iter().map(|s| format!("{s:?}")).collect();
        out.push_str(&format!(
            "[gateway.admin.oidc]\nissuer = {:?}\nclient_id = {:?}\nclient_secret = {{ env = {SECRET_VAR:?} }}\nscopes = [{}]\n",
            self.issuer(),
            self.client_id,
            scopes.join(", ")
        ));
        out.push_str("\n[identity]\n");
        if let Some(subject) = identity.subject_claim {
            out.push_str(&format!("subject_claim = {subject:?}\n"));
        }
        let claims: Vec<String> = identity
            .roles_claims
            .iter()
            .map(|c| format!("{c:?}"))
            .collect();
        out.push_str(&format!("roles_claims = [{}]\n", claims.join(", ")));
        for (claim, value, role) in &identity.role_map {
            out.push_str(&format!(
                "\n[[identity.role_map]]\nclaim = {claim:?}\nvalue = {value:?}\nroles = [{role:?}]\n"
            ));
        }
        out
    }

    /// What `sso init` prints: what to do, in comments, then the config.
    pub fn printed(&self) -> String {
        let mut out = comment(
            &format!(
                "Signing people in to MCPdef's console at {}.",
                self.provider.title()
            ),
            "# ",
            "# ",
        );
        out.push_str("#\n# At the provider:\n");
        for (n, step) in self.steps().iter().enumerate() {
            out.push_str(&comment(&format!("{}. {step}", n + 1), "#   ", "#      "));
        }
        out.push_str("#\n");
        out.push_str(&comment(
            &format!(
                "Then this goes in the config (or run this again with --write), {SECRET_VAR} \
                 is set where MCPdef runs, and the gateway is restarted. Someone the provider \
                 gives no console role is shown the claims MCPdef received of them: map one \
                 to a role with [[identity.role_map]]."
            ),
            "# ",
            "# ",
        ));
        out.push('\n');
        out.push_str(&self.config());
        out
    }
}

/// `text` as comment lines of at most 80 columns, the first starting with
/// `first`, the rest with `rest`.
fn comment(text: &str, first: &str, rest: &str) -> String {
    let mut out = String::new();
    let mut line = first.to_string();
    let mut empty = true;
    for word in text.split_whitespace() {
        if !empty && line.len() + 1 + word.len() > 80 {
            out.push_str(line.trim_end());
            out.push('\n');
            line = rest.to_string();
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    out.push_str(line.trim_end());
    out.push('\n');
    out
}

/// The table `key` of `parent`, made if it is not there.
fn table<'a>(
    parent: &'a mut toml_edit::Table,
    key: &str,
    at: &str,
) -> Result<&'a mut toml_edit::Table> {
    let item = parent.entry(key).or_insert_with(|| {
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        toml_edit::Item::Table(t)
    });
    item.as_table_mut()
        .with_context(|| format!("{at} in the config is not a table: left as it is"))
}

/// One past the last place any table under `table` is written at.
fn after_last(table: &toml_edit::Table) -> usize {
    let mut last = table.position().unwrap_or(0);
    for (_, item) in table.iter() {
        match item {
            toml_edit::Item::Table(t) => last = last.max(after_last(t) - 1),
            toml_edit::Item::ArrayOfTables(tables) => {
                for t in tables.iter() {
                    last = last.max(after_last(t) - 1);
                }
            }
            _ => {}
        }
    }
    last + 1
}

/// `init`'s config merged into `text`, a config file's: refused when the
/// file signs people in already, or sets otherwise what the config sets.
/// The tables it adds are written after the file's own, in order.
pub fn merged(text: &str, init: &Init) -> Result<String> {
    if init.issuer.is_none() {
        bail!("--write needs --issuer: the provider's issuer, exactly as its tokens write it");
    }
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .context("the config is not TOML: left as it is")?;
    let stub: toml_edit::DocumentMut = init.config().parse().expect("the stub is TOML");
    let mut next = after_last(doc.as_table());
    let mut placed = |mut table: toml_edit::Table| {
        table.set_position(next);
        next += 1;
        table
    };
    let root = doc.as_table_mut();
    let admin = table(
        table(root, "gateway", "[gateway]")?,
        "admin",
        "[gateway.admin]",
    )?;
    if admin.contains_key("oidc") {
        bail!("the config has [gateway.admin.oidc] already: change it there, or take it out and run this again");
    }
    match (
        admin.get("public_url").and_then(|v| v.as_str()),
        &init.public_url,
    ) {
        (Some(set), Some(given)) if set.trim_end_matches('/') != given.trim_end_matches('/') => {
            bail!(
                "the config's [gateway.admin] public_url is {set:?}, and --public-url {given:?}: \
             leave one out"
            )
        }
        (Some(_), _) => {}
        (None, Some(given)) => {
            admin.insert("public_url", toml_edit::value(given.as_str()));
        }
        (None, None) => bail!(
            "--write needs the console's URL, which the provider sends people back to: \
             --public-url, or [gateway.admin] public_url"
        ),
    }
    admin.set_implicit(false);
    let oidc = stub["gateway"]["admin"]["oidc"]
        .as_table()
        .expect("the stub's [gateway.admin.oidc]")
        .clone();
    admin.insert("oidc", toml_edit::Item::Table(placed(oidc)));
    let identity = table(root, "identity", "[identity]")?;
    // An `[identity]` the file does not write itself goes after its tables.
    if identity.is_implicit() {
        let position = placed(toml_edit::Table::new()).position();
        if let Some(position) = position {
            identity.set_position(position);
        }
    }
    for key in ["subject_claim", "roles_claims"] {
        let Some(wanted) = stub["identity"].get(key) else {
            continue;
        };
        match identity.get(key) {
            Some(set) if set.to_string().trim() != wanted.to_string().trim() => bail!(
                "the config's [identity] {key} is {}, and {} reads it from {}: set it by hand",
                set.to_string().trim(),
                init.provider.title(),
                wanted.to_string().trim()
            ),
            Some(_) => {}
            None => {
                identity.insert(key, wanted.clone());
            }
        }
    }
    identity.set_implicit(false);
    if let Some(mapped) = stub["identity"]
        .get("role_map")
        .and_then(|m| m.as_array_of_tables())
    {
        let map = identity
            .entry("role_map")
            .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
            .as_array_of_tables_mut()
            .context("[identity] role_map in the config is not [[identity.role_map]]")?;
        for entry in mapped {
            let same = |t: &toml_edit::Table| {
                ["claim", "value", "roles"]
                    .iter()
                    .all(|k| t.get(k).map(|v| v.to_string()) == entry.get(k).map(|v| v.to_string()))
            };
            if !map.iter().any(same) {
                map.push(placed(entry.clone()));
            }
        }
    }
    let after = doc.to_string();
    // Nothing goes in that the gateway would refuse to start with.
    let current = Config::parse(text).ok();
    let before = current.as_ref().map(|c| c.validate()).unwrap_or_default();
    let config = Config::parse(&after).context("the config, merged, does not read back")?;
    let new: Vec<String> = config
        .validate()
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    if !new.is_empty() {
        bail!(
            "the config, merged, would be refused, so it is left as it is:\n  {}",
            new.join("\n  ")
        );
    }
    // `[identity]` names the MCP listener's callers too: where
    // `[gateway.auth]` takes their tokens, the claims it reads them by are
    // not changed here, unseen.
    if let Some(current) = current.filter(|c| c.gateway.auth.enabled) {
        let (was, now) = (current.identity.model(), config.identity.model());
        let mut changes = Vec::new();
        if was.subject_claim != now.subject_claim {
            changes.push(format!(
                "subject_claim {:?} → {:?}",
                was.subject_claim, now.subject_claim
            ));
        }
        if was.roles_claims != now.roles_claims {
            changes.push(format!(
                "roles_claims {:?} → {:?}",
                was.roles_claims, now.roles_claims
            ));
        }
        if !changes.is_empty() {
            bail!(
                "[gateway.auth] reads its callers' tokens by [identity] too, and {}'s [identity] \
                 would change it: {}. After a restart the MCP listener would name its callers, \
                 and find their roles, by those claims: set [identity] by hand, to claims both \
                 listeners can read, and add the rest of what `mcpdef sso init` prints",
                init.provider.title(),
                changes.join(", ")
            );
        }
    }
    Ok(after)
}

/// Merge `init`'s config into `file`, keeping a `.bak` of it; the `.bak`'s
/// path.
pub fn write(file: &Path, init: &Init) -> Result<PathBuf> {
    let before =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let after = merged(&before, init)?;
    let mut backup = file.as_os_str().to_owned();
    backup.push(".bak");
    let backup = PathBuf::from(backup);
    std::fs::write(&backup, &before)
        .with_context(|| format!("writing the backup {}", backup.display()))?;
    std::fs::write(file, after).with_context(|| format!("writing {}", file.display()))?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comment_wraps_at_eighty_columns() {
        let wrapped = comment(&"word ".repeat(40), "#   ", "#      ");
        assert!(
            wrapped.lines().all(|l| l.len() <= 80 && l.starts_with('#')),
            "{wrapped}"
        );
        assert!(wrapped.starts_with("#   word"));
        assert!(wrapped.lines().nth(1).unwrap().starts_with("#      word"));
    }

    #[test]
    fn each_provider_is_named_as_the_command_line_names_it() {
        for provider in Provider::ALL {
            assert_eq!(Provider::parse(provider.name()), Some(provider));
        }
        assert_eq!(Provider::parse("azure"), None);
    }
}
