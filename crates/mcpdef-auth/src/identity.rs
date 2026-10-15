// SPDX-License-Identifier: Apache-2.0
//! Who a verified token's claims say its caller is: which claim is the
//! subject, which claims hold roles, and the roles a claim's value gives.
//! One model for the MCP listener's bearer tokens and the console's sign-in,
//! since an identity provider says who someone is the same way to both.
//!
//! A claim is named by a dotted path into the claims, `realm_access.roles`
//! say; a claim whose own name holds dots, as a namespaced one such as
//! `https://example.com/roles` does, is taken by that name first. A claim
//! may be a string or an array of strings; anything else holds no value.

use serde_json::{Map, Value};

/// Roles given to a caller whose claim `claim` holds `value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMapping {
    pub claim: String,
    pub value: String,
    pub roles: Vec<String>,
}

/// How claims name a caller. The default reads the subject from `sub` and
/// roles from `roles`, as a token was always read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityModel {
    pub subject_claim: String,
    pub roles_claims: Vec<String>,
    pub role_map: Vec<RoleMapping>,
}

impl Default for IdentityModel {
    fn default() -> Self {
        IdentityModel {
            subject_claim: "sub".into(),
            roles_claims: vec!["roles".into()],
            role_map: Vec::new(),
        }
    }
}

impl IdentityModel {
    /// The subject `claims` name, or why they name none.
    pub fn subject(&self, claims: &Map<String, Value>) -> Result<String, String> {
        match claim(claims, &self.subject_claim) {
            Some(Value::String(subject)) if !subject.is_empty() => Ok(subject.clone()),
            _ => Err(format!(
                "it has no `{}` claim to name its subject by, as [identity] subject_claim says",
                self.subject_claim
            )),
        }
    }

    /// The roles `claims` give: those each roles claim holds, then those of
    /// each mapping whose claim holds its value, in that order, each once.
    pub fn roles(&self, claims: &Map<String, Value>) -> Vec<String> {
        let held = self
            .roles_claims
            .iter()
            .flat_map(|path| strings(claim(claims, path)));
        let mapped = self
            .role_map
            .iter()
            .filter(|m| strings(claim(claims, &m.claim)).any(|v| v == m.value))
            .flat_map(|m| m.roles.iter().map(String::as_str));
        let mut roles: Vec<String> = Vec::new();
        for role in held.chain(mapped) {
            if !roles.iter().any(|r| r == role) {
                roles.push(role.to_string());
            }
        }
        roles
    }
}

/// The claim at `path` in `claims`: the one named `path` itself if there is
/// one, else the walk down its dotted segments.
pub fn claim<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(value) = claims.get(path) {
        return Some(value);
    }
    let mut segments = path.split('.');
    let first = claims.get(segments.next()?)?;
    segments.try_fold(first, |value, segment| value.as_object()?.get(segment))
}

/// The strings a claim holds: itself, if it is one, or each string of an
/// array.
pub fn strings(value: Option<&Value>) -> impl Iterator<Item = &str> {
    let (one, many) = match value {
        Some(Value::String(s)) => (Some(s.as_str()), None),
        Some(Value::Array(items)) => (None, Some(items.iter().filter_map(Value::as_str))),
        _ => (None, None),
    };
    one.into_iter().chain(many.into_iter().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn mapping(claim: &str, value: &str, roles: &[&str]) -> RoleMapping {
        RoleMapping {
            claim: claim.into(),
            value: value.into(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[test]
    fn each_provider_maps_as_configured() {
        // Keycloak: realm roles under an object.
        let keycloak = IdentityModel {
            roles_claims: vec![
                "realm_access.roles".into(),
                "resource_access.mcpdef.roles".into(),
            ],
            ..IdentityModel::default()
        };
        let token = claims(json!({
            "sub": "f81d4fae",
            "realm_access": { "roles": ["offline_access", "mcp-reader"] },
            "resource_access": { "mcpdef": { "roles": ["console:viewer"] } },
        }));
        assert_eq!(
            keycloak.roles(&token),
            ["offline_access", "mcp-reader", "console:viewer"]
        );

        // Entra: app roles as an array; `scp` a string, read as scopes elsewhere.
        let entra = IdentityModel {
            subject_claim: "oid".into(),
            ..IdentityModel::default()
        };
        let token = claims(
            json!({ "sub": "x", "oid": "00000000-aaaa", "roles": ["Mcp.Admin"], "scp": "User.Read" }),
        );
        assert_eq!(entra.subject(&token).unwrap(), "00000000-aaaa");
        assert_eq!(entra.roles(&token), ["Mcp.Admin"]);

        // Okta: groups, mapped.
        let okta = IdentityModel {
            roles_claims: vec![],
            role_map: vec![mapping("groups", "mcp-admins", &["admin", "console:admin"])],
            ..IdentityModel::default()
        };
        let member = claims(json!({ "sub": "00u1", "groups": ["Everyone", "mcp-admins"] }));
        let other = claims(json!({ "sub": "00u2", "groups": ["Everyone"] }));
        assert_eq!(okta.roles(&member), ["admin", "console:admin"]);
        assert_eq!(okta.roles(&other), Vec::<String>::new());

        // Google: the hosted domain, a string.
        let google = IdentityModel {
            subject_claim: "email".into(),
            role_map: vec![mapping("hd", "example.com", &["reader"])],
            ..IdentityModel::default()
        };
        let token =
            claims(json!({ "sub": "1061", "email": "ann@example.com", "hd": "example.com" }));
        assert_eq!(google.subject(&token).unwrap(), "ann@example.com");
        assert_eq!(google.roles(&token), ["reader"]);
        let outsider = claims(json!({ "sub": "1062", "email": "bo@gmail.com" }));
        assert_eq!(google.roles(&outsider), Vec::<String>::new());
    }

    #[test]
    fn a_claim_is_found_by_its_own_name_first_and_each_role_is_given_once() {
        let model = IdentityModel {
            roles_claims: vec!["https://example.com/roles".into(), "roles".into()],
            role_map: vec![mapping("team", "ops", &["admin", "reader"])],
            ..IdentityModel::default()
        };
        let token = claims(json!({
            "sub": "a",
            "https://example.com/roles": "reader",
            "roles": ["admin", 7, null, "reader"],
            "team": "ops",
        }));
        assert_eq!(model.roles(&token), ["reader", "admin"]);
        assert_eq!(claim(&token, "nowhere.at.all"), None);
        assert_eq!(claim(&token, "sub.deeper"), None);
    }

    #[test]
    fn a_subject_must_be_a_string() {
        let model = IdentityModel::default();
        for token in [
            json!({}),
            json!({ "sub": 7 }),
            json!({ "sub": "" }),
            json!({ "sub": ["a"] }),
        ] {
            assert!(model.subject(&claims(token.clone())).is_err(), "{token}");
        }
        assert_eq!(model.subject(&claims(json!({ "sub": "a" }))).unwrap(), "a");
    }
}
