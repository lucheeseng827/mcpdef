// SPDX-License-Identifier: Apache-2.0
//! Who a request is from: what its transport established, and what a call's
//! audit records and RBAC gate make of it.

use mcpdef_auth::Principal;
use mcpdef_policy::Rbac;
use std::net::SocketAddr;

/// Who a request is from, as its transport established it: the bearer token
/// it carried, the client certificate it came with, and where from.
#[derive(Clone, Debug, Default)]
pub struct Caller {
    /// The bearer token the listener validated, if the request carried one
    /// `[gateway.auth]` takes.
    pub principal: Option<Principal>,
    /// The identity the client's certificate gives, as `[gateway.tls.client_auth]`
    /// reads it, if the listener asked for one and the client presented one.
    pub certificate: Option<String>,
    /// The client's address, on a network listener.
    pub peer: Option<SocketAddr>,
}

/// The issuer of a principal a client key names: the gateway itself. No
/// URL, so no identity provider's issuer can be it.
pub(crate) const GATEWAY_ISSUER: &str = "mcpdef";

/// A client key the gateway issued (`[[key]]`): its caller's name, its
/// SHA-256, and the roles it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedKey {
    pub name: String,
    pub digest: [u8; 32],
    pub roles: Vec<String>,
}

/// The caller the client key `token` is, among `keys`: `key:<name>` in its
/// records, holding its roles. Found by the token's SHA-256, compared in
/// constant time.
pub fn issued(keys: &[IssuedKey], token: &str) -> Option<Principal> {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(token.as_bytes());
    let key = keys
        .iter()
        .find(|key| mcpdef_auth::same(&digest, &key.digest))?;
    Some(Principal {
        subject: key.name.clone(),
        scopes: Vec::new(),
        roles: key.roles.clone(),
        client_id: None,
        issuer: GATEWAY_ISSUER.to_string(),
    })
}

/// What a call's audit records say of who made it, and what its RBAC gate
/// judges.
///
/// The subject is the token's when the request carried one, and the
/// certificate's otherwise. A certificate behind a token is recorded as the
/// `actor`: the workload the token's subject called through.
pub(crate) struct Who<'c> {
    /// The records' `agent`: the token's subject (`sub:…`), or the client
    /// key's name (`key:…`), else the certificate's identity (`cert:…`), else
    /// the name of a caller no credential names, such as a stdio client.
    pub(crate) agent: String,
    /// The records' `actor`: the certificate's identity, behind a token.
    pub(crate) actor: Option<String>,
    /// The records' `peer`: the client's address.
    pub(crate) peer: Option<String>,
    subject: Subject<'c>,
}

/// Whose grants the RBAC gate judges.
enum Subject<'c> {
    /// No credential named the caller: the gate lets it by.
    None,
    /// A token's scopes and roles.
    Token(&'c Principal),
    /// A certificate's identity: the roles `[[identity.cert_map]]` gives it.
    Certificate(&'c str),
}

impl<'c> Who<'c> {
    /// Who `caller` is, or `unnamed()` when no credential names it.
    pub(crate) fn of(caller: &'c Caller, unnamed: impl FnOnce() -> String) -> Self {
        let certificate = caller.certificate.as_deref();
        let (agent, actor, subject) = match (&caller.principal, certificate) {
            (Some(p), _) => (
                match p.issuer == GATEWAY_ISSUER {
                    true => format!("key:{}", p.subject),
                    false => format!("sub:{}", p.subject),
                },
                certificate.map(|id| format!("cert:{id}")),
                Subject::Token(p),
            ),
            (None, Some(id)) => (format!("cert:{id}"), None, Subject::Certificate(id)),
            (None, None) => (unnamed(), None, Subject::None),
        };
        Who {
            agent,
            actor,
            peer: caller.peer.map(|addr| addr.to_string()),
            subject,
        }
    }

    /// A caller no credential names, recorded as `agent`: the gateway
    /// itself, or a stdio client.
    pub(crate) fn named(agent: impl Into<String>) -> Self {
        Who {
            agent: agent.into(),
            actor: None,
            peer: None,
            subject: Subject::None,
        }
    }

    /// What the RBAC gate judges: the subject's roles and scopes, or `None`
    /// for a caller no credential names, whom the gate lets by. A
    /// certificate no `[[identity.cert_map]]` entry maps holds no role.
    pub(crate) fn grants<'a>(&'a self, rbac: &'a Rbac) -> Option<Vec<&'a str>> {
        match self.subject {
            Subject::None => None,
            Subject::Token(p) => Some(p.grants_subjects().collect()),
            Subject::Certificate(identity) => Some(rbac.certificate_roles(identity).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Principal {
        Principal {
            subject: "alice".into(),
            scopes: vec!["read".into()],
            roles: vec!["dev".into()],
            client_id: None,
            issuer: "https://idp.test".into(),
        }
    }

    #[test]
    fn the_token_is_the_subject_and_the_certificate_behind_it_the_actor() {
        let mut rbac = Rbac::new();
        rbac.map_certificates("spiffe://acme/ci/*", vec!["ci".into()]);
        let both = Caller {
            principal: Some(alice()),
            certificate: Some("spiffe://acme/ci/bot".into()),
            peer: Some("203.0.113.7:51234".parse().unwrap()),
        };
        let who = Who::of(&both, || unreachable!());
        assert_eq!(who.agent, "sub:alice");
        assert_eq!(who.actor.as_deref(), Some("cert:spiffe://acme/ci/bot"));
        assert_eq!(who.peer.as_deref(), Some("203.0.113.7:51234"));
        assert_eq!(who.grants(&rbac), Some(vec!["read", "dev"]));

        let certificate = Caller {
            principal: None,
            ..both.clone()
        };
        let who = Who::of(&certificate, || unreachable!());
        assert_eq!(who.agent, "cert:spiffe://acme/ci/bot");
        assert_eq!(who.actor, None);
        assert_eq!(who.grants(&rbac), Some(vec!["ci"]));

        // A certificate no entry maps holds no role, never a default one.
        let unmapped = Caller {
            certificate: Some("spiffe://acme/web/app".into()),
            ..Caller::default()
        };
        assert_eq!(
            Who::of(&unmapped, || unreachable!()).grants(&rbac),
            Some(vec![])
        );

        let anonymous = Caller::default();
        let nobody = Who::of(&anonymous, || "agent:claude".into());
        assert_eq!(nobody.agent, "agent:claude");
        assert_eq!((&nobody.actor, &nobody.peer), (&None, &None));
        assert_eq!(nobody.grants(&rbac), None);
    }
}
