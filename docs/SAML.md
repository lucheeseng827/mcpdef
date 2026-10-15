# SAML sign-in, through a broker

MCPdef's console signs people in over **OpenID Connect** alone
([SSO.md](./SSO.md)). A **SAML**
identity provider (ADFS, Microsoft Entra ID, Okta, Shibboleth) signs people
in to it **through a broker** that speaks both: the broker takes the provider's
SAML assertions, checks their signatures, and signs the person in to MCPdef as
an OpenID Connect provider. MCPdef never parses SAML.

Keycloak is the broker MCPdef is tested with
([`deploy/compose/sso-saml`](../deploy/compose/sso-saml), and a test that
signs in through it in CI). authentik and ZITADEL broker SAML too. Dex is not
one to use for it: its own documentation calls its SAML connector
unmaintained, and likely vulnerable to authentication bypass.

## Why a broker

XML signatures are the most dangerous parser class in identity. A signature
checked over one reading of a document, and claims taken from another, has
let attackers sign in as anyone: ruby-saml's CVE-2024-45409, its parser
differentials CVE-2025-25291 and CVE-2025-25292 and their incomplete fixes,
signature wrapping in samlify and node-saml, and in authentik, a broker
(CVE-2026-25922). A gateway in every tool call's path is the last place for
that parser. With a broker, it runs in one service you patch like any
identity provider, and MCPdef stays one static binary that checks one kind
of signature: an ID token's.

What it takes: the broker, one more service to run; and a person signs in
through two hops instead of one, which they only see as a redirect.

## Try it

[`deploy/compose/sso-saml`](../deploy/compose/sso-saml) runs it on one
machine with `docker compose up -d`: Keycloak with a realm `corp` standing in
for your SAML identity provider, a realm `mcpdef` brokering it, and MCPdef
signing in to that. Its README lists the demo users.

## Your identity provider, through Keycloak

In the broker's realm (in the kit, `mcpdef`):

1. **Identity providers > SAML v2.0.** An alias (it is in the URLs below:
   `corp` in the kit), and *Use entity descriptor* with your identity
   provider's metadata URL: Keycloak reads its single sign-on URL and signing
   certificate from it. With *Use metadata descriptor URL* on, it reads them
   again as the provider rotates its keys.
   - *Principal type*: Subject NameID. *NameID policy format*: Email, or
     Persistent where the provider gives no stable e-mail address.
   - *Validate signatures* on, and *Want assertions signed* on. Never off:
     without them anyone can write an assertion.
   - *Sync mode*: Force, so that a person's groups are read again at each
     sign-in, and a group taken away at the provider is taken away here.
2. **What your identity provider asks for** about the broker (its service
   provider):
   - entity ID: `https://<keycloak>/realms/<realm>`
   - assertion consumer service (ACS) URL, HTTP-POST:
     `https://<keycloak>/realms/<realm>/broker/<alias>/endpoint`
   - or all of it at once, its metadata:
     `https://<keycloak>/realms/<realm>/broker/<alias>/endpoint/descriptor`
3. **The provider's mappers.** *Attribute Importer* for the e-mail address,
   given name and surname, from the attribute names your provider sends (each
   section below gives them). Then one *Advanced Attribute to Group* per
   console group: the attribute that holds the person's groups, its value the
   group at the provider, and the broker's group: `mcpdef-viewers`,
   `mcpdef-operators`, `mcpdef-admins`.
4. **The client MCPdef signs in with**, and MCPdef's config: run

   ```sh
   mcpdef sso init --provider saml-broker \
     --issuer https://<keycloak>/realms/<realm> --public-url https://<console>
   ```

   It prints what to set on the client (its redirect URIs, and the group
   membership in the ID token), and the config; `--write` merges the config
   into `mcpdef.toml`. Someone whose groups give no console role is shown
   the claims MCPdef received of them, which is where a misnamed group shows.
5. Optionally, **Authentication > browser > Identity Provider Redirector**,
   set to the alias: people go straight to their identity provider, never
   seeing Keycloak's own form.

### ADFS

- *Relying Party Trusts > Add Relying Party Trust*, claims aware: import the
  broker's metadata URL (2. above), or enter its identifier (the entity ID)
  and a SAML 2.0 WebSSO endpoint (the ACS URL).
- *Edit Claim Issuance Policy*:
  - *Send LDAP Attributes as Claims*: E-Mail-Addresses → E-Mail Address,
    Given-Name → Given Name, Surname → Surname, Token-Groups - Unqualified
    Names → Group.
  - *Transform an Incoming Claim*: E-Mail Address → Name ID, its format
    Email.
- In Keycloak, the metadata URL is
  `https://<adfs>/FederationMetadata/2007-06/FederationMetadata.xml`, and the
  attributes arrive by their claim type URIs:
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`,
  `…/claims/givenname`, `…/claims/surname`, and the groups as
  `http://schemas.xmlsoap.org/claims/Group`.
- ADFS signs the assertion; Keycloak's *Want assertions signed* is what it
  checks.

### Microsoft Entra ID (a SAML application)

- *Enterprise applications > New application > Create your own application*,
  non-gallery; *Single sign-on > SAML*: *Identifier (Entity ID)* the entity
  ID, *Reply URL (Assertion Consumer Service URL)* the ACS URL.
- *Attributes & Claims*: *Unique User Identifier (Name ID)* `user.mail` (or
  `user.userprincipalname`), its format Email address. *Add a group claim*:
  *Groups assigned to the application*. Its *Source attribute* decides what
  the values are: object IDs by default, which are what the group mappers
  then match, or *Cloud-only group display names* for groups' names.
- *SAML Certificates*: the *App Federation Metadata Url* is what Keycloak's
  *Use entity descriptor* takes. *Signing Option*: Sign SAML response and
  assertion.
- *Users and groups*: assign the groups.
- In Keycloak, the attributes arrive as
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`,
  `…/givenname`, `…/surname`, and the groups as
  `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`.
- Where SAML is not mandated, Entra ID speaks OpenID Connect itself:
  `mcpdef sso init --provider entra` signs people in with no broker.

### Okta (a SAML application)

- *Applications > Create App Integration > SAML 2.0*: *Single sign-on URL*
  the ACS URL (*Use this for Recipient URL and Destination URL* on);
  *Audience URI (SP Entity ID)* the entity ID; *Name ID format* EmailAddress,
  *Application username* Email.
- *Attribute Statements*: `email` → `user.email`, `firstName` →
  `user.firstName`, `lastName` → `user.lastName`. *Group Attribute
  Statements*: `groups`, filtered to the names that start with `mcpdef-`.
- *Sign On*: the *Metadata URL* is what Keycloak's *Use entity descriptor*
  takes.
- *Assignments*: the groups.
- Okta speaks OpenID Connect too: `mcpdef sso init --provider okta` needs no
  broker, where SAML is not mandated.

### Shibboleth IdP

- `conf/metadata-providers.xml`: a metadata provider for the broker's
  metadata (its descriptor URL, 2. above), or a copy of it in a file.
- `conf/attribute-filter.xml`: release `mail`, `givenName`, `sn`, and the
  attribute that holds groups (`isMemberOf`, or `eduPersonEntitlement`) to
  the broker's entity ID.
- `conf/saml-nameid.xml`: the NameID, the e-mail address
  (`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`) or a persistent
  one.
- In Keycloak, the metadata URL is the IdP's `https://<idp>/idp/shibboleth`,
  and the attributes arrive by OID: `mail` as
  `urn:oid:0.9.2342.19200300.100.1.3`, `givenName` as `urn:oid:2.5.4.42`,
  `sn` as `urn:oid:2.5.4.4`, `isMemberOf` as
  `urn:oid:1.3.6.1.4.1.5923.1.5.1.1`, `eduPersonEntitlement` as
  `urn:oid:1.3.6.1.4.1.5923.1.1.1.7`.

## In production

- **Keycloak in production mode**: `start`, not `start-dev`; a database of
  its own; TLS, so that the issuer is `https://`. MCPdef refuses an `http`
  issuer other than this machine's.
- **Patch the broker** like any identity provider, its SAML handling above
  all; the authentik advisory above is the reminder.
- **The console over https**: `[gateway.admin] public_url` an `https://`
  origin, `[gateway.admin.tls]` or a proxy in front. MCPdef refuses an `http`
  one other than this machine's: a sign-in's cookies need it.
- **A client secret of your own**, from where secrets are kept: the client's
  *Credentials* in Keycloak, and `MCPDEF_OIDC_CLIENT_SECRET` (or `{ file =
  … }`) where MCPdef runs.
- **Signatures**: *Validate signatures* and *Want assertions signed* stay on.
  *Want AuthnRequests signed* has the identity provider check the broker's
  requests too, where the provider supports it. Keep *Allowed clock skew*
  small (seconds).
- **One way in**: with the Identity Provider Redirector, the broker's own
  form, and its own users, are out of the way. A break-glass token
  (`[gateway.admin.break_glass]`, docs/OPERATIONS.md) is the way in when the
  broker or the identity provider is down.
