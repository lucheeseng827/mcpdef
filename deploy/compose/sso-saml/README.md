# The SAML kit: sign-in through Keycloak as a broker

MCPdef's console signs people in over OpenID Connect alone. A SAML identity
provider signs them in through a broker that speaks both: here Keycloak, which
checks each SAML assertion's signature and signs the person in to MCPdef as an
OpenID Connect provider. MCPdef never parses SAML. [docs/SAML.md](../../../docs/SAML.md)
says why, and how ADFS, Entra ID, Okta or Shibboleth takes the place of the
stand-in identity provider here.

## Run it

```sh
docker compose up -d
```

Open <http://localhost:7879>. MCPdef sends you to Keycloak; choose
**Corp (SAML)**, and sign in at the SAML identity provider:

| User | Password | Groups it asserts | Console role |
|---|---|---|---|
| `saml-admin` | `saml-admin` | `mcpdef-admins` | `console:admin` |
| `saml-operator` | `saml-operator` | `mcpdef-operators` | `console:operator` |
| `saml-viewer` | `saml-viewer` | `mcpdef-viewers` | `console:viewer` |
| `saml-nobody` | `saml-nobody` | none | none: the page that shows the claims MCPdef received |

The broker's own people sign in on its form instead: `ops-admin`,
`ops-operator`, `ops-viewer` and `ops-nobody`, each password its name.

Signing out of the console signs you out of both realms; the next sign-in
asks for the password again. Who signed in and out, and each action they
took, is in the ledger: on the console's Audit screen, or

```sh
docker compose exec mcpdef mcpdef audit tail --config /etc/mcpdef/mcpdef.toml
```

Keycloak's own administration console is at <http://localhost:8080/admin>
(`admin` / `admin`): the realms below, as they are wired.

To run a build of this tree instead of the published image: `make docker-build`
at the repository's root, then `MCPDEF_IMAGE=mcpdef:dev docker compose up -d`.

## How it is wired

```
browser ──▶ MCPdef console :7879 ──OIDC──▶ Keycloak realm "mcpdef" (the broker)
                                               │  SAML (HTTP-POST, signed)
                                               ▼
                                          Keycloak realm "corp" (the SAML IdP)
```

- **`realms/corp.json`**, the identity provider: its people and their groups,
  and one SAML client, the broker. It signs the response and the assertion
  (RSA-SHA256), names the person by e-mail address (the NameID), and sends
  `email`, `firstName`, `lastName` and `groups` as attributes.
- **`realms/mcpdef.json`**, the broker:
  - an identity provider, `corp`, of type SAML: it reads corp's metadata,
    signing keys included, from its descriptor URL, and requires a valid
    signature on every response and assertion;
  - mappers: the attributes to the person's e-mail and name, and each of the
    three groups to the broker's group of the same name;
  - the OpenID Connect client MCPdef signs in with, `mcpdef-console`: PKCE
    S256, the standard flow alone, and the group membership in the ID token
    (`groups`). It also gives the groups' client roles in
    `resource_access.mcpdef-console.roles`, which is how `mcpdef sso init
    --provider keycloak` reads roles; this kit's config reads the groups.
- **`mcpdef.toml`**: what `mcpdef sso init --provider saml-broker` writes,
  and an upstream to replace with yours.
- **`compose.yaml`**: MCPdef runs on Keycloak's network, so that
  `http://localhost:8080` is Keycloak for MCPdef as it is for the browser:
  the issuer both see is the one the tokens name.

The same realms are what MCPdef's own test signs in at
(`crates/mcpdef/tests/keycloak.rs`, run in CI): every user above, an action in
the ledger, a request from another origin refused, signing out of both realms,
and a SAML response altered on its way to the broker refused there.

## Not for production

This is for trying it out on one machine: Keycloak in development mode, its
database inside its container, plain http on localhost, demo passwords, and
a client secret everyone can read. [docs/SAML.md](../../../docs/SAML.md#in-production)
lists what production needs.
