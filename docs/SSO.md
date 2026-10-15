# Signing in to the console

The console signs people in at your identity provider over OpenID Connect:
the authorization code flow with PKCE (S256), a state and a nonce, the ID
token's signature, issuer, audience and times checked, and RFC 9207's `iss`
where the provider sends it. `[identity]` then names the person by a claim
and gives them console roles from their claims:

| Role | May |
|---|---|
| `console:viewer` | read the console: everything but the redacted config and how the gateway names its callers |
| `console:operator` | also reload the config, restart and test an upstream, approve pin drift |
| `console:admin` | also see the redacted config and how the gateway names its callers |

Someone the provider gives none of them is shown the claims MCPdef received
of them, and no session: the one-look fix for "sign-in works, but nobody has a
role". Each sign-in, refusal, sign-out and action is in the ledger, as theirs.

A SAML identity provider signs people in through a broker:
[SAML.md](./SAML.md).

## The three steps

1. **The provider's side, and the config.** `mcpdef sso init` prints both:

   ```sh
   mcpdef sso init --provider <keycloak|entra|okta|google|authentik|generic|saml-broker> \
     --issuer <the provider's issuer> --public-url https://<console host>:7879
   ```

   What to register at the provider comes first, as comments: the client
   (confidential, the authorization code flow), its redirect URI
   `<public_url>/callback` and post-logout redirect URI `<public_url>/`, and
   the claim that carries roles or groups. The config follows:
   `[gateway.admin] public_url`, `[gateway.admin.oidc]` and `[identity]`.
   `--write` merges it into `mcpdef.toml`, keeping a `.bak`, and refuses to
   change a sign-in or an `[identity]` already there. Where `[gateway.auth]`
   is on, it refuses too when the provider's `[identity]` reads other claims
   than the MCP listener reads its callers' tokens by, since one `[identity]`
   serves both: set it by hand then, to claims both can read.
2. **The client's secret** goes where MCPdef runs, never in the config:
   `MCPDEF_OIDC_CLIENT_SECRET`, which the config reads with
   `client_secret = { env = "MCPDEF_OIDC_CLIENT_SECRET" }`, or a file with
   `{ file = "/run/secrets/oidc-client-secret" }`.
3. **Restart the gateway**, open `<public_url>`, and sign in.

The console needs https off this machine: its cookies are `__Host-` cookies,
which a browser keeps only from a secure origin, so MCPdef refuses an `http`
`public_url` (or issuer) other than `localhost`'s. `[gateway.admin.tls]` (see
[CONFIG.md](./CONFIG.md)) or a TLS proxy in front gives it one.

## Keycloak

```sh
mcpdef sso init --provider keycloak --issuer https://<keycloak>/realms/<realm> \
  --public-url https://<console>
```

- The issuer is the realm's URL, exactly: `https://<keycloak>/realms/<realm>`.
- Roles are the client's own: `console:viewer`, `console:operator`,
  `console:admin`, given to groups (or people). Keycloak puts client roles
  in the access token alone; a *User Client Role* mapper on the client's
  dedicated scope, *add to ID token* on, puts them where the console reads
  them: `resource_access.mcpdef-console.roles`.
- Signing out sends people to Keycloak's end-session endpoint, which asks them
  to confirm (MCPdef keeps no ID token to send it as a hint), then back to the
  console.
- To try it on one machine, the SAML kit
  ([`deploy/compose/sso-saml`](../deploy/compose/sso-saml)) runs Keycloak with
  a realm set up this way, its people signing in on its own form.

## Microsoft Entra ID

```sh
mcpdef sso init --provider entra \
  --issuer https://login.microsoftonline.com/<tenant id>/v2.0 --public-url https://<console>
```

- The issuer is the v2.0 one, with your tenant's ID: the ID tokens of an app
  registration on the v2.0 endpoint write it so.
- Roles are the app's *App roles* (`MCPdef.Viewer`, `MCPdef.Operator`,
  `MCPdef.Admin`), assigned to people or groups under *Enterprise
  applications*; they arrive in the ID token's `roles` claim, whatever the
  number of groups a person is in. (Groups themselves are a poor fit: past
  200 of them, Entra sends a link to them instead of the groups.)
- People are named by `oid`, their object ID, which does not change when
  their name or e-mail address does.
- For automation, Entra issues tokens for an API it names
  `api://<application id>`: that is the admin API's `api_audience`, and for
  the MCP listener, `[gateway.auth] audiences`.

## Okta

```sh
mcpdef sso init --provider okta --issuer https://<org>.okta.com/oauth2/default \
  --public-url https://<console>
```

- The issuer is an authorization server's: `default`, or one of your own.
  Its *Claims* tab is where `groups` is added to the ID token, with the
  `groups` scope, filtered to the groups named `mcpdef-…`.
- Groups `mcpdef-viewers`, `mcpdef-operators` and `mcpdef-admins`, assigned
  to the app, give the console roles.

## Google

```sh
mcpdef sso init --provider google --issuer https://accounts.google.com \
  --public-url https://<console>
```

- Google's ID tokens carry no groups. `hd`, the Workspace domain, gives
  `console:viewer` (set your domain in `[[identity.role_map]]`); operators and
  admins sign in by a client certificate, or through a broker that reads
  Google's groups (Keycloak, as for SAML).
- Make the OAuth consent screen *Internal*, so that only your Workspace's
  people can sign in at all.
- Google has no end-session endpoint: signing out ends the console's session
  alone, and the person stays signed in to Google.

## authentik

```sh
mcpdef sso init --provider authentik \
  --issuer https://<authentik>/application/o/<slug>/ --public-url https://<console>
```

- The issuer ends in a slash: `https://<authentik>/application/o/<slug>/`,
  exactly as authentik writes it in its tokens.
- The provider needs a signing key (RS256): without one, authentik signs ID
  tokens with the client secret (HS256), which MCPdef refuses, as it refuses
  any symmetric algorithm.
- Groups `mcpdef-viewers`, `mcpdef-operators` and `mcpdef-admins`, bound to
  the application, give the console roles.

## Any other provider

`--provider generic` asks for what every OpenID Connect provider can give: a
discovery document at `<issuer>/.well-known/openid-configuration`, ID tokens
signed with RS256, RS384, RS512, PS256, ES256 or ES384, and roles in a
`roles` claim or groups in a `groups` claim. Where a provider puts groups in
its userinfo answer alone, `userinfo = true` adds those claims.

## When it does not work

- **The console's Identity screen** (and `GET /api/v1/identity`, for
  `console:admin`) says whether the provider was found, and if not, why:
  its discovery document unreachable, or naming another issuer. The provider
  is looked for again a few seconds on, not at each sign-in.
- **"No console role"**, with the claims MCPdef received: the claim or the
  value `[identity]` expects is not among them. Map one that is, with
  `[[identity.role_map]]`, or have the provider send the one it expects.
- **A refusal page** names why, and so does its record's `rule` in the ledger
  (`mcpdef audit tail --format json`): `sign-in-state` (the sign-in started
  elsewhere, took over ten minutes, or was replayed), `sign-in-issuer`,
  `sign-in-provider` (the provider, its token endpoint or its discovery
  failed), `sign-in-token` (the ID token, or the subject `[identity]` names),
  `sign-in-userinfo`. Past twenty refused in a minute, one more record, with
  the rule `sign-in-refusals-unrecorded`, says the rest of that minute's are
  not recorded: anyone who reaches the listener can be refused, so the ledger
  grows by so much at most.
- **The provider refuses the redirect URI**: it must be `<public_url>/callback`
  exactly, `public_url` being the origin people reach the console at.
- **Locked out** — the provider down, or nobody with a role: a break-glass
  token ([OPERATIONS.md](./OPERATIONS.md)), made beforehand with `mcpdef admin
  token`, opens the admin API as `console:admin`, every request it makes
  recorded.
