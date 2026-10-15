# mcpdef-transport

The `Transport` trait and its implementations — stdio child, HTTP bridges, and the egress/SSRF guard that carries MCP traffic to upstream servers.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Defines the `Transport` trait plus stdio-child and in-memory duplex transports.
- Shares one upstream connection between concurrent calls (`UpstreamHandle`): each request goes
  out under a private id, replies are routed back by id in any order, notifications go to
  subscribers (from the moment the handle takes the transport over, those it already holds
  included, with `UpstreamHandle::spawn_listening`), and a per-upstream in-flight cap applies
  backpressure. A Streamable-HTTP endpoint
  takes those calls' POSTs concurrently; a pipe or a single stream takes them in turn.
- Tells a supervisor when an upstream goes down (`UpstreamHandle::watch`): its connection closed,
  its Streamable-HTTP session ended, or, with `HandleOptions::trip_after` set, that many calls
  in a row failed or timed out.
- Leaves a per-request hook (`RequestAuth`) for adding upstream credentials to every HTTP request,
  and fills it with static ones (`StaticAuth`: a bearer token, a header of the upstream's own, or
  HTTP Basic), marked sensitive. An upstream's `401` has them read again once, and the request
  sent once more if that changed them; a second `401` fails it closed.
- Fetches a bearer token by the OAuth 2.0 client credentials grant (`TokenAuth`), with RFC 8707's
  `resource`, through the egress guard and a TLS profile of its own: one fetch however many
  requests need a token, kept until 30 s before it expires, and fetched afresh on a `401`. With no
  token to send, a request is not sent. `RequestAuth::expires_at` says when the token it holds
  expires, and `TlsWatch::client_not_after` when the certificate a connection presents does.
- Spawns stdio upstreams with token-broker env injection so servers never hold long-lived creds.
- Bridges Streamable HTTP and the legacy 2024-11-05 HTTP+SSE transport (probe/fallback, `Last-Event-ID` resumption).
- Enforces the egress/SSRF guard: cloud-metadata block, private/loopback classification, and DNS pinning.
- Reads the certificate and key a listener serves (`read_served`) by the rules a client certificate is
  read by: PEM only, the key unencrypted and the certificate's own, with an error that says how to
  convert DER or PKCS #12. `CertificateNames` reads a certificate's subject, issuer and alternative
  names, DNS, IP, URI and email, by the same DER walk that reads its expiry. `read_client_trust`
  reads the CAs and CRLs a listener checks a client's certificate against, by the rules an
  upstream's are read by.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-transport
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
