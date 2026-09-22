# @senti100/dsh-oidc

Provider-neutral OpenID Connect admission for the DeepSeek Harness (DSH) Web profile. It uses Authorization Code + PKCE through `openid-client`, then hands a successful browser to DSH's unchanged native Connection plugin.

## Security architecture

This package is a Host-only Cordis plugin. It registers `/auth/login`, `/auth/callback`, `/auth/check`, and `/auth/logout`; it does **not** replace or copy `@deepseek-ai/dsh-client-connection`. After validating the ID token and admission policy, it creates a short-lived opaque in-memory session and redirects through `ctx.connection.authenticatedUrl(publicOrigin)` so DSH mints its own native browser cookie.

A reverse proxy is a mandatory part of the security boundary. It must send `/auth/*` directly to DSH and guard **every other path** (root, static assets, `/api`, uploads, SSE/streams, and WebSocket upgrades) with `forward_auth /auth/check`. A stale native DSH cookie is not sufficient after the OIDC session is removed. DSH must remain loopback-bound and the public hostname must be HTTPS-only with HSTS; do not expose HTTP port 80 for that hostname.

DSH 0.1.5-rc.1 has one process-wide operator peer. Every admitted user shares the same DSH home, sessions, workspaces, credentials, tools, approvals, and event stream. Groups control admission only; they do not create internal roles or isolation. Run one DSH home/process per user when isolation is required.

## Compatibility

The first candidate is intentionally pinned to the public DSH `0.1.5-rc.1` package interfaces. DSH APIs are pre-stable; test and release a separate adapter/version before widening these exact peer versions. Current upstream `0.1.7-alpha.2` remains a future compatibility lane, not an implied supported version.

## Configuration

| Field                       | Meaning                                                                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                    | Exact HTTPS issuer identifier used for discovery and token validation.                                                                                              |
| `clientId`                  | Exact OIDC client identifier.                                                                                                                                       |
| `clientSecretRef`           | Optional DSH credential reference name. The secret value is resolved for each login/callback/logout operation and is never configuration. Omit for a public client. |
| `publicOrigin`              | Fixed HTTPS origin, path `/`; never derived from `Host` or forwarded headers.                                                                                       |
| `allowedSubjects`           | Exact `{ issuer, subject }` tuples.                                                                                                                                 |
| `allowedEmails`             | Exact email values as an additional policy category, never identity.                                                                                                |
| `allowedGroups`             | Exact case-sensitive values from `groupsClaim`.                                                                                                                     |
| `groupMode`                 | `any` or `all` for configured allowed groups.                                                                                                                       |
| `requiredClaims`            | Exact allowed values per required claim; categories are ANDed.                                                                                                      |
| `sessionMaxAgeSeconds`      | Absolute local OIDC-session lifetime (default 8 hours).                                                                                                             |
| `sessionIdleTimeoutSeconds` | Idle expiry (default 30 minutes). Provider policy changes do not invalidate an already-issued session before these limits.                                          |

At least one allow category is mandatory. Every configured category is ANDed; values within subject, email, and `any` group categories are ORed. Match comparison is byte-exact with no case folding or substring behavior. Explicit empty policy lists are invalid. Group claims must be nonempty arrays of unique strings.

See [`examples/cordis.patch.yml`](examples/cordis.patch.yml), [`examples/Caddyfile`](examples/Caddyfile), and [`.env.example`](.env.example). Configuration values in the patch are environment-backed; the client secret value stays behind `ctx.credentials` and only its reference name appears in plugin config.

## Protocol behavior

- OpenID Connect discovery over HTTPS with redirects rejected and a bounded request timeout.
- Authorization Code only, PKCE S256, independent random state/nonce/verifier/transaction/session/CSRF values.
- One-use five-minute transaction with a bound `Secure; HttpOnly; SameSite=Lax; Path=/` cookie.
- ID-token signature, issuer, audience/authorized-party, expiry, nonce, and optional `auth_time` validation by `openid-client`/`oauth4webapi`.
- Opaque hashed server-side sessions; no access token, refresh token, raw ID token, claims, secret, code, state, or nonce is retained in cookies or logs.
- GET logout only renders a confirmation form. POST requires exact Origin and session CSRF before local deletion. RP-initiated logout is optional and provider-advertised.
- Restart invalidates all transactions and OIDC sessions.

## Local development

Node 22.19 or newer in the Node 22 line is required.

```sh
npm ci
npm run check
```

`npm run check` runs formatting, lint, strict TypeScript, coverage-gated tests, build, package-content inspection, and a local secret-pattern scan. Provider interoperability and reverse-proxy/live-browser acceptance require separate disposable or attended environments; this repository does not contact a real provider during its local gates.

## Non-goals

This package does not change DSH RPC methods, permissions, model credentials, workspace authorization, per-user ownership, or event delivery. It does not make non-loopback DSH binding safe. It does not deploy or configure an identity provider, proxy, DNS, or DSH instance.
