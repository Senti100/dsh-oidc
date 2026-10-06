# Changelog

## 0.2.1-alpha.0 - Released

- Add a bundled self-contained sign-in page at `/auth/signin` (strict CSP, inline HTML, no external assets).
- Make `/auth/check` navigation-aware: browser navigations receive `303 -> /auth/signin` (which Caddy's `forward_auth` subrequest copies through verbatim); `fetch`/XHR/WebSocket subrequests keep the plain `401`. This gives human users a real sign-in entry point without any reverse-proxy configuration change.
- Document the sign-in flow and the five-route `/auth` matcher in the README, deployment guide, and shipped `examples/Caddyfile`.
- **Tested with DSH `0.2.0-rc.2`** (the current release): full-profile acceptance against a real DSH `0.2.0-rc.2` Web profile + Caddy 2.10.2 (synthetic OIDC, native-cookie `Secure`, WebSocket, upload), the separate `web-oidc` public-install gate, and a live deployment verified through Caddy 2.11.3 (sign-in redirect, login chain to the provider with PKCE S256, API-client 401 preservation). The compatibility pin to `0.2.0-rc.2` package interfaces is unchanged.

## 0.2.0-alpha.0 - Released

- Isolated exact DSH 0.2.0-rc.2 / Cordis 4.0.4 compatibility candidate with clean locked runtime closure.
- Inspect upstream native-bootstrap, PeerAdmission, API waterfall, and readiness-gated WebSocket changes without replacing the native Connection or weakening the proxy boundary.
- Add mixed-old-peer rejection, real denied-identity and revoked-cookie replay coverage, stronger browser cookie assertions, and isolated TLS listener/trust handling.
- Document pinned clean-home staging and paired application/home rollback; no in-place migration or production/provider change is implied.

## 0.1.0-alpha.0 - Unreleased

- Initial local candidate: provider-neutral OIDC Authorization Code + PKCE admission.
- Host-only exact auth routes with opaque bounded sessions, CSRF logout, exact claim policy, DSH native-cookie bootstrap, and mandatory reverse-proxy gate documentation.
- Exact DSH 0.1.5-rc.1 compatibility pin.
