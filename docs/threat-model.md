# Threat model and invariants

## Assets and attackers

Assets are OIDC credentials, authorization transactions, local sessions, DSH's native bootstrap token/cookie, and the shared operator authority. Attackers include an unauthenticated internet client, a malicious site driving a browser, a DNS-rebinding origin, a denied issuer identity, and a client forging proxy/identity headers. Compromise of the DSH host, identity provider, reverse proxy, or an admitted shared operator is outside the plugin's containment ability.

## Invariants

1. The configured HTTPS issuer and fixed `publicOrigin` are the only URL authorities. Host and forwarded headers never derive redirect or issuer values.
2. `openid-client` owns discovery, JWKS/signature, issuer, audience/`azp`, expiry/time, nonce, PKCE, and optional `auth_time` validation.
3. Each callback needs one unexpired transaction cookie and exact state, consumes the transaction before token exchange, and cannot replay.
4. Configuration contains only a credential reference. Missing resolution fails closed. Logs and browser state exclude secret/token/code/state/nonce/verifier/claim material.
5. Every configured policy category is required. Empty configured lists, malformed identity/groups/claims, and exact-match failures deny.
6. Local session and transaction bearers are independent 256-bit values indexed by hash, memory-only, bounded, and expired by cleanup.
7. Logout state change requires the local session, exact public Origin, content type, and session-bound CSRF value.
8. The reverse proxy admits `/auth/*` directly but requires `/auth/check` success for every other HTTP and upgrade path. Logout therefore defeats stale DSH cookies.
9. DSH remains loopback-only. HTTPS-only reachability/HSTS protects its native non-Secure cookie.
10. All admitted users are equivalent shared operators; no per-user DSH isolation or attribution is claimed.

## Residual risks

Provider policy changes remain latent until idle/absolute expiry or restart. Memory-local state does not support multi-process replicas. Provider back-channel logout/revocation and refresh tokens are absent. The DSH bootstrap URL carries a temporary query bearer, requiring URL printing and query logging to be disabled. Real Authentik, Dex/Keycloak, Caddy, and browser interoperability require separate isolated gates.
