# Provider interoperability plan

The package is provider-neutral by protocol and does not claim broad provider interoperability until isolated lanes pass.

## Authentik lane (bounded production observation)

A separate production Authentik application/provider has admitted the intended operator to a DSH Web 0.1.5-rc.1 instance: browser sign-in completed and a workspace was created. The deployed proxy subsequently needed a correction to remove WebSocket upgrade headers on the **auth pre-check**; an unauthenticated WebSocket request then returned 401 instead of 502. This is **not** a complete, reproducible public-provider interoperability certification: the authenticated WebSocket after that correction, the browser-stored native-cookie `Secure` flag, logout/stale-cookie denial, denied identity, and key rotation have not been independently confirmed in that browser. No production client ID, subject, provider export, or deployment hostname belongs in this repository.

For transferable Authentik certification, use a disposable non-production application/provider with Authorization Code, exact callback `https://dsh.example/auth/callback`, `openid profile email` scopes, a placeholder client ID, and a secret installed only through the DSH credential provider. Verify valid login, exact subject/group/claim denial, nonce/state/code replay, logout behavior, key rotation, restart invalidation, query/secret log suppression, the native-cookie flag, and WebSocket reconnect. Delete the disposable application and credentials after evidence capture.

## Standards lane (required before broad claim)

Run Dex or Keycloak in an isolated loopback-only test topology with a synthetic CA/hostname, ephemeral users/groups, and no production data. Exercise discovery/JWKS rotation, issuer/audience/authorized-party/time failures, PKCE, two browsers, API/upload/SSE/WebSocket proxy gating, logout denial, and restart. Record exact image/version/config hashes and tear down all containers, networks, volumes, keys, and listeners.

Until those lanes pass, documentation may say “provider-neutral implementation” and “bounded Authentik production sign-in observed”, but not “fully verified with Authentik”, “Dex compatible”, “Keycloak compatible”, or “broadly interoperable”.
