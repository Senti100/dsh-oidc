# Provider interoperability plan

The package is provider-neutral by protocol and does not claim broad provider interoperability until isolated lanes pass.

## Authentik lane (planned)

Use a disposable non-production application/provider with Authorization Code, exact callback `https://dsh.example/auth/callback`, `openid profile email` scopes, a placeholder client ID, and a secret installed only through the DSH credential provider. Verify valid login, exact subject/group/claim denial, nonce/state/code replay, logout behavior, key rotation, restart invalidation, and that no query/secret material reaches logs. Delete the disposable application and credentials after evidence capture.

## Standards lane (required before broad claim)

Run Dex or Keycloak in an isolated loopback-only test topology with a synthetic CA/hostname, ephemeral users/groups, and no production data. Exercise discovery/JWKS rotation, issuer/audience/authorized-party/time failures, PKCE, two browsers, API/upload/SSE/WebSocket proxy gating, logout denial, and restart. Record exact image/version/config hashes and tear down all containers, networks, volumes, keys, and listeners.

Until those lanes pass, documentation may say “provider-neutral implementation” but not “verified with Authentik”, “Dex compatible”, “Keycloak compatible”, or “broadly interoperable”.
