# Security policy

## Reporting

Report suspected vulnerabilities privately to the repository maintainers. Do not include production credentials, tokens, cookies, identity claims, or deployment logs in a public issue.

## Deployment requirements

- Keep DSH bound to `127.0.0.1`; only the HTTPS reverse proxy may reach it.
- Guard every path except the four exact registered OIDC endpoints with `/auth/check`, including static files, `/api`, WebSocket, and streaming paths. Deny unmatched `/auth/*` and strip `Connection`/`Upgrade` **only on the auth pre-check**, not the application WebSocket proxy.
- For DSH 0.1.5-rc.1, mark newly issued native `dsh-auth-*` cookies `Secure` at the TLS proxy; test multiple `Set-Cookie` headers, deletion, and an already-Secure value. This is not retroactive for cookies already in browsers.
- Preserve the public Host header, strip client-supplied proxy/identity headers, disable query-string access logging, and configure DSH Connection `trustedHosts` with the public authority.
- Disable DSH URL printing/browser opening. The native bootstrap URL temporarily contains a bearer query token.
- For strict HTTPS-only security, serve the DSH address only on HTTPS and keep TCP/80 unreachable at the network edge; HSTS or HTTP-to-HTTPS redirects do not prevent an old non-`Secure` cookie from being sent on a first HTTP request. A shared IP with other HTTP sites does **not** meet this stronger guarantee. See [deployment options](docs/deployment.md).
- Configure only `clientSecretRef` in the Cordis patch. Keep the actual client secret in a supported DSH credential provider or inherited process environment supplied by a restricted service manager; never put `DSH_*` bootstrap variables in `$DSH_HOME/.env` or commit a real EnvironmentFile. See [deployment options](docs/deployment.md).

Local OIDC sessions are memory-only. Restart and logout invalidate them, but DSH's native cookie cannot be individually revoked in 0.1.5-rc.1; the mandatory proxy gate supplies revocation. Provider-side account or group changes take effect no later than local idle/absolute expiry unless the process is restarted sooner.

All admitted identities share one DSH operator authority. This package is admission control, not per-user authorization.
