# Security policy

## Reporting

Report suspected vulnerabilities privately to the repository maintainers. Do not include production credentials, tokens, cookies, identity claims, or deployment logs in a public issue.

## Deployment requirements

- Keep DSH bound to `127.0.0.1`; only the HTTPS reverse proxy may reach it.
- Guard every non-`/auth/*` path with `/auth/check`, including static files, `/api`, WebSocket, and streaming paths.
- Preserve the public Host header, strip client-supplied proxy/identity headers, disable query-string access logging, and configure DSH Connection `trustedHosts` with the public authority.
- Disable DSH URL printing/browser opening. The native bootstrap URL temporarily contains a bearer query token.
- Serve the hostname only over HTTPS with HSTS; do not expose an HTTP listener for it.
- Store the client secret in the DSH credential provider and configure only `clientSecretRef`.

Local OIDC sessions are memory-only. Restart and logout invalidate them, but DSH's native cookie cannot be individually revoked in 0.1.5-rc.1; the mandatory proxy gate supplies revocation. Provider-side account or group changes take effect no later than local idle/absolute expiry unless the process is restarted sooner.

All admitted identities share one DSH operator authority. This package is admission control, not per-user authorization.
