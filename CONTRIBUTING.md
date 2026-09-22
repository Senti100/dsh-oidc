# Contributing

Use Node 22.19 or newer in the Node 22 line. Install with `npm ci` and run `npm run check` before proposing a change.

Security behavior requires negative tests. Changes to OIDC, cookies, policy, sessions, CSRF, routes, credentials, DSH versions, or proxy examples must add fail-closed coverage and update the README/SECURITY documentation. Never add live secrets, real client IDs, subject IDs, group names, provider exports, or deployment hostnames.

Keep the native DSH Connection row intact. A future DSH version adapter must be explicit and independently tested; do not silently probe private internals.
