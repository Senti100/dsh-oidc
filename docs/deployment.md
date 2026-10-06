# Install and operate DSH OIDC (Web, 0.2.0-rc.2)

This is a **source-checkout + local-tarball** installation guide. `@senti100/dsh-oidc` is not assumed to exist on npm. The public GitHub checkout includes the exact 0.2.0-rc.2 dependency-override fixture; the plugin tarball alone does not. Use a disposable DSH home first, then back up any real home and proxy configuration before repeating the process. Do not copy provider exports, session cookies, client secrets, or real subject IDs into a Git checkout or support ticket.

## Prerequisites and topology

- Node 22.19+ within Node 22, Corepack with pnpm 10.34.5, the DSH 0.2.0-rc.2 CLI and shipped `web` template, Caddy 2.10.2 (the acceptance version; validate other versions separately), a TLS certificate, and a reachable OIDC issuer with authorization-code + PKCE S256 support.
- A single loopback-bound DSH process/home behind the reverse proxy. The application shares **one operator authority** among all admitted identities; use one process/home per identity if isolation is needed.
- An HTTPS public origin with no HTTP path on which a browser could send DSH's native cookie. The Caddy example disables automatic redirects, but an HTTPS site declaration **does not close TCP/80**. Use an isolated IP/edge firewall or equivalent network boundary, and DNS-01 or operator-managed TLS certificates that do not need HTTP-01. Verify from outside the host that TCP/80 for that address is unavailable. When an IP is shared with HTTP sites, do **not** call it strictly HTTPS-only. The example's `Set-Cookie` rewrite protects newly minted native cookies, not cookies already stored without `Secure`.
- Public hostname must be the exact fixed `publicOrigin` and a DSH `--trusted-host` authority. The DSH listener must not be reachable directly from other machines.

## Build and create a separate compatible profile

Run from this checkout on the DSH host with a disposable `DSH_HOME` first. The commands below **do not** alter an existing `web` profile:

```sh
export DSH_HOME=/path/to/isolated-dsh-home
export COREPACK_HOME="$DSH_HOME/corepack"
export COREPACK_DEFAULT_TO_LATEST=0
npm ci --ignore-scripts
npm run check
# No global Corepack defaults or host trust changes.
test "$(corepack pnpm@10.34.5 --version)" = 10.34.5
corepack pnpm@10.34.5 --dir tests/fixtures/full-profile install --frozen-lockfile
export PATH="$PWD/tests/fixtures/full-profile/node_modules/.bin:$PATH"
# The flag initializes the shipped Web template and exits without opening a listener.
dsh --profile web-oidc --from-default-profile web --dump-config >/dev/null
# Install the exact 291-override compatibility fixture into the fresh profile.
python3 - "$DSH_HOME/profiles/web-oidc/package.json" <<'PY'
import json, pathlib, sys
profile = pathlib.Path(sys.argv[1])
fixture = json.loads(pathlib.Path('tests/fixtures/full-profile/package.json').read_text())
current = json.loads(profile.read_text())
if current['name'] != 'dsh-profile-web-oidc' or current.get('dependencies') or current.get('pnpm'):
    raise SystemExit('refusing nonempty or wrong profile')
overrides = fixture['pnpm']['overrides']
if len(overrides) != 291 or sum(n == '@deepseek-ai/dsh' or n.startswith('@deepseek-ai/dsh-') for n in overrides) != 278:
    raise SystemExit('override closure drift')
if overrides.get('@deepseek-ai/libreoffice-kit@0.1.2>fflate') != '0.8.3':
    raise SystemExit('missing Office remediation')
current['packageManager'] = 'pnpm@10.34.5'
current['pnpm'] = {'overrides': overrides}
profile.write_text(json.dumps(current, indent=2) + '\n')
profile.chmod(0o600)
PY
# Checks the actual CLI → Office → LibreOffice Kit → fflate resolution,
# installed management executable, and profile Corepack selection.
node scripts/attest-install.mjs tests/fixtures/full-profile "$DSH_HOME/profiles/web-oidc"
TARBALL="$(npm pack --silent)"
dsh plugin --profile web-oidc add --save-exact "file:$PWD/$TARBALL"
dsh plugin --profile web-oidc add --save-exact \
  @deepseek-ai/cordis@4.0.4 \
  @deepseek-ai/dsh-client-connection@0.2.0-rc.2 \
  @deepseek-ai/dsh-credentials@0.2.0-rc.2 \
  @deepseek-ai/dsh-host-webserver@0.2.0-rc.2
corepack pnpm@10.34.5 --dir "$DSH_HOME/profiles/web-oidc" install --frozen-lockfile
corepack pnpm@10.34.5 --dir "$DSH_HOME/profiles/web-oidc" audit --audit-level=low
node scripts/attest-install.mjs tests/fixtures/full-profile "$DSH_HOME/profiles/web-oidc"
# Preserve this generated profile manifest/lock together with the exact tarball.
# Fresh profile only: fail closed if a patch was already customized.
python3 - "$DSH_HOME/profiles/web-oidc/cordis.patch.yml" <<'PY'
import pathlib, sys
if [line.strip() for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')] != ['[]']:
    raise SystemExit('profile patch is not empty')
PY
install -m 600 examples/cordis.patch.yml "$DSH_HOME/profiles/web-oidc/cordis.patch.yml"
```

The override fixture is scoped to this pre-stable DSH release, **not** a general way to downgrade another working profile. Confirm the four exact effective peer versions and that DSH composes the `web-oidc` profile; if either fails, stop instead of editing your existing profile or bypassing the plugin's compatibility check. Keep the tarball available for subsequent profile operations; it is ignored by Git.

**Existing installations:** This source rename also changes the Cordis plugin ID. It does not upgrade a running profile automatically. If you installed a prior tarball, back up the profile and verify the replacement package, manifest, and patch together in a disposable home before planning an explicit migration and rollback. Do not apply this patch over an already-customized profile or assume the prior ID is interchangeable.

## Configure the OIDC provider and credentials

Create a confidential OIDC client at your provider with an **exact** redirect URI `https://dsh.example/auth/callback` (substitute your origin), authorization-code flow, and `openid profile email` scopes. Choose an explicit subject allowlist from the provider's `(issuer, sub)` identity; do not assume email alone gives stable identity. Bind admission at the provider **and** in `DSH_OIDC_ALLOWED_SUBJECTS`. The example reference `DSH_OIDC_CLIENT_SECRET_REF=DSH_OIDC_CLIENT_SECRET` names a credential, not its value. Never put its value in `.env.example`, the Cordis patch, command arguments, Caddy, or the Git repository. The [DSH credentials guide](https://deepseekdocs.com/en/docs/user-guide/credentials) documents credential-provider resolution; inherited process environment can supply the named reference.

**Do not copy `.env.example` to a DSH `.env` file.** DSH 0.2.0-rc.2 treats the entire `DSH_*` prefix as bootstrap-only and rejects it from both checkout and `$DSH_HOME/.env` (`@deepseek-ai/dsh-app-boot`'s `readEnvLayer`). Instead, use the example as a template for a restricted service-manager **process environment**. On a systemd deployment, create a private root-controlled `0600` `/etc/dsh-oidc/oidc.env` with the five non-secret settings from [`.env.example`](../.env.example), substituting issuer, client ID, origin, and one quoted JSON subject tuple. Supply `DSH_OIDC_CLIENT_SECRET` through your service secret manager or as an additional entry in that private file; never in the public example. An illustrative unit fragment (adapt user, paths, permissions, and binary location) is:

```ini
[Service]
User=dsh
Environment=DSH_HOME=/srv/dsh-home
EnvironmentFile=/etc/dsh-oidc/oidc.env
Environment=COREPACK_DEFAULT_TO_LATEST=0
Environment=COREPACK_HOME=/srv/dsh-home/corepack
Environment=PATH=/srv/dsh-candidate/tests/fixtures/full-profile/node_modules/.bin:/opt/node22/bin:/usr/bin:/bin
ExecStart=/srv/dsh-candidate/tests/fixtures/full-profile/node_modules/.bin/dsh --profile web-oidc --no-open --host 127.0.0.1 --port 3080 --trusted-host dsh.example
```

Systemd reads `EnvironmentFile` into the **inherited process environment**; this is different from DSH reading a `.env` layer. If using a container/orchestrator, inject the same keys as process environment from a restricted secret source. Process environment can be inspected by sufficiently privileged local principals; use a dedicated service user and appropriate host isolation. The issuer in each tuple must exactly match discovery, and the provider callback must exactly match `publicOrigin + /auth/callback`. A managed DSH credential record may supply the secret instead of the process variable if it is provisioned **before** the first login; do not assume an unauthenticated operator can reach a credential-setting UI. Never print resolved config or credential values to logs.

Start DSH with the launch environment and `dsh --profile web-oidc --no-open --host 127.0.0.1 --port 3080 --trusted-host dsh.example` (or the unit above). The public Cordis patch explicitly overrides **`web-runtime.config.printUrl: false`**; `--no-open` alone only suppresses opening a browser. Confirm that a disposable startup binds loopback without writing `/?token=` or another bearer bootstrap URL to service logs **before** exposing the proxy. If your DSH image lacks a working pnpm/Corepack toolchain, supply pinned pnpm in a separate reproducible derivative image rather than changing a serving profile in place.

## Proxy and browser acceptance

Adapt and validate [`examples/Caddyfile`](../examples/Caddyfile) against the Caddy binary and actual certificate/network layout before using it. Replace `dsh.example`, upstream port, and TLS provisioner. Its `auto_https disable_redirects` is a **process-global** choice; if joining an existing multi-site Caddyfile, reconcile the existing global block and other sites' redirect policies instead of pasting it wholesale. HSTS in this template applies only to the named host; enable `includeSubDomains` only after verifying you control and serve every relevant subdomain. The example:

- passes only five **exact** `/auth` routes to the plugin and rejects unmatched `/auth/*` routes;
- strips client-supplied identity and address headers, then gates every other path with `/auth/check`;
- removes `Connection`/`Upgrade` only on the auth pre-check (the application proxy still upgrades WebSockets);
- makes newly issued `dsh-auth-*` cookies `Secure`, including deletion and already-Secure cases, and redacts URL queries from access logs.

Keep a backup/rollback of the prior proxy configuration. Do not turn on public routing until DSH and the provider are ready. With no browser cookies, check `/` and `/api` return 401 to API clients and `/auth/not-registered` returns 404, and `HEAD /auth/login` is state-free. A browser navigation to any protected path is redirected to the bundled sign-in page `/auth/signin`; its Sign-in button starts OIDC at `/auth/login`. Either open `/auth/login` directly or follow that button in a real browser, then sign in, verify the clean DSH root, an API/workspace read and write, a native `dsh-auth-*` browser cookie marked **Secure**, and a successful `/api/remote.mux` WebSocket (no persistent “Reconnecting”). Finally use the logout confirmation and POST, then prove a stale native cookie cannot reach protected paths. A model catalog being empty or a model still loading does not by itself diagnose the WebSocket. Do not report browser acceptance based only on unauthenticated HTTP smoke.

## Rollback and limitations

Preserve the original DSH profile/home, image, and proxy configuration. On failure, restore the previous proxy and application pair together under the site's normal change control, verify its health, and leave the new profile disabled; do not delete the shared home or rotate the native signing key as a casual rollback. Restart of the plugin invalidates its memory-local OIDC sessions. Provider-side policy revocation is not immediate for an existing local session; it takes effect at idle/absolute expiry or restart. Logout removes the outer session, not necessarily the native cookie, so the proxy gate remains mandatory. An HTTP redirect, HSTS, or a `Secure` rewrite cannot retroactively prevent an already-stored non-`Secure` cookie from being sent on a first HTTP request.

The full-profile release gate (`DSH_OIDC_CADDY_BIN=/path/to/caddy-2.10.2 npm run test:acceptance:full-profile`) exercises a synthetic provider and real 0.2.0-rc.2 Web profile against the **shipped** Caddy recipe. The separate `npm run test:public-install` gate exercises the documented **`web-oidc`** installation and confirms startup does not print a bearer bootstrap URL; both run in CI. Neither certifies another Caddy version, your provider, your firewall, or a browser session in your environment.
