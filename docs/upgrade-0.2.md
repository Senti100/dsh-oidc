# Isolated compatibility candidate: DSH 0.2.0-rc.2

This is a **new exact-version candidate**, not an in-place updater or production approval. Plugin `0.2.0-alpha.0` requires Cordis **4.0.4** and DSH connection/credentials/webserver **0.2.0-rc.2**. It deliberately rejects the old 4.0.2 / 0.1.5-rc.1 peers, mixed graphs, and unreadable metadata. Do not relax the check to a semver range. Authentication, policy, transaction/session, and logout implementation are unchanged.

## Inspected upstream contract

Compare upstream tag `dsh-v0.1.5-rc.1` (`183f08e9c6dde7e36cd2318eaee70b0da08fb35e`) with `dsh-v0.2.0-rc.2` (`639ed015397290b3745d163aafe02ffee4aa3f84`) in [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness). The checked-in seam fixture records that comparison; it is not a substitute for executing acceptance.

- `packages/client/connection/src/browser-auth.ts`: `authenticatedUrl()` now preserves the caller's path, query, and fragment rather than clearing them. Our existing validated HTTPS `publicOrigin` permits only the clean root, so no incoming URL or callback parameter is forwarded. Native token exchange now sends relative `Location: ./` rather than `/`; the browser gate proves it lands on the clean root.
- `packages/client/connection/src/rpc-host.ts` and `rpc.ts`: `admit(request)` returns `PeerAdmission` for the shared operator after the existing Host/Origin fence and signed-cookie authentication. It does not implement external identity admission or per-user isolation.
- `packages/client/connection/src/index.ts`: new `connection/request` waterfall wraps authenticated shared-API HTTP requests. It is **not** a universal authentication hook: it runs after native admission and does not cover the frontend, all exact routes, or the WebSocket upgrade. We intentionally retain the native Connection and mandatory outer Caddy gate rather than using this incomplete seam as an OIDC replacement.
- `packages/api/gateway/src/index.ts`: WebSocket mux registration waits for application readiness and calls `connection.admit`; peer/uplink transport internals changed. Real authenticated and denied browser upgrades are therefore a required gate, not inferred from successful TypeScript compilation.
- `packages/host/webserver/src/index.ts`: exact-route registration/disposal remains compatible; multipart compression support changed. `CredentialProvider.resolve` remains compatible. New upstream account-platform services are not this plugin's OIDC authentication.
- `packages/bundle/web-app/src/index.ts`: startup audits now precede URL readiness. The public `web-runtime.config.printUrl: false` setting still suppresses bearer startup URLs; the separate-profile smoke verifies it.
- Cordis is 4.0.4 and Schemastery is 3.18.4. The pinned fixture includes 278 DSH packages and 12 supporting scoped package overrides (290 total), derived by traversing dependency, optional-dependency, and peer-dependency edges from the upstream CLI manifest at the target commit. Only the installed closure is runtime-attested; an override is not proof a package was loaded.

## Clean dependency tree is mandatory

Never reuse or copy `node_modules`, a profile package symlink farm, or the old generated profile lock. A real incremental lock update retained old 0.1.5-rc.1 peer contexts despite new overrides; regeneration in an empty fixture directory eliminated them. The committed lock was generated cleanly and the acceptance runner always installs it into a new temporary runtime and DSH home.

For ordinary reproduction, use the committed locks, not another resolution:

```sh
npm ci --ignore-scripts
corepack pnpm --dir tests/fixtures/full-profile install --frozen-lockfile
tests/fixtures/full-profile/node_modules/.bin/playwright install chromium
npm run check
DSH_OIDC_CADDY_BIN=/path/to/caddy-2.10.2 npm run test:acceptance:full-profile
PYTHONOPTIMIZE=1 npm run test:public-install
```

Node 22.19+ within Node 22, pnpm 10.18.3, and Caddy 2.10.2 are the certified lane. The runtime fixture's plain-dependency/no-`dsh.bundle` warnings are expected because the explicit Cordis patch mounts the plugin. Profile peer warnings for scope/invariants are supplied by the exact CLI runtime and are checked by the complete runtime closure gate; do not install a second unreviewed core graph to silence them. Native build scripts blocked by pnpm are not automatically authorized; this gate does not certify terminal/native-addon functionality or model execution.

The target release was published on 2026-09-29. An isolated test of this specifically requested prerelease is not a waiver of the normal dependency-age/review gate for production deployment. Preserve the exact locks and package integrity hashes; do not silently refresh to newer releases.

## Upgrade staging and rollback

1. Record the incumbent source commit, immutable image digest, process command, profile patch, dependency manifests/locks, and the exact proxy config hash in a **private** operator receipt. Preserve a stopped-consistent backup of the entire DSH home and the old image/tarball. Provider secrets and user data must never enter this repository.
2. Build/pack this candidate from the reviewed commit. Record SHA-256 of the tarball plus both committed locks. Follow [deployment.md](deployment.md) in a **new empty home**, with its fixture CLI on PATH; never run a global unpinned `dsh` against the incumbent home. Initialize a fresh `web-oidc` profile and use the candidate's exact overrides. Do not migrate session/storage data as part of compatibility testing.
3. Run synthetic acceptance first. The harness uses a local synthetic issuer, temporary homes, a loopback-only Caddy listener, isolated CA files (no system trust installation), and Chromium. It verifies denied identities, native/OIDC cookie properties, clean bootstrap redirect, API/upload owners, WebSocket admission, logout/replayed cookies, live unload, and cleanup including controlled setup failure. The install smoke separately proves hidden startup URLs.
4. Stop here for independent review. Real-provider browser acceptance, incumbent-data migration and restore rehearsal, the actual deployment Caddy version, platform/native-addon checks, and a separately approved cutover remain gates. A local green candidate never authorizes provider edits, publication, or production changes.
5. If staging fails, stop only the isolated candidate and keep the incumbent untouched. For a **later separately approved** cutover, roll back by switching back to the recorded old application **and its preserved home/profile** plus the matching reviewed proxy configuration. Never point the old binary at a home the newer release has migrated. Do not remove the mandatory OIDC proxy gate while leaving a newly issued native cookie usable. Verify old health, admission denial and authenticated browser operation after rollback.

The prior public source is pinned at `94d4bfd4b36558dcbf1ccc807cd4905d2bf48c6e` (plugin 0.1.0-alpha.0 / DSH 0.1.5-rc.1). It is a source rollback reference, **not necessarily the tarball/ID installed by an operator**. Retain the actual incumbent deployment artifact separately; a renamed public package is not an interchangeable production rollback.

## Limits retained

Caddy still secures newly minted native cookies and gates every application owner. Existing non-Secure cookies are not retroactively repaired; shared TCP/80 does not become strictly HTTPS-only. Logout denies subsequent requests/upgrades but does not terminate a WebSocket already established before logout. All allowed identities share the process operator. Synthetic-provider success does not certify a real provider or production browser session.

## Dependency audit hold

The plugin's full and production-only npm audits report no vulnerabilities at candidate preparation. A separate audit of the complete test/runtime fixture is **not green**: it reports 28 advisories (15 high, 13 moderate). These include the inherited pinned pnpm 10.18.3 and Playwright 1.55.0 tools, plus `fflate` 0.8.2 under upstream DSH's `dsh-skill-office → libreoffice-kit` dependency (GHSA-px8p-9vwx-vf98). This lane does not silently replace upstream/tooling pins or claim these advisories are harmless. A separately reviewed tooling/runtime dependency remediation and fresh acceptance is required before treating the whole stack as release-ready. No vulnerable-archive or untrusted-repository payload is part of these synthetic tests.
