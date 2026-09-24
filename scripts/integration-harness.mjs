import { execFileSync } from 'node:child_process'
import { accessSync, constants } from 'node:fs'

const caddy = process.env.DSH_OIDC_CADDY_BIN
if (caddy === undefined || caddy === '') {
  throw new Error(
    'REAL_STACK_BLOCKED: set DSH_OIDC_CADDY_BIN to an actual Caddy binary; a skipped harness is not a pass',
  )
}
accessSync(caddy, constants.X_OK)

const version = execFileSync(caddy, ['version'], { encoding: 'utf8' }).trim()
if (!/^v2\.10\.2(?:\s|$)/u.test(version)) {
  throw new Error(`REAL_STACK_BLOCKED: expected Caddy v2.10.2, observed ${version || '<empty>'}`)
}

// Parse the distributed reference configuration with Caddy itself before running
// the generated-port real reverse-proxy topology.
execFileSync(caddy, ['adapt', '--config', 'examples/Caddyfile', '--adapter', 'caddyfile'], {
  stdio: ['ignore', 'ignore', 'inherit'],
})
execFileSync(
  process.execPath,
  ['node_modules/vitest/vitest.mjs', 'run', '--config', 'tests/vitest.acceptance.config.ts'],
  { stdio: 'inherit', env: { ...process.env, DSH_OIDC_CADDY_BIN: caddy } },
)
console.log(`real DSH/Caddy acceptance passed with ${version}`)
