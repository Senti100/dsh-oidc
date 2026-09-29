import { execFileSync, spawnSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, resolve } from 'node:path'

import { attestInstall } from './attest-install.mjs'

const expectedCaddy = 'v2.10.2'
const expectedDsh = '0.2.0-rc.2'
const fixture = resolve('tests/fixtures/full-profile')
const corepack = process.env.DSH_OIDC_COREPACK_BIN ?? 'corepack'
const packageManager = 'pnpm@10.34.5'
const pnpmVersion = execFileSync(corepack, [packageManager, '--version'], {
  encoding: 'utf8',
}).trim()
if (pnpmVersion !== '10.34.5') throw new Error(`unexpected pnpm: ${pnpmVersion}`)
const caddy = process.env.DSH_OIDC_CADDY_BIN
if (caddy === undefined || caddy === '') {
  throw new Error(
    'FULL_PROFILE_BLOCKED: set DSH_OIDC_CADDY_BIN to the exact Caddy v2.10.2 binary; skip is not pass',
  )
}
const caddyVersionOutput = execFileSync(caddy, ['version'], { encoding: 'utf8' }).trim()
const caddyVersion = caddyVersionOutput.split(/\s+/u)[0] ?? ''
if (caddyVersion !== expectedCaddy) {
  throw new Error(
    `FULL_PROFILE_BLOCKED: expected ${expectedCaddy}, observed ${caddyVersionOutput || '<empty>'}`,
  )
}
execFileSync(caddy, ['adapt', '--config', 'examples/Caddyfile', '--adapter', 'caddyfile'], {
  stdio: ['ignore', 'ignore', 'inherit'],
})
if (!/^v22\.(?:19|2\d)\./u.test(process.version)) {
  throw new Error(`FULL_PROFILE_BLOCKED: Node >=22.19.0 <23 required, observed ${process.version}`)
}

const runRoot = mkdtempSync(join(tmpdir(), 'dsh-oidc-full-profile-'))
chmodSync(runRoot, 0o700)
const runtime = join(runRoot, 'runtime')
const artifacts = join(runRoot, 'artifacts')
const dshHome = join(runRoot, 'home')
mkdirSync(runtime, { mode: 0o700 })
mkdirSync(artifacts, { mode: 0o700 })

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    stdio: options.capture === true ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    env: options.env ?? process.env,
    maxBuffer: 32 * 1024 * 1024,
  })
}

function vitest(environment, expectFailure = false) {
  const result = spawnSync(
    process.execPath,
    ['node_modules/vitest/vitest.mjs', 'run', '--config', 'tests/vitest.acceptance.config.ts'],
    {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: environment,
      maxBuffer: 32 * 1024 * 1024,
    },
  )
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`
  if (expectFailure) {
    if (result.status === 0 || !output.includes('CONTROLLED_SETUP_FAILURE')) {
      throw new Error('controlled setup failure did not fail with its expected diagnostic')
    }
    if (output.includes('?token='))
      throw new Error('controlled failure output exposed a native token')
    return
  }
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? '')
    process.stderr.write(result.stderr ?? '')
    throw new Error(`full-profile acceptance failed with exit ${String(result.status)}`)
  }
  process.stdout.write(result.stdout ?? '')
  process.stderr.write(result.stderr ?? '')
}

try {
  run('npm', ['run', 'build'])
  const packed = JSON.parse(
    run('npm', ['pack', '--ignore-scripts', '--pack-destination', artifacts, '--json'], {
      capture: true,
    }),
  )
  if (!Array.isArray(packed) || packed.length !== 1 || typeof packed[0]?.filename !== 'string') {
    throw new Error('npm pack did not return one candidate tarball')
  }
  const candidateTarball = join(artifacts, basename(packed[0].filename))
  copyFileSync(join(fixture, 'package.json'), join(runtime, 'package.json'))
  copyFileSync(join(fixture, 'pnpm-lock.yaml'), join(runtime, 'pnpm-lock.yaml'))
  run(corepack, [packageManager, '--dir', runtime, 'install', '--frozen-lockfile'])

  const runtimeManifest = JSON.parse(readFileSync(join(runtime, 'package.json'), 'utf8'))
  const overrides = runtimeManifest.pnpm?.overrides ?? {}
  const overrideCount = Object.keys(overrides).filter(
    (name) => name === '@deepseek-ai/dsh' || name.startsWith('@deepseek-ai/dsh-'),
  ).length
  if (overrideCount !== 278) {
    throw new Error(
      `full-profile override closure changed: expected 278, observed ${String(overrideCount)}`,
    )
  }
  const environment = {
    ...process.env,
    DSH_HOME: dshHome,
    PATH: `${join(runtime, 'node_modules/.bin')}:${process.env.PATH ?? ''}`,
  }
  run(join(runtime, 'node_modules/.bin/dsh'), ['--profile', 'web', '--dump-config'], {
    env: environment,
    capture: true,
  })
  const profileManifestPath = join(dshHome, 'profiles/web/package.json')
  const profileManifest = JSON.parse(readFileSync(profileManifestPath, 'utf8'))
  profileManifest.packageManager = packageManager
  profileManifest.pnpm = { overrides: runtimeManifest.pnpm.overrides }
  writeFileSync(profileManifestPath, `${JSON.stringify(profileManifest, null, 2)}\n`, {
    mode: 0o600,
  })
  run(
    join(runtime, 'node_modules/.bin/dsh'),
    [
      'plugin',
      '--profile',
      'web',
      'add',
      '--save-exact',
      `file:${candidateTarball}`,
      '@deepseek-ai/cordis@4.0.4',
      '@deepseek-ai/dsh-client-connection@0.2.0-rc.2',
      '@deepseek-ai/dsh-credentials@0.2.0-rc.2',
      '@deepseek-ai/dsh-host-webserver@0.2.0-rc.2',
    ],
    { env: environment },
  )

  // A clean profile must replay its generated lock without a second resolution.
  rmSync(join(dshHome, 'profiles/web/node_modules'), { recursive: true, force: true })
  run(corepack, [
    packageManager,
    '--dir',
    join(dshHome, 'profiles/web'),
    'install',
    '--frozen-lockfile',
    '--offline',
  ])
  attestInstall(runtime, join(dshHome, 'profiles/web'))

  const testEnvironment = {
    ...environment,
    DSH_OIDC_CADDY_BIN: caddy,
    DSH_OIDC_CANDIDATE_TARBALL: candidateTarball,
    DSH_OIDC_FULL_PROFILE_RUN_ROOT: runRoot,
    DSH_OIDC_RUNTIME: runtime,
  }
  vitest(testEnvironment)
  vitest({ ...testEnvironment, DSH_OIDC_CONTROLLED_SETUP_FAILURE: '1' }, true)
  const residue = ['stack', 'failure-stack'].filter((name) => existsSync(join(runRoot, name)))
  if (residue.length !== 0)
    throw new Error(`acceptance stack residue remained: ${residue.join(', ')}`)
  console.log(
    `full-profile acceptance passed: DSH ${expectedDsh}; overrides=${String(overrideCount)}; packed plugin loaded; browser scenarios=6; failure cleanup=pass; ${caddyVersionOutput}`,
  )
} finally {
  rmSync(runRoot, { recursive: true, force: true })
  if (existsSync(runRoot)) throw new Error('full-profile run root cleanup failed')
}
