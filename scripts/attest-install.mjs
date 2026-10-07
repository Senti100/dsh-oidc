import { execFileSync } from 'node:child_process'
import { readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'

// Bundled Web/Office packages resolve from the CLI installation, not necessarily
// the profile. A profile-only override cannot repair an unsafe CLI installation.
export function attestInstall(runtime, profile) {
  const root = createRequire(join(resolve(runtime), 'package.json'))
  const dsh = createRequire(root.resolve('@deepseek-ai/dsh/package.json'))
  const office = createRequire(dsh.resolve('@deepseek-ai/dsh-skill-office/package.json'))
  const kitPath = office.resolve('@deepseek-ai/libreoffice-kit/package.json')
  const kit = createRequire(kitPath)
  const fflatePath = join(dirname(kit.resolve('fflate')), '../package.json')
  const version = JSON.parse(readFileSync(fflatePath, 'utf8')).version
  if (version !== '0.8.3') throw new Error(`Office runtime fflate mismatch: ${version}`)
  const pnpmPath = join(dirname(root.resolve('pnpm')), 'bin/pnpm.cjs')
  const pnpm = execFileSync(process.execPath, [pnpmPath, '--version'], {
    encoding: 'utf8',
  }).trim()
  if (pnpm !== '10.34.5') throw new Error(`installed pnpm mismatch: ${pnpm}`)
  if (profile !== undefined) {
    const manifest = JSON.parse(readFileSync(join(profile, 'package.json'), 'utf8'))
    if (manifest.packageManager !== 'pnpm@10.34.5') throw new Error('profile manager drift')
    if (manifest.pnpm?.overrides?.['@deepseek-ai/libreoffice-kit@0.1.2>fflate'] !== '0.8.3') {
      throw new Error('profile Office override missing')
    }
    const effective = execFileSync(
      process.env.DSH_OIDC_COREPACK_BIN ?? 'corepack',
      ['pnpm', '--version'],
      {
        cwd: profile,
        encoding: 'utf8',
      },
    ).trim()
    if (effective !== '10.34.5') throw new Error(`profile Corepack mismatch: ${effective}`)
  }
  console.log(
    JSON.stringify({
      pnpm,
      fflate: version,
      kit: realpathSync(kitPath),
      fflatePath: realpathSync(fflatePath),
    }),
  )
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  if (!process.argv[2]) throw new Error('usage: node scripts/attest-install.mjs RUNTIME [PROFILE]')
  attestInstall(process.argv[2], process.argv[3])
}
