import { execFileSync } from 'node:child_process'
import { chmodSync, lstatSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Pin the exact distributable inventory, including the synthetic environment
// example and the external deployment guide alongside the runtime declarations.
const expectedFiles = [
  '.env.example',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'THIRD_PARTY_NOTICES.md',
  'dist/admission.d.ts',
  'dist/compatibility.d.ts',
  'dist/config.d.ts',
  'dist/index.d.ts',
  'dist/index.js',
  'dist/index.js.map',
  'dist/oidc.d.ts',
  'dist/policy.d.ts',
  'dist/state.d.ts',
  'docs/deployment.md',
  'docs/interoperability.md',
  'docs/threat-model.md',
  'examples/Caddyfile',
  'examples/cordis.patch.yml',
  'package.json',
]

const temporary = mkdtempSync(join(tmpdir(), 'dsh-oidc-pack-'))
chmodSync(temporary, 0o700)
try {
  const output = execFileSync('npm', ['pack', '--json', '--pack-destination', temporary], {
    encoding: 'utf8',
  })
  const [result] = JSON.parse(output)
  if (result === undefined) throw new Error('npm pack returned no result')
  const actualFiles = result.files.map(({ path }) => path).sort()
  if (JSON.stringify(actualFiles) !== JSON.stringify([...expectedFiles].sort())) {
    throw new Error(
      `packed inventory mismatch: expected=${String(expectedFiles.length)} actual=${String(actualFiles.length)}`,
    )
  }
  if (result.entryCount !== expectedFiles.length)
    throw new Error(`packed entry count mismatch: ${String(result.entryCount)}`)

  const tarball = join(temporary, result.filename)
  const archiveEntries = execFileSync('tar', ['-tzf', tarball], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .filter((entry) => entry !== '' && !entry.endsWith('/'))
  const expectedEntries = expectedFiles.map((path) => `package/${path}`).sort()
  if (JSON.stringify(archiveEntries.sort()) !== JSON.stringify(expectedEntries))
    throw new Error('tarball paths do not match the pinned package inventory')

  const extracted = join(temporary, 'extracted')
  execFileSync('mkdir', ['-m', '0700', extracted])
  execFileSync('tar', [
    '-xzf',
    tarball,
    '--no-same-owner',
    '--no-same-permissions',
    '-C',
    extracted,
  ])
  for (const path of expectedFiles) {
    const status = lstatSync(join(extracted, 'package', path))
    if (!status.isFile() || status.isSymbolicLink()) throw new Error(`unsafe packed entry: ${path}`)
  }
  const manifest = JSON.parse(readFileSync(join(extracted, 'package/package.json'), 'utf8'))
  if (manifest.exports?.['.']?.default !== './dist/index.js')
    throw new Error('packed default export does not point to dist/index.js')
  if (manifest.exports?.['.']?.types !== './dist/index.d.ts')
    throw new Error('packed type export does not point to dist/index.d.ts')
  if (manifest.exports?.['./client'] !== undefined)
    throw new Error('Host-only package unexpectedly exports a client entry')

  console.log(`package inventory and extraction ok: ${String(expectedFiles.length)} files`)
} finally {
  rmSync(temporary, { recursive: true, force: true })
}
