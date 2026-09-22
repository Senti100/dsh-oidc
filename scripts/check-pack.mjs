import { execFileSync } from 'node:child_process'
import { rmSync } from 'node:fs'

const output = execFileSync('npm', ['pack', '--json'], { encoding: 'utf8' })
const [result] = JSON.parse(output)
if (result === undefined) throw new Error('npm pack returned no result')
const allowedRoots = new Set([
  'package.json',
  'README.md',
  'SECURITY.md',
  'LICENSE',
  'THIRD_PARTY_NOTICES.md',
])
const forbidden = result.files.filter(
  ({ path }) =>
    !allowedRoots.has(path) &&
    !path.startsWith('dist/') &&
    !path.startsWith('docs/') &&
    !path.startsWith('examples/'),
)
if (forbidden.length > 0)
  throw new Error(`unexpected packed files: ${forbidden.map(({ path }) => path).join(', ')}`)
const required = [
  'dist/index.js',
  'dist/index.d.ts',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'THIRD_PARTY_NOTICES.md',
]
for (const path of required)
  if (!result.files.some((file) => file.path === path))
    throw new Error(`packed file missing: ${path}`)
if (result.files.some(({ path }) => path.endsWith('.env') || path.includes('node_modules')))
  throw new Error('package contains private/generated material')
rmSync(result.filename)
console.log(`package inventory ok: ${String(result.files.length)} files`)
