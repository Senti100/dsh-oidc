import { execFileSync } from 'node:child_process'
import { chmodSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'

const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{20,}\b/u,
  /client_secret\s*[:=]\s*["'][^"']{8,}["']/iu,
  /\b(?:sso|dsh)\.[a-z0-9-]+\.com\b/iu,
]

function scan(path, label) {
  const text = readFileSync(path, 'utf8')
  for (const pattern of patterns) {
    if (pattern.test(text)) throw new Error(`possible secret or deployment identifier in ${label}`)
  }
}

function regularFiles(root) {
  const files = []
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`secret scan refuses symlink: ${path}`)
      if (entry.isDirectory()) visit(path)
      else if (entry.isFile()) files.push(path)
      else throw new Error(`secret scan refuses special file: ${path}`)
    }
  }
  visit(root)
  return files
}

const tracked = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
  encoding: 'utf8',
})
  .trim()
  .split('\n')
  .filter(Boolean)

// package-lock.json is scanned deliberately. Its registry URLs, integrity hashes,
// and package metadata are not secrets; no blanket lockfile exemption exists.
for (const path of tracked) scan(path, path)
for (const path of regularFiles('dist')) scan(path, path)

const temporary = mkdtempSync(join(tmpdir(), 'dsh-oidc-secret-scan-'))
chmodSync(temporary, 0o700)
try {
  const output = execFileSync('npm', ['pack', '--json', '--pack-destination', temporary], {
    encoding: 'utf8',
  })
  const [result] = JSON.parse(output)
  if (result === undefined) throw new Error('npm pack returned no result')
  const tarball = join(temporary, result.filename)
  const entries = execFileSync('tar', ['-tzf', tarball], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .filter(Boolean)
  if (entries.some((entry) => entry.startsWith('/') || entry.split('/').includes('..')))
    throw new Error('unsafe tarball path')
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
  for (const path of regularFiles(extracted)) {
    if (!lstatSync(path).isFile()) throw new Error(`unsafe extracted entry: ${path}`)
    scan(path, `tarball:${relative(extracted, path)}`)
  }
  console.log(
    `secret scan ok: tracked=${String(tracked.length)} dist=${String(regularFiles('dist').length)} packed=${String(result.files.length)}`,
  )
} finally {
  rmSync(temporary, { recursive: true, force: true })
}
