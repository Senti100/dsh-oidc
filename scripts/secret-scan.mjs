import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
  encoding: 'utf8',
})
  .trim()
  .split('\n')
  .filter(Boolean)
  .filter((path) => !path.endsWith('package-lock.json'))
const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{20,}\b/u,
  /client_secret\s*[:=]\s*["'][^"']{8,}["']/iu,
  /\b(?:sso|dsh)\.[a-z0-9-]+\.com\b/iu,
]
for (const file of files) {
  const text = readFileSync(file, 'utf8')
  for (const pattern of patterns) {
    if (pattern.test(text)) throw new Error(`possible secret or deployment identifier in ${file}`)
  }
}
console.log(`secret scan ok: ${String(files.length)} files`)
