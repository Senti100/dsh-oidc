import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { Worker } from 'node:worker_threads'
import { readFile, writeFile, rm, mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { performance } from 'node:perf_hooks'

// ZIP64 discriminator retained from the independent candidate-review v3 repro.
// Resolve through the actual CLI Office bundle, not a test's direct fflate.
const rootRequire = createRequire(
  join(resolve(process.argv[2] ?? 'tests/fixtures/full-profile'), 'package.json'),
)
const dsh = createRequire(rootRequire.resolve('@deepseek-ai/dsh/package.json'))
const office = createRequire(dsh.resolve('@deepseek-ai/dsh-skill-office/package.json'))
const lib = dirname(office.resolve('@deepseek-ai/libreoffice-kit/package.json'))
const require = createRequire(join(lib, 'package.json'))
const { zipSync, strToU8, unzipSync } = require('fflate')
const valid = zipSync({ 'word/document.xml': strToU8('<document/>') }, { level: 0 })
let malformed = Buffer.from(valid)
const offset = malformed.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]))
assert.ok(offset >= 0)
malformed.writeUInt32LE(0xffffffff, offset + 20)
const originalEnd = malformed.length - 22
const zip64 = Buffer.alloc(56)
zip64.writeUInt32LE(0x06064b50, 0)
zip64.writeBigUInt64LE(44n, 4)
zip64.writeBigUInt64LE(1n, 24)
zip64.writeBigUInt64LE(1n, 32)
zip64.writeBigUInt64LE(BigInt(originalEnd - offset), 40)
zip64.writeBigUInt64LE(BigInt(offset), 48)
const locator = Buffer.alloc(20)
locator.writeUInt32LE(0x07064b50, 0)
locator.writeBigUInt64LE(BigInt(originalEnd), 8)
locator.writeUInt32LE(1, 16)
const end = Buffer.from(malformed.subarray(originalEnd))
end.writeUInt16LE(0xffff, 8)
end.writeUInt16LE(0xffff, 10)
end.writeUInt32LE(0xffffffff, 16)
malformed = Buffer.concat([malformed.subarray(0, originalEnd), zip64, locator, end])
console.log(
  JSON.stringify({
    fflate: JSON.parse(
      await readFile(join(dirname(require.resolve('fflate')), '../package.json'), 'utf8'),
    ).version,
    control: Object.keys(unzipSync(valid)),
    lib,
  }),
)
async function direct(bytes) {
  const w = new Worker(
    `const {parentPort,workerData}=require('node:worker_threads');const {unzipSync}=require(workerData.module);try{parentPort.postMessage({done:true,keys:Object.keys(unzipSync(workerData.bytes))})}catch(e){parentPort.postMessage({error:e.message})}`,
    { eval: true, workerData: { module: require.resolve('fflate'), bytes } },
  )
  let timer
  try {
    return await Promise.race([
      new Promise((resolve, reject) => {
        w.once('message', resolve)
        w.once('error', reject)
      }),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve({ timedOut: true }), 500)
      }),
    ])
  } finally {
    clearTimeout(timer)
    await w.terminate()
  }
}
const normal = await direct(valid)
const bad = await direct(malformed)
console.log('direct-valid', JSON.stringify(normal))
console.log('direct-malformed', JSON.stringify(bad))
assert.deepEqual(normal, { done: true, keys: ['word/document.xml'] })
assert.ok(bad.error, 'malformed ZIP64 must reject rather than wait for worker deadline')
assert.equal(bad.timedOut, undefined)
const { createConverter } = await import(pathToFileURL(join(lib, 'lib/index.js')).href)
const root = await mkdtemp(join(tmpdir(), 'dsh-office-control-'))
const converter = await createConverter({
  timeoutMs: 500,
  fontDirectories: [],
  fontMetadataCacheDirectory: false,
})
try {
  for (const [name, bytes] of [
    ['valid-zip-invalid-doc', valid],
    ['malformed-zip64', malformed],
  ]) {
    const inputPath = join(root, name + '.docx'),
      outputPath = join(root, name + '.pdf')
    await writeFile(inputPath, bytes)
    const start = performance.now()
    let failure
    try {
      await converter.render({ inputPath, outputPath })
    } catch (error) {
      failure = error
    }
    assert.ok(failure, 'invalid input unexpectedly converted')
    console.log(
      name,
      JSON.stringify({
        code: failure.code,
        message: failure.message,
        ms: Math.round(performance.now() - start),
      }),
    )
    assert.notEqual(failure.code, 'timeout', 'malformed input must not consume the worker deadline')
  }
} finally {
  await converter.dispose()
}
// A healthy OOXML document must still convert through the real native engine.
const docx = zipSync(
  Object.fromEntries(
    Object.entries({
      '[Content_Types].xml':
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
      '_rels/.rels':
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      'word/document.xml':
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic healthy Office control</w:t></w:r></w:p><w:sectPr/></w:body></w:document>',
    }).map(([name, text]) => [name, strToU8(text)]),
  ),
)
const healthy = await createConverter({
  timeoutMs: 30000,
  fontDirectories: process.env.DSH_OIDC_FONT_DIR ? [process.env.DSH_OIDC_FONT_DIR] : undefined,
  fontMetadataCacheDirectory: false,
})
try {
  const inputPath = join(root, 'healthy.docx'),
    outputPath = join(root, 'healthy.pdf')
  await writeFile(inputPath, docx)
  await healthy.render({ inputPath, outputPath })
  const pdf = await readFile(outputPath)
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-')
  console.log('healthy-docx-to-pdf', JSON.stringify({ bytes: pdf.length, header: '%PDF-' }))
} finally {
  await healthy.dispose()
  await rm(root, { recursive: true, force: true })
}
