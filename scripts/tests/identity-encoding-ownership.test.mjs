// Flow contract: Gateway consumes neutral identifier encoding from Antifraud rather than the frozen library.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'

test('production source does not import frozen UUID or base58 helpers', async () => {
  const files = await readdir(new URL('../../src/', import.meta.url), { recursive: true })
  const violations = []
  for (const path of files.filter(path => path.endsWith('.ts') && !path.includes('__tests__'))) {
    const source = await readFile(new URL(`../../src/${path.replaceAll('\\', '/')}`, import.meta.url), 'utf8')
    if (/from\s*['"]gdc-common-utils-ts\/utils\/(?:multibase58|normalize-uuid)['"]/u.test(source)) violations.push(path)
    if (/import\s*\{[^}]*\bnormalizeUuid\b[^}]*\}\s*from\s*['"]gdc-common-utils-ts['"]/u.test(source)) violations.push(path)
  }
  assert.deepEqual(violations, [])
})
