// Flow contract: Gateway does not declare or configure the unused frozen SDK client as a source or test dependency.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

test('removes the unused frozen SDK client from declarations and module-resolution configuration', async () => {
  for (const path of ['package.json', 'jest.config.ts', 'tsconfig.jest.json', 'scripts/patch-esm-imports.mjs']) {
    const source = await readFile(new URL(`../../${path}`, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /gdc-sdk-client-ts/u, path)
  }
})
