// Flow contract: SOS release entry points cannot mutate sibling projects or publish this private service.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

test('retired release-chain entry point stops before any package mutation', async () => {
  const source = await readFile(new URL('../release-chain.sh', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /npm\s+(?:version|install|publish)\b/u)
  assert.doesNotMatch(source, /(?:pushd|cd)\s+["']?\$\{?(?:WORKSPACE|COMMON_UTILS|SDK)_/u)
  assert.match(source, /exit 1\s*$/u)
  assert.match(source, /retired/iu)
})

test('Gateway governance preserves frozen-project and independent ownership boundaries', async () => {
  const source = await readFile(new URL('../../AGENTS.md', import.meta.url), 'utf8')
  assert.match(source, /SOS must never import, depend on, wrap or re-export GDC/u)
  assert.match(source, /Every GDC mutation requires explicit user approval/u)
  assert.match(source, /Cross-sector ISCO belongs in `antifraud-data-utils-ts`/u)
  assert.doesNotMatch(source, /must consume shared policy from\s*`gdc-common-utils-ts`/u)
})
