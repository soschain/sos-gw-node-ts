// Flow contract: persisted service-capability parsing imports the independent SOS owner, including test fixtures and re-exports.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

test('service-capability contracts never import or re-export a GDC implementation', async () => {
  const root = new URL('../../src/', import.meta.url)
  const violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      if (!(ts.isImportDeclaration(node) || ts.isExportDeclaration(node))) continue
      const module = node.moduleSpecifier
      if (module && ts.isStringLiteralLike(module) && module.text.startsWith('gdc-') && module.text.includes('service-capabilities')) violations.push(path)
    }
  }
  assert.deepEqual(violations, [])
})
