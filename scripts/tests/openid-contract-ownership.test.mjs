// Flow contract: client-bound token, registration and device data use neutral Antifraud contracts without implying that typed or decoded metadata is authenticated.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const owned = new Set(['IAccessTokenClaims', 'DcrRegistrationRequest', 'DcrRegistrationResponse', 'OpenIdDeviceInfo'])

test('OpenID application-profile imports and re-exports do not use GDC contracts', async () => {
  const root = new URL('../../src/', import.meta.url)
  const violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      const importing = ts.isImportDeclaration(node)
      if (!(importing || ts.isExportDeclaration(node)) || !node.moduleSpecifier || !ts.isStringLiteralLike(node.moduleSpecifier) || !node.moduleSpecifier.text.startsWith('gdc-')) continue
      const bindings = importing ? node.importClause?.namedBindings : node.exportClause
      if (bindings && (ts.isNamedImports(bindings) || ts.isNamedExports(bindings))) {
        for (const item of bindings.elements) {
          const name = item.propertyName?.text ?? item.name.text
          if (owned.has(name)) violations.push(`${path}: ${name}`)
        }
      }
    }
  }
  assert.deepEqual(violations, [])
})
