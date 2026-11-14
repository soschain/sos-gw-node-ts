// Flow contract: person, organization, service, action and commerce flat claim catalogs come from their neutral Antifraud owner; importing a legacy catalog from GDC is rejected even in fixtures and re-exports.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const migrated = new Set(['ClaimsPersonSchemaorg', 'ClaimsOrganizationSchemaorg', 'ClaimsServiceSchemaorg', 'ClaimsActionSchemaorg', 'ClaimsOfferSchemaorg', 'ClaimsOrderSchemaorg', 'ClaimsIndividualProductSchemaorg'])
test('neutral identity and commerce catalogs never import or re-export GDC', async () => {
  const root = new URL('../../src/', import.meta.url), violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      const importing = ts.isImportDeclaration(node)
      if (!(importing || ts.isExportDeclaration(node)) || !node.moduleSpecifier || !ts.isStringLiteralLike(node.moduleSpecifier) || !node.moduleSpecifier.text.startsWith('gdc-')) continue
      const bindings = importing ? node.importClause?.namedBindings : node.exportClause
      if (bindings && (ts.isNamedImports(bindings) || ts.isNamedExports(bindings))) for (const binding of bindings.elements) {
        const name = binding.propertyName?.text ?? binding.name.text
        if (migrated.has(name)) violations.push(`${path}: ${name}`)
      }
    }
  }
  assert.deepEqual(violations, [])
})
