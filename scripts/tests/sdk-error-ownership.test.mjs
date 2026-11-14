// Flow contract: Gateway and its tests use the SOS operational error class rather than a frozen runtime implementation.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

test('runtime operational errors and status policy have the SOS SDK owner', async () => {
  const root = new URL('../../src/', import.meta.url)
  const files = await readdir(root, { recursive: true })
  const violations = []
  for (const path of files.filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const statement of source.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue
      const bindings = statement.importClause?.namedBindings
      if (!statement.moduleSpecifier.text.startsWith('gdc-') || !bindings || !ts.isNamedImports(bindings)) continue
      for (const binding of bindings.elements) {
        const name = binding.propertyName?.text ?? binding.name.text
        if (name === 'ManagerError' || name === 'IssueTypeToHttpStatus') violations.push(`${path}: ${name}`)
      }
    }
  }
  assert.equal(violations.length, 0, violations.join('\n'))
})
