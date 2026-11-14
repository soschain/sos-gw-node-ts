// Flow contract: healthcare role policy belongs to SOS Data; frozen imports and re-exports cannot provide it.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const owned = new Set(['HealthcareActorRoles', 'HealthcareActorRoleCodes', 'HealthcareAllRolesByClaim', 'HealthcareRoleFamilies', 'HealthcareRoleFamily', 'HealthcareActorRoleDescriptor', 'getHealthcareRoleByClaim', 'getHealthcareRolesByFamily', 'getHealthcareProfessionalRolesBySector', 'ISCO08_CODING_SYSTEM'])
test('imports and re-exports use the independent healthcare role owner', async () => {
  const root = new URL('../../src/', import.meta.url)
  const violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      if (!(ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) || !node.moduleSpecifier || !ts.isStringLiteralLike(node.moduleSpecifier) || !node.moduleSpecifier.text.startsWith('gdc-')) continue
      const bindings = ts.isImportDeclaration(node) ? node.importClause?.namedBindings : node.exportClause
      if (bindings && (ts.isNamedImports(bindings) || ts.isNamedExports(bindings))) for (const item of bindings.elements) {
        const name = item.propertyName?.text ?? item.name.text
        if (owned.has(name)) violations.push(`${path}: ${name}`)
      }
    }
  }
  assert.equal(violations.length, 0, violations.join('\n'))
})
