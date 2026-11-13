// Flow contract: Gateway consumes canonical clinical resource and claim vocabularies from FHIR data utilities.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const canonicalNames = new Set([
  'ResourceTypesFhirR4', 'ResourceTypesFhirR5', 'FhirDataTypes',
  'ClaimConsent', 'ConsentDecisions', 'ConsentStatuses',
  'CompositionClaim', 'CompositionAttesterModes', 'CommunicationClaim',
  'RelatedPersonClaim', 'TaskClaimsFhirApi',
])

test('production FHIR vocabularies have their canonical package owner', async () => {
  const root = new URL('../../src/', import.meta.url)
  const files = await readdir(root, { recursive: true })
  const violations = []
  for (const path of files.filter(path => path.endsWith('.ts') && !path.includes('__tests__'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const statement of source.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue
      const bindings = statement.importClause?.namedBindings
      if (!statement.moduleSpecifier.text.startsWith('gdc-') || !bindings || !ts.isNamedImports(bindings)) continue
      for (const binding of bindings.elements) {
        const name = binding.propertyName?.text ?? binding.name.text
        if (canonicalNames.has(name)) violations.push(`${path}: ${name}`)
      }
    }
  }
  assert.equal(violations.length, 0, violations.join('\n'))
})
