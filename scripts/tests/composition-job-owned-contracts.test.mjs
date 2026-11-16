// Flow contract: Communication uses the canonical FHIR composition converter and host Offer/Order uses the SOS confidential-job type, preserving the existing conversion and request boundaries.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

test('Communication composition conversion imports its canonical FHIR owner', async () => {
  const text = await readFile(new URL('../../src/managers/CommunicationManager.ts', import.meta.url), 'utf8')
  const source = ts.createSourceFile('CommunicationManager.ts', text, ts.ScriptTarget.Latest, true)
  const owners = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement)) continue
    const bindings = statement.importClause?.namedBindings
    if (!bindings || !ts.isNamedImports(bindings)) continue
    for (const binding of bindings.elements) {
      if ((binding.propertyName?.text ?? binding.name.text) === 'compositionFhirR4ToFlat') owners.push(statement.moduleSpecifier.text)
    }
  }
  assert.deepEqual(owners, ['fhir-data-utils-ts'])
})

test('host Offer/Order inline request type uses the existing SOS job contract', async () => {
  const text = await readFile(new URL('../../src/managers/hosting/HostingOfferOrderService.ts', import.meta.url), 'utf8')
  const source = ts.createSourceFile('HostingOfferOrderService.ts', text, ts.ScriptTarget.Latest, true)
  const owners = []
  function visit(node) {
    if (ts.isImportTypeNode(node) && node.qualifier?.getText(source) === 'JobRequest') owners.push(node.argument.literal.text)
    ts.forEachChild(node, visit)
  }
  visit(source)
  assert.deepEqual(owners, ['sos-data-utils-ts/confidential-job'])
})
