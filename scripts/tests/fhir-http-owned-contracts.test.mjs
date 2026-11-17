// Flow contract: FHIR code-system identifiers use their canonical owner; search responses stringify registered SOS HTTP status values without importing example data into runtime.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { AppointmentClaimsFhirApi, AppointmentStatus, FhirCodeSystems } from 'fhir-data-utils-ts'
import { HttpStatusCodes } from 'sos-data-utils-ts/bff-wire-contract'
import ts from 'typescript'

test('the shared FHIR code-system export uses its canonical owner', async () => {
  const text = await readFile(new URL('../../src/shared/healthcare-constants.ts', import.meta.url), 'utf8')
  const source = ts.createSourceFile('healthcare-constants.ts', text, ts.ScriptTarget.Latest, true)
  const owners = []
  for (const statement of source.statements) {
    if (!ts.isExportDeclaration(statement) || !statement.exportClause || !ts.isNamedExports(statement.exportClause)) continue
    for (const binding of statement.exportClause.elements) {
      if ((binding.propertyName?.text ?? binding.name.text) === 'FhirCodeSystems') owners.push(statement.moduleSpecifier.text)
    }
  }
  assert.deepEqual(owners, ['fhir-data-utils-ts'])
})

test('search responses use registered HTTP status data instead of legacy examples', async () => {
  const text = await readFile(new URL('../../src/utils/didcomm-response.ts', import.meta.url), 'utf8')
  const source = ts.createSourceFile('didcomm-response.ts', text, ts.ScriptTarget.Latest, true)
  const owners = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement)) continue
    assert.ok(!statement.moduleSpecifier.text.startsWith('gdc-'), 'response runtime still loads a GDC example package')
    const bindings = statement.importClause?.namedBindings
    if (!bindings || !ts.isNamedImports(bindings)) continue
    for (const binding of bindings.elements) {
      if ((binding.propertyName?.text ?? binding.name.text) === 'HttpStatusCodes') owners.push(statement.moduleSpecifier.text)
    }
  }
  assert.deepEqual(owners, ['sos-data-utils-ts/bff-wire-contract'])
})

test('existing code-system and successful response wire values stay exact', () => {
  assert.equal(Object.isFrozen(FhirCodeSystems), true)
  assert.deepEqual(Object.fromEntries(['Loinc', 'SnomedCt', 'Ucum', 'CommunicationCategory', 'ActReason', 'ObservationCategory', 'EventTiming'].map(key => [key, FhirCodeSystems[key]])), {
    Loinc: 'http://loinc.org',
    SnomedCt: 'http://snomed.info/sct',
    Ucum: 'http://unitsofmeasure.org',
    CommunicationCategory: 'http://terminology.hl7.org/CodeSystem/communication-category',
    ActReason: 'http://terminology.hl7.org/CodeSystem/v3-ActReason',
    ObservationCategory: 'http://terminology.hl7.org/CodeSystem/observation-category',
    EventTiming: 'http://hl7.org/fhir/event-timing',
  })
  assert.equal(String(HttpStatusCodes.Ok), '200')
})

test('private clinical claim files do not forward the legacy complete catalog', async () => {
  for (const name of ['Appointment', 'AppointmentResponse', 'MedicationStatement']) {
    const url = new URL(`../../src/gdc-backend-utils-node/models/fhir/${name}.claims.ts`, import.meta.url)
    const text = await readFile(url, 'utf8').catch(error => {
      if (error.code === 'ENOENT') return ''
      throw error
    })
    assert.ok(!text.includes('gdc-common-utils-ts'), `${name} still forwards GDC claims`)
  }
  const text = await readFile(new URL('../../src/__tests__/data/appointment.data.ts', import.meta.url), 'utf8')
  const source = ts.createSourceFile('appointment.data.ts', text, ts.ScriptTarget.Latest, true)
  const owners = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement)) continue
    const bindings = statement.importClause?.namedBindings
    if (!bindings || !ts.isNamedImports(bindings)) continue
    for (const binding of bindings.elements) {
      if (['AppointmentClaimsFhirApi', 'AppointmentStatus'].includes(binding.propertyName?.text ?? binding.name.text)) owners.push(statement.moduleSpecifier.text)
    }
  }
  assert.deepEqual(owners, ['fhir-data-utils-ts', 'fhir-data-utils-ts'])
  assert.equal(AppointmentClaimsFhirApi.Status, 'org.hl7.fhir.api.Appointment.status')
  assert.equal(AppointmentStatus.Booked, 'booked')
  assert.equal(AppointmentStatus.Cancelled, 'cancelled')
})
