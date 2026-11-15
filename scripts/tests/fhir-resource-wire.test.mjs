// Flow contract: existing GW-consumed canonical FHIR resource and datatype tokens retain exact case and wire values; descriptive resource names do not grant access.
import test from 'node:test'
import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {pathToFileURL} from 'node:url'
const require=createRequire(new URL('../../package.json',import.meta.url))
const owned=await import(pathToFileURL(require.resolve('fhir-data-utils-ts')).href)
const expected=[
  {
    "catalog": "FhirDataTypes",
    "member": "Annotation",
    "value": "Annotation"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Composition",
    "value": "Composition"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "DocumentReference",
    "value": "DocumentReference"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Consent",
    "value": "Consent"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Bundle",
    "value": "Bundle"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Communication",
    "value": "Communication"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Device",
    "value": "Device"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Parameters",
    "value": "Parameters"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Patient",
    "value": "Patient"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "ResearchSubject",
    "value": "ResearchSubject"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Condition",
    "value": "Condition"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "MedicationStatement",
    "value": "MedicationStatement"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "AllergyIntolerance",
    "value": "AllergyIntolerance"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Practitioner",
    "value": "Practitioner"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "PractitionerRole",
    "value": "PractitionerRole"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Organization",
    "value": "Organization"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "RelatedPerson",
    "value": "RelatedPerson"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Immunization",
    "value": "Immunization"
  },
  {
    "catalog": "ResourceTypesFhirR4",
    "member": "Observation",
    "value": "Observation"
  }
]
test('every current selected member preserves its governed wire value',()=>{for(const row of expected)assert.equal(owned[row.catalog][row.member],row.value,row.catalog+'.'+row.member)})
test('datatype catalog preserves Annotation and unrelated types never become resource permissions',()=>{assert.equal(owned.FhirDataTypes.Annotation,'Annotation');assert.ok(Object.isFrozen(owned.ResourceTypesFhirR4));assert.ok(Object.isFrozen(owned.FhirDataTypes));assert.equal(Object.hasOwn(owned.ResourceTypesFhirR4,'NotAResource'),false)})
