// Flow contract: gateway resource-name and datatype catalog imports use their existing canonical FHIR owner, preserving all managers and authorization behavior.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
const root=process.argv[2]||process.cwd()
const files=[
  "src/shared/fhir-constants.ts",
  "src/__tests__/data/appointment.data.ts",
  "src/__tests__/data/demo-smart-access-local-network.data.ts",
  "src/__tests__/e2e/consentaccess.test-network-unid.e2e.spec.ts",
  "src/__tests__/integration/byok-dcr.test.ts",
  "src/__tests__/integration/patient-match-human-transport.api.test.ts",
  "src/__tests__/integration/patient-match.api.test.ts",
  "src/__tests__/integration/wellKnownApi.test.ts",
  "src/__tests__/unit/managers/CompositionManager.test.ts",
  "src/__tests__/unit/managers/FamilyManager.OfferOrder.test.ts",
  "src/__tests__/unit/managers/VeterinaryHealthCardCredentialManager.test.ts",
  "src/__tests__/unit/services/DiscoveryService.test.ts",
  "src/__tests__/unit/utils/digital-twin-secondary-use.test.ts",
  "src/__tests__/unit/utils/fhir-versioning.test.ts"
]
test('selected GW resource catalog sites use FHIR without a legacy module alias',()=>{for(const file of files){const s=fs.readFileSync(path.join(root,file),'utf8');assert.ok(!s.includes('gdc-common-utils-ts/constants/fhir-resource-types'),file);assert.match(s,/from ['"]fhir-data-utils-ts['"]/u,file)}})
