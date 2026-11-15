// Flow contract: licence pool classification cannot grant professional authority; individual relationship roles and professional occupations retain separate pools, and issued-seat fallback2 stays distinct from the historical GW device/search fallback5.
import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {createRequire} from 'node:module'
const require=createRequire(import.meta.url)
const {Isco08CodingSystem,Isco08Hl7CodingSystem}=require('antifraud-data-utils-ts/isco-08')
const {HL7_CODING_SYSTEM_V3_ROLE_CODE}=require('fhir-data-utils-ts')
const policy=()=>import(new URL('../../src/utils/license-seat-policy.ts',import.meta.url).href)

test('actual licence policy consumers no longer load the legacy runtime helper',()=>{
 for(const path of ['src/managers/LicenseManager.ts','src/utils/license-issuance.ts'])assert.ok(!readFileSync(path,'utf8').includes('gdc-common-utils-ts/utils/license'),path)
})
test('role families select a pool without interpreting occupation or relationship as authority',async()=>{
 const owned=await policy()
 for(const token of [`${HL7_CODING_SYSTEM_V3_ROLE_CODE}|RESPRSN`,'v3-RoleCode|ONESELF','org.hl7.v3.rolecode|MTH'])assert.equal(owned.classifyLicenseRole(token),owned.LicenseRoleKinds.IndividualMember)
 for(const system of ['ISCO','ISCO-08','org.ilo.isco','org.ilo.isco-08',Isco08CodingSystem,Isco08Hl7CodingSystem])assert.equal(owned.classifyLicenseRole(system+'|2261'),owned.LicenseRoleKinds.Professional)
 assert.ok(Object.isFrozen(owned.LicenseRoleKinds))
})
test('unknown and empty role systems cannot select either licence pool',async()=>{
 const owned=await policy()
 for(const token of ['', '   ','unknown|2261','unknown|RESPRSN','RESPRSN','2261'])assert.equal(owned.classifyLicenseRole(token),owned.LicenseRoleKinds.Unsupported)
})
test('issued seat fallback remains2, positive explicit capacities survive, and the GW legacy fallback stays5',async()=>{
 const owned=await policy()
 for(const value of [undefined,null,0,-1,1.5,NaN,Infinity,'invalid'])assert.equal(owned.resolveIssuedSeatDeviceAllowance(value),2)
 for(const value of [1,2,5,8,'3'])assert.equal(owned.resolveIssuedSeatDeviceAllowance(value),Number(value))
 assert.match(readFileSync('src/constants/domain.ts','utf8'),/DEFAULT_LICENSE_DEVICE_ALLOWANCE\s*=\s*5\s*;/u)
})
