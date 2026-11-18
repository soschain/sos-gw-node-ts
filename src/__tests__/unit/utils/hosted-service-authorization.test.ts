// Flow contract: hosted service admission reads only verified credential scope and never turns advertisements or category wildcards into service authority.
import { describe, expect, it } from '@jest/globals';
import { ServiceCapability, DeprecatedServiceCapabilityToken } from 'sos-data-utils-ts/service-capabilities';
import { GatewaySector } from 'sos-data-utils-ts/gateway-sector-contract';
import { readFileSync } from 'node:fs';
const helperPath = '../../../utils/hosted-service-authorization';
const load = () => import(helperPath);
const required = {requiredCategory:GatewaySector.HEALTH_CARE,requiredServiceTypes:[ServiceCapability.IndexReader]};
const credential = (makesOffer:unknown) => ({credentialSubject:{makesOffer}});

describe('hosted service authorization profile', () => {
 it('uses the GW owner at the actual activation boundary', () => {
  const source=readFileSync('src/managers/hosting/process-organization-activation.ts','utf8');
  expect(source).not.toMatch(/import\s*\{[^}]*\bvalidateHostedServiceAuthorization\b[^}]*\}\s*from\s*['"]sos-data-utils-ts\/activation-policy['"]/u);
  expect(source.includes('validateHostedServiceAuthorization')).toBe(true);
  const manager=readFileSync('src/managers/HostingManager.ts','utf8');
  expect(manager).not.toMatch(/import\s*\{[^}]*\bvalidateHostedServiceAuthorization\b[^}]*\}\s*from\s*['"]sos-data-utils-ts\/activation-policy['"]/u);
 });
 it('admits explicitly authorized category and canonical or historical capability spellings',async()=>{
  const {validateHostedServiceAuthorization:validate}=await load();
  for(const token of [ServiceCapability.IndexReader,DeprecatedServiceCapabilityToken.IndexReader])
   expect(validate({...required,organizationCredential:credential({category:[GatewaySector.HEALTH_CARE],serviceType:token})})).toEqual([]);
  const extension='extension-capability.rs';
  expect(validate({...required,requiredServiceTypes:[extension],organizationCredential:credential({category:GatewaySector.HEALTH_CARE,serviceType:extension})})).toEqual([]);
 });
 it('keeps missing category and service dimensions as ordered errors',async()=>{
  const {validateHostedServiceAuthorization:validate}=await load();
  expect(validate({...required,organizationCredential:credential({})}).map((error:any)=>error.code)).toEqual(['MISSING_ORGANIZATION_SERVICE_CATEGORY','MISSING_ORGANIZATION_SERVICE_TYPE']);
 });
 it('rejects crossed category and service scopes without widening either dimension',async()=>{
  const {validateHostedServiceAuthorization:validate}=await load();
  expect(validate({...required,organizationCredential:credential({category:GatewaySector.RESEARCH,serviceType:ServiceCapability.IndexProvider})}).map((error:any)=>error.code)).toEqual(['UNAUTHORIZED_ORGANIZATION_SERVICE_CATEGORY','UNAUTHORIZED_ORGANIZATION_SERVICE_TYPE']);
 });
 it('allows wildcard categories but requires each exact service capability',async()=>{
  const {validateHostedServiceAuthorization:validate}=await load();
  expect(validate({...required,organizationCredential:credential({category:'*',serviceType:ServiceCapability.IndexReader})})).toEqual([]);
  expect(validate({...required,organizationCredential:credential({category:'*',serviceType:'*'})}).map((error:any)=>error.code)).toEqual(['UNAUTHORIZED_ORGANIZATION_SERVICE_TYPE']);
 });
 it('uses only known additionalType capabilities and preserves first-subject/nullish precedence',async()=>{
  const {validateHostedServiceAuthorization:validate}=await load();
  const subject={category:GatewaySector.HEALTH_CARE,additionalType:DeprecatedServiceCapabilityToken.IndexReader};
  expect(validate({...required,organizationCredential:{credentialSubject:[subject,{}]}})).toEqual([]);
  expect(validate({...required,organizationCredential:{credentialSubject:{...subject,additionalType:'unknown-extension-label'}}}).map((error:any)=>error.code)).toEqual(['MISSING_ORGANIZATION_SERVICE_TYPE']);
  expect(validate({...required,organizationCredential:{credentialSubject:{...subject,serviceType:ServiceCapability.IndexReader,makesOffer:{serviceType:'',additionalType:''}}}}).map((error:any)=>error.code)).toEqual(['MISSING_ORGANIZATION_SERVICE_TYPE']);
 });
});
