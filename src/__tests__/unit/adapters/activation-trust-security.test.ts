// Flow contract: bind activation to the receiving host and signed ICA credential set, retain the verified controller key, and accept trust checks only from verified evidence. Explicit local Demo can omit cryptography; NODE_ENV or network labels alone never bypass checks. Unit collaborators model already-verified evidence, not a live ICA or Fabric proof.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import {createHash} from 'node:crypto';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {DefaultActivationTrustAdapter} from '../../../adapters/activation-trust.adapter';
import {DefaultTrustRegistryAdapter} from '../../../adapters/trust-registry.adapter';
import {buildDeterministicSignedJwt,buildDeterministicVpTokenFixture,deriveDeterministicEcJwkPair} from '../../utils/deterministic-jwt-fixtures';
import type {ClearingHouseVerificationResult,ClearingHouseVerificationRequest} from '../../../services/ClearingHouseService';

const original=process.env;
const checks={revocationChecked:true,issuerKeyStatusChecked:true,subjectKeyStatusChecked:true,onChainChecked:false};
function organizationCredential(){return {type:['VerifiableCredential','OrganizationCredential'],credentialSubject:{id:safe.didWeb,'@type':'Organization',taxID:String(safe.organizationBusinessNumber)}};}
async function signed(){const credential=organizationCredential();const vp=await buildDeterministicVpTokenFixture({seed:safe.resourceUuid,issuerDid:safe.didWeb,audience:safe.httpsBaseUrl,credentials:[credential]});return {credential,vp};}
function service(result:ClearingHouseVerificationResult){return {verifyVpToken:jest.fn(async(_request:ClearingHouseVerificationRequest)=>result)};}
const verified=():ClearingHouseVerificationResult=>({acr:'activation',ledgerVerified:false,trustChecks:checks});
beforeEach(()=>{process.env={...original,SECURITY_MODE:'strict',NETWORK_MODE:'test',NODE_ENV:'test'};});
afterEach(()=>{process.env=original;});

describe('activation evidence binding',()=>{
 it('routes verification through the host and preserves the verified presentation signer',async()=>{
  const {credential,vp}=await signed();const verifier=service(verified());
  const result=await new DefaultActivationTrustAdapter(verifier).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl} as any);
  expect(verifier.verifyVpToken).toHaveBeenCalledWith(expect.objectContaining({tenantDid:safe.httpsBaseUrl,tenantVaultId:'host'}));
  expect((result as any).controllerSigningKey).toMatchObject(vp.publicJwk);
  expect(result.trustPolicy).toMatchObject(checks);
 });
 it('retains the signed presentation method identifier when its verified JWK omits kid',async()=>{
  const credential=organizationCredential();const pair=deriveDeterministicEcJwkPair({seed:safe.resourceUuid,purpose:safe.tenantId});const {kid,...publicMaterial}=pair.publicJwk;
  const vp=await buildDeterministicSignedJwt({seed:safe.resourceUuid,purpose:safe.tenantId,payload:{iss:safe.didWeb,vp:{holder:safe.didWeb,verifiableCredential:[credential]}},header:{jwk:publicMaterial}});
  const result=await new DefaultActivationTrustAdapter(service(verified())).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl} as any);
  expect(result.controllerSigningKey).toMatchObject({...publicMaterial,kid});
  const parts=vp.compactToken.split('.');parts[0]=Buffer.from(JSON.stringify({...vp.header,kid:safe.tenantId})).toString('base64url');
  await expect(new DefaultActivationTrustAdapter(service(verified())).evaluate({networkMode:'test',vpToken:parts.join('.'),organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl} as any)).rejects.toThrow();
 });
 it('rejects credentials substituted after the presentation was signed',async()=>{
  const {credential,vp}=await signed();credential.credentialSubject.taxID=safe.tenantId;
  await expect(new DefaultActivationTrustAdapter(service(verified())).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl} as any)).rejects.toThrow(/presentation|credential.*match/i);
 });
 it('rejects a registration key different from the verified signer',async()=>{
  const {credential,vp}=await signed();const alternate=deriveDeterministicEcJwkPair({seed:safe.tenantId,purpose:safe.resourceUuid}).publicJwk;
  await expect(new DefaultActivationTrustAdapter(service(verified())).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl,controllerBinding:{publicKeyJwk:alternate}} as any)).rejects.toThrow(/controller|signing key/i);
 });
 it('requires receiving host context in strict local tests',async()=>{
  const {credential,vp}=await signed();await expect(new DefaultActivationTrustAdapter(service(verified())).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential})).rejects.toThrow(/host|context/i);
 });
 it('rejects substituted or incorrectly labelled native ICA evidence',async()=>{
  const {credential,vp}=await signed();
  for(const result of [{...verified(),activationEvidenceSource:'ica',ledgerVerified:true,amr:['ica'],vpHash:createHash('sha256').update(vp.compactToken).digest('hex')},{...verified(),activationEvidenceSource:'ica',amr:['ica'],vpHash:safe.resourceUuid}]){
   await expect(new DefaultActivationTrustAdapter(service(result as ClearingHouseVerificationResult)).evaluate({networkMode:'test',vpToken:vp.compactToken,organizationCredential:credential,verifierTenantDid:safe.httpsBaseUrl} as any)).rejects.toThrow(/ICA|evidence|presentation/i);
  }
 });
 it('does not treat NODE_ENV=demo alone as permission to skip presentation signatures',async()=>{
  process.env.NODE_ENV='demo';const verifier=service(verified());
  await expect(new DefaultActivationTrustAdapter(verifier).evaluate({networkMode:'test',vpToken:'unsigned',organizationCredential:organizationCredential(),verifierTenantDid:safe.httpsBaseUrl} as any)).rejects.toThrow();
  expect(verifier.verifyVpToken).not.toHaveBeenCalled();
 });
});
describe('trust evidence requirements',()=>{
 it('rejects every network label without current verification evidence',async()=>{
  for(const networkMode of ['test','local-network','test-network','network'] as const){await expect(new DefaultTrustRegistryAdapter().verifyActivationTrust({networkMode,organizationDid:safe.didWeb})).rejects.toThrow(/evidence|verified/i);}
 });
 it('reports only the supplied current evidence, requiring ledger evidence for non-ICA network paths',async()=>{
  const adapter=new DefaultTrustRegistryAdapter();await expect(adapter.verifyActivationTrust({networkMode:'network',organizationDid:safe.didWeb,verificationEvidence:checks} as any)).rejects.toThrow();
  await expect(adapter.verifyActivationTrust({networkMode:'network',organizationDid:safe.didWeb,verificationEvidence:checks,activationEvidenceSource:'ica'} as any)).resolves.toEqual(checks);
 });
 it('permits explicit local Demo without claiming performed cryptographic checks',async()=>{
  process.env.SECURITY_MODE='demo';
  await expect(new DefaultTrustRegistryAdapter().verifyActivationTrust({networkMode:'test',organizationDid:safe.didWeb})).resolves.toEqual({revocationChecked:false,issuerKeyStatusChecked:false,subjectKeyStatusChecked:false,onChainChecked:false});
  process.env.DEPLOYMENT_ENV='staging';await expect(new DefaultTrustRegistryAdapter().verifyActivationTrust({networkMode:'test',organizationDid:safe.didWeb})).rejects.toThrow();
 });
});
