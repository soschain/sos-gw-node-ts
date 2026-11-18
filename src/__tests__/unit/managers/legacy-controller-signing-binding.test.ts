// Flow contract: an existing finalized tenant may renew its historical controller only when the authenticated outer signing key matches the ICA-authorized business key. Reject mismatches or missing authority before key provisioning or persistence; preserve the existing rotation flow after that check.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {toJwkThumbprintSha256Urn} from 'antifraud-data-utils-ts/jwk-thumbprints';
import {deriveDeterministicEcJwkPair} from '../../utils/deterministic-jwt-fixtures';
import {testClaimsTenant1Registration} from '../../data/end-to-end.data';
import {URN_NAMESPACE,URN_NETWORK} from '../../data/urn.data';
const unexpectedFabric=()=>{throw new Error('Unexpected Fabric transport in controller-binding unit.');};
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:unexpectedFabric,signers:{newPrivateKeySigner:unexpectedFabric},checkpointers:{inMemory:unexpectedFabric,file:unexpectedFabric}}));
const {HostingManager}=await import('../../../managers/HostingManager');
const original=process.env;
beforeEach(()=>{process.env={...original,SECURITY_MODE:'strict',NETWORK_MODE:'test',NODE_ENV:'test',HOST_LEGACY_REPRESENTATIVE_CONTROLLER:'true'};});
afterEach(()=>{process.env=original;});
function fixture(){
 const authorized=deriveDeterministicEcJwkPair({seed:safe.resourceUuid,purpose:safe.tenantId}).publicJwk;
 const outer=deriveDeterministicEcJwkPair({seed:safe.tenantId,purpose:safe.resourceUuid}).publicJwk;
 const stored={id:safe.tenantId,status:'active',content:{status:'active',didDocument:{id:safe.didWeb}}};
 const mutation=jest.fn(async()=>{throw new Error('Unexpected controller provisioning before authorization.');});
 const context={applyLegalOrganizationIdentityCompatibility:(claims:unknown)=>claims,isDemoSecurityMode:()=>false,
  extractRegistrationKeys:()=>({signerJwk:outer}),extractResources:()=>({person:{}}),getCurrentUrnNetwork:()=>URN_NETWORK,
  config:{namespace:URN_NAMESPACE,apiBaseUrl:safe.httpsBaseUrl},hostRuntime:{hostCollectionName:safe.tenantId},
  vaultRepository:{vaultExists:jest.fn(async()=>true),get:jest.fn(async()=>stored)},
  kmsService:{unprotectConfidentialData:jest.fn(async()=>stored.content)},buildControllerEntityConfig:mutation};
 const input={claims:{...testClaimsTenant1Registration},representativeCredential:{type:['VerifiableCredential','LegalRepresentativeCredential']}};
 return {authorized,outer,context,input,mutation,stored};
}
const evaluate=(context:unknown,input:unknown)=>(HostingManager.prototype as any).reregisterExistingLegacyRepresentativeController.call(context,input);
describe('existing controller signing-key authorization',()=>{
 it('continues the existing rotation flow after exact signer binding',async()=>{
  const f=fixture();f.context.extractRegistrationKeys=()=>({signerJwk:f.authorized});
  await expect(evaluate(f.context,{...f.input,verifiedControllerSigningKey:f.authorized})).rejects.toThrow('Unexpected controller provisioning before authorization.');expect(f.mutation).toHaveBeenCalledTimes(1);
 });
 it('leaves pending registration on its original continuation without provisioning a controller',async()=>{
  const f=fixture();f.stored.content.status='pending';await expect(evaluate(f.context,f.input)).resolves.toBeUndefined();expect(f.mutation).not.toHaveBeenCalled();
 });

 it('rejects an outer DIDComm key different from the verified activation presentation signer',async()=>{
  const f=fixture();await expect(evaluate(f.context,{...f.input,verifiedControllerSigningKey:f.authorized})).rejects.toThrow(/ICA-authorized|signing.key.*match/i);expect(f.mutation).not.toHaveBeenCalled();
 });
 it('rejects an outer key different from the current ICA-issued transaction controller binding',async()=>{
  const f=fixture();const controller={type:['VerifiableCredential','ServiceControllerCredential'],credentialSubject:{owner:{hasCredential:{material:toJwkThumbprintSha256Urn(f.authorized)}}}};
  await expect(evaluate(f.context,{...f.input,credentials:[f.input.representativeCredential,controller]})).rejects.toThrow(/ICA-authorized|signing.key.*match/i);expect(f.mutation).not.toHaveBeenCalled();
 });
 it('rejects re-registration with no verified ICA signing-key authority',async()=>{
  const f=fixture();await expect(evaluate(f.context,f.input)).rejects.toThrow(/ICA-authorized|signing.key/i);expect(f.mutation).not.toHaveBeenCalled();
 });
});
