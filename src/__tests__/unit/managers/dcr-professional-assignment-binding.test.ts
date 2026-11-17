// Flow contract: DCR finalization anchors the server-validated professional assignment and the exact matching key-binding links through canonical builders. Individual controllers and missing professional bindings never acquire those links. Ledger method spies isolate projection/orchestration; this is not a live Fabric execution.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {DataspaceSectors} from 'sos-data-utils-ts/dataspace-sectors';
import {FhirIpsCreatorKinds} from 'sos-data-utils-ts/clinical-creator-contract';
import {buildOrganizationAuthorizationUrnCds} from 'sos-data-utils-ts/organization-authorization-urn';
import {deriveDeterministicEcJwkPair} from '../../utils/deterministic-jwt-fixtures';
import {URN_NAMESPACE,URN_NETWORK} from '../../data/urn.data';
const unexpectedFabric=()=>{throw new Error('Unexpected Fabric transport in DCR projection unit.');};
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:unexpectedFabric,signers:{newPrivateKeySigner:unexpectedFabric},checkpointers:{inMemory:unexpectedFabric,file:unexpectedFabric}}));
const {DeviceRegistrationManager}=await import('../../../managers/DeviceRegistrationManager');
const {registerSubjectKeysOnLedger}=await import('../../../utils/ledger-device-registration');
const {buildProfessionalAssignmentLedgerPayload}=await import('../../../utils/professional-assignment-ledger');
const {createEmployeeUrn,createUrnUuid}=await import('../../../utils/urn');
const {ManageAssetCryptographicKey}=await import('../../../blockchain/fabric/v3/manageAssetCryptographicKey');
const {ManageAssetSubjectKeyBinding}=await import('../../../blockchain/fabric/v3/manageAssetSubjectKeyBinding');
const {ManageAssetProfessionalAssignment}=await import('../../../blockchain/fabric/v3/manageAssetProfessionalAssignment');
const original=process.env;
let keyWrite:ReturnType<typeof jest.spyOn>,bindingWrite:ReturnType<typeof jest.spyOn>,assignmentWrite:ReturnType<typeof jest.spyOn>;
beforeEach(()=>{
 process.env={...original,NETWORK_MODE:'test-network',LEDGER_PROVIDER_DEFAULT:'fabric',LEDGER_PROVIDER_MAP:'test-network=fabric',LEDGER_MSP_ID:safe.tenantId};
 keyWrite=jest.spyOn(ManageAssetCryptographicKey.prototype,'registerKey').mockResolvedValue({});
 bindingWrite=jest.spyOn(ManageAssetSubjectKeyBinding.prototype,'upsertSubjectKeyBinding').mockResolvedValue({});
 assignmentWrite=jest.spyOn(ManageAssetProfessionalAssignment.prototype,'upsertProfessionalAssignment').mockResolvedValue({});
});
afterEach(()=>{process.env=original;jest.restoreAllMocks();});
function fixture(){
 const organizationId=buildOrganizationAuthorizationUrnCds({jurisdiction:safe.secondaryCountryIso2,identifierType:safe.organizationIdentifierType,identifierValue:safe.organizationBusinessNumber});
 const clinical={kind:FhirIpsCreatorKinds.Professional,actorIdentifier:createUrnUuid(safe.resourceUuid),authorIdentifier:createUrnUuid(safe.demoOrganizationUuids.healthCare),ownerIdentifier:organizationId,role:HealthcareActorRoles.Veterinarian};
 const employeeUrn=createEmployeeUrn({namespace:URN_NAMESPACE,network:URN_NETWORK,jurisdiction:safe.secondaryCountryIso2,sector:DataspaceSectors.HealthCare,idType:safe.organizationIdentifierType,idValue:safe.organizationBusinessNumber,email:safe.firstContactEmail,role:clinical.role});
 const key=deriveDeterministicEcJwkPair({seed:safe.resourceUuid,purpose:safe.tenantId}).publicJwk;
 const method={id:`${safe.didWeb}#${key.kid}`,type:'JsonWebKey2020',controller:safe.didWeb,publicKeyJwk:key};
 const employeeContent:{status:string;didDocument:{id:string;verificationMethod:Array<typeof method>}}={status:'active',didDocument:{id:safe.didWeb,verificationMethod:[]}};
 const employeeDoc={id:safe.resourceUuid,status:'active',sequence:0,content:employeeContent};
 const input={jurisdiction:safe.secondaryCountryIso2,organizationId,subjectType:'employee',subjectId:employeeUrn,licensedRole:clinical.role,verificationMethods:[method],professionalAssignment:{assignmentIdentifier:clinical.authorIdentifier,employeeIdentifier:clinical.actorIdentifier,organizationIdentifier:clinical.ownerIdentifier}};
 const links=buildProfessionalAssignmentLedgerPayload({...input.professionalAssignment,role:clinical.role});
 return {input,clinical,method,links,context:{subjectId:safe.resourceUuid,actorIdentifier:clinical.actorIdentifier,employeeUrn,licensedRole:clinical.role,roleLicenseId:safe.tenantId,organizationId,jurisdiction:safe.secondaryCountryIso2,employeeDoc,employeeContent,previousVerificationMethods:[],newVerificationMethods:[method]}};
}
describe('registered professional assignment links',()=>{
 it('repairs only ledger links for the same current registered key without rewriting profiles',async()=>{
  const f=fixture();f.context.employeeContent.didDocument.verificationMethod.push(f.method);const put=jest.fn(async()=>undefined);const manager=new DeviceRegistrationManager(safe.httpsBaseUrl,{put} as any);
  await (manager as any).synchronizeProfessionalAssignmentOnLedger({context:f.context,clinicalCreatorBinding:f.clinical,clientId:safe.resourceUuid,registeredKeysOnly:true});
  expect(assignmentWrite).toHaveBeenCalledWith(safe.tenantId,f.links.assignmentLink,f.links);expect(bindingWrite).toHaveBeenCalledWith(safe.tenantId,expect.any(String),expect.objectContaining({professionalAssignmentLink:f.links.assignmentLink,employeeLink:f.links.employeeLink,organizationLink:f.links.organizationLink}));expect(put).not.toHaveBeenCalled();
 });
 it('refuses ledger-link repair for a key not in the current registered employee DID',async()=>{
  const f=fixture();const manager=new DeviceRegistrationManager(safe.httpsBaseUrl,{put:jest.fn()} as any);
  await expect((manager as any).synchronizeProfessionalAssignmentOnLedger({context:f.context,clinicalCreatorBinding:f.clinical,clientId:safe.resourceUuid,registeredKeysOnly:true})).rejects.toThrow(/registered|key/i);expect(assignmentWrite).not.toHaveBeenCalled();expect(bindingWrite).not.toHaveBeenCalled();
 });
 it('does not attach another employee assignment to the current registered key',async()=>{
  const f=fixture();f.context.employeeContent.didDocument.verificationMethod.push(f.method);const manager=new DeviceRegistrationManager(safe.httpsBaseUrl,{put:jest.fn()} as any);
  await expect((manager as any).synchronizeProfessionalAssignmentOnLedger({context:f.context,clinicalCreatorBinding:{...f.clinical,actorIdentifier:createUrnUuid(safe.demoOrganizationUuids.publicHealth)},clientId:safe.resourceUuid,registeredKeysOnly:true})).rejects.toThrow(/employee|assignment/i);expect(assignmentWrite).not.toHaveBeenCalled();
 });
 it('does not repair links for an inactive current employee',async()=>{
  const f=fixture();f.context.employeeContent.status='suspended';f.context.employeeContent.didDocument.verificationMethod.push(f.method);const manager=new DeviceRegistrationManager(safe.httpsBaseUrl,{put:jest.fn()} as any);
  await expect((manager as any).synchronizeProfessionalAssignmentOnLedger({context:f.context,clinicalCreatorBinding:f.clinical,clientId:safe.resourceUuid,registeredKeysOnly:true})).rejects.toThrow(/active|assignment/i);expect(assignmentWrite).not.toHaveBeenCalled();
 });

 it('stores the three exact canonical private-reference hashes in the registered key binding',async()=>{
  const f=fixture();await registerSubjectKeysOnLedger(f.input as any);
  expect(bindingWrite).toHaveBeenCalledWith(safe.tenantId,expect.any(String),expect.objectContaining({professionalAssignmentLink:f.links.assignmentLink,employeeLink:f.links.employeeLink,organizationLink:f.links.organizationLink}));
  expect(f.links.assignmentLink).not.toBe(f.clinical.authorIdentifier);expect(f.links.employeeLink).not.toBe(f.clinical.actorIdentifier);expect(f.links.organizationLink).not.toBe(f.clinical.ownerIdentifier);
 });
 it('registers the current professional assignment during actual DCR finalization before key admission',async()=>{
  const f=fixture();const put=jest.fn(async()=>undefined);const manager=new DeviceRegistrationManager(safe.httpsBaseUrl,{put} as any);
  await (manager as any).finalizeEmployeeDeviceIdentityContext({job:{},vaultId:safe.tenantId,clientId:safe.resourceUuid,clinicalCreatorBinding:f.clinical,context:f.context});
  expect(assignmentWrite).toHaveBeenCalledWith(safe.tenantId,f.links.assignmentLink,f.links);
  expect(bindingWrite).toHaveBeenCalledWith(safe.tenantId,expect.any(String),expect.objectContaining({professionalAssignmentLink:f.links.assignmentLink,employeeLink:f.links.employeeLink,organizationLink:f.links.organizationLink}));
  expect(assignmentWrite.mock.invocationCallOrder[0]).toBeLessThan(bindingWrite.mock.invocationCallOrder[0]!);
 });
 it('does not infer professional assignment authority when the DCR has no verified professional binding',async()=>{
  const f=fixture();const {professionalAssignment,...unbound}=f.input;await registerSubjectKeysOnLedger(unbound as any);
  const payload=bindingWrite.mock.calls[0]?.[2] as Record<string,unknown>;expect(payload).not.toHaveProperty('professionalAssignmentLink');expect(assignmentWrite).not.toHaveBeenCalled();
 });
});
