// Flow contract: use the canonical subject-key-binding asset projection and
// real encrypted current professional records. Bindings carry opaque links;
// assignment/role-licence assets own current role and licence authority.
// Fabric RPC spies isolate graph verification and never claim live execution.
import {afterEach,beforeEach,expect,it,jest} from '@jest/globals';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity';
import {SchemaOrgPersonClaim} from 'antifraud-data-utils-ts/schema-org-claims';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {DataspaceSectors} from 'sos-data-utils-ts/dataspace-sectors';
import {buildProfessionalEmployeeCredential} from 'sos-data-utils-ts/professional-smart';
import {URN_NAMESPACE,URN_NETWORK} from '../../data/urn.data';
import {deriveDeterministicEcJwkPair} from '../../utils/deterministic-jwt-fixtures';
import {VaultMemRepository} from '../../../database/repositories/vault/vault.mem.repository';
import {TenantsCacheManager} from '../../../managers/TenantsCacheManager';
import {KmsService} from '../../../services/KmsService';
import {AdapterCryptoSdkNode} from '../../../gdc-backend-utils-node/adapters/node/crypto';
import {getEnvSectionId} from '../../../utils/section-env';
const unexpectedFabric=()=>{throw new Error('Unexpected live Fabric RPC in canonical schema unit.');};
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:unexpectedFabric,signers:{newPrivateKeySigner:unexpectedFabric},checkpointers:{inMemory:unexpectedFabric,file:unexpectedFabric}}));
const {buildLocalClearingHouseVerifier}=await import('../../../bootstrap/build-clearing-house-verifier');
const {ManageAsset}=await import('../../../blockchain/fabric/v3/manageAsset');
const {createEmployeeUrn}=await import('../../../utils/urn');
const {buildIssuedRoleLicenseLedgerIdentityFromSeat}=await import('../../../utils/ledger-role-license');
const {buildProfessionalAssignmentLedgerPayload}=await import('../../../utils/professional-assignment-ledger');
const {tryGetJwkThumbprint}=await import('../../../utils/ledger-organization-registration-helpers');
const require=createRequire(import.meta.url);
const {buildStoredSubjectKeyBindingAsset}=require(resolve(process.cwd(),'chaincode/subjectkeybinding-sc-javascript/lib/subject-key-binding-asset.js'));
const original=process.env;
let kms:KmsService,vault:VaultMemRepository;
beforeEach(()=>{process.env={...original,NODE_ENV:'test',NETWORK_MODE:'test-network',SECURITY_MODE:'strict',LEDGER_MSP_ID:e.tenantId,HOST_JURISDICTION:e.countryIso2,LEDGER_ORGANIZATION_IDENTITY_CHANNEL_DEFAULT:'identity-local'};});
afterEach(()=>{kms?.destroy();vault?.clear();jest.restoreAllMocks();process.env=original;});
async function fixture(){
 vault=new VaultMemRepository();let local:KmsService;const keyTenants=new TenantsCacheManager(vault,()=>local,e.tenantId);local=new KmsService(new CryptographyService(new AdapterCryptoSdkNode()),keyTenants);kms=local;await kms.init();await kms.provisionKeys(e.tenantId);
 const vaultId=e.tenantId,employeeCollection=vaultId+'-employees',actorDid=e.didWeb+':employee',holder=e.resourceUuid,role=HealthcareActorRoles.Veterinarian,employeeId=e.demoOrganizationUuids.healthCare;
 const stable=buildStableActorIdentifier({contactKind:'email',contact:e.firstContactEmail});
 const employeeUrn=createEmployeeUrn({namespace:URN_NAMESPACE,network:URN_NETWORK,jurisdiction:e.countryIso2,sector:DataspaceSectors.HealthTech,idType:e.organizationIdentifierType,idValue:e.organizationBusinessNumber,email:e.firstContactEmail,role,instanceId:employeeId});
 const key=deriveDeterministicEcJwkPair({seed:e.resourceUuid,purpose:e.tenantId}).publicJwk,keyId=tryGetJwkThumbprint(key)!;
 const seat={id:e.demoOrganizationUuids.publicHealth,status:'active',userClass:'employee',exp:Math.floor(Date.now()/1000)+600,subjectId:employeeId,activationCode:e.resourceUuid,ownerOrganizationId:e.organizationBusinessNumber,activatedBy:stable,issuedToRole:role,deviceBindings:[{clientId:holder,status:'active'}]};
 const profile={clientId:holder,subjectId:employeeId,activationCode:seat.activationCode,stableActorIdentifier:stable,jwks:{keys:[key]}};
 const employee={status:'active',didDocument:{id:actorDid,alsoKnownAs:[employeeUrn]},claims:{[SchemaOrgPersonClaim.Email]:e.firstContactEmail,[SchemaOrgPersonClaim.HasOccupation]:role}};
 const put=async(id:string,section:string,content:any,collection:string=vaultId)=>{const doc=await kms.protectConfidentialData({id,status:'active',sequence:0,content}as any,vaultId);await vault.put(collection,[doc],getEnvSectionId(section));};
 await put(holder,'device-profiles',profile);await put(seat.id,'device-licenses',seat);await put(employeeId,'employees',employee,employeeCollection);
 const expected=buildIssuedRoleLicenseLedgerIdentityFromSeat({organizationId:seat.ownerOrganizationId,jurisdiction:e.countryIso2,stableContactIdentifier:stable,licensedRole:role});
 const assignment:any=buildProfessionalAssignmentLedgerPayload({assignmentIdentifier:'urn:uuid:'+e.demoOrganizationUuids.animalCare,employeeIdentifier:'urn:uuid:'+employeeId,organizationIdentifier:'urn:uuid:'+e.resourceUuid,role});
 const binding:any=buildStoredSubjectKeyBindingAsset({stub:{getTxTimestamp:()=>({seconds:{toNumber:()=>Math.floor(Date.now()/1000)}}),getTxID:()=>e.resourceUuid}},'employee_'+employeeUrn+'__'+keyId,{subjectType:'employee',subjectId:employeeUrn,keyId,relationship:'employee-device-signing',status:'active',licensedRole:role,roleLicenseId:expected.id,professionalAssignmentLink:assignment.assignmentLink,employeeLink:assignment.employeeLink,organizationLink:assignment.organizationLink});
 const licence:any={...expected,status:'active'};
 const licenceRead=jest.fn(async()=>licence),assignmentRead=jest.fn(async()=>assignment);
 jest.spyOn(ManageAsset.prototype,'read').mockImplementation(async function(this:any,_msp,id){
  if(this.channel!=='identity-local')throw new Error('Unexpected professional identity channel.');
  if(id===binding.bindingId)return binding;
  if(id===expected.id)return licenceRead();
  if(id===binding.professionalAssignmentLink)return assignmentRead();
  throw new Error('Unexpected authoritative graph target.');
 });
 const verifier=buildLocalClearingHouseVerifier({network:'test-network',ledgerKind:'fabric',tenants:{getDidDocument:async()=>({id:e.didWeb}),isTenantOperational:async()=>true,getCollectionName:async()=>employeeCollection}as any,ledger:{}as any,vaultRepository:vault,kmsService:kms,cryptography:new CryptographyService(new AdapterCryptoSdkNode()),authorize:async()=>{}});
 const credential=buildProfessionalEmployeeCredential({actorDid,role,email:e.firstContactEmail});
 const verify=()=> (verifier as any).options.verifyRegisteredIdentity(credential,holder,key,{tenantDid:e.didWeb,tenantVaultId:vaultId,holderVaultId:vaultId});
 return{verify,binding,assignment,licence,licenceRead,assignmentRead,seat,put};
}
it('accepts the exact canonical binding schema without duplicated role/licence fields',async()=>{const f=await fixture();expect(f.binding).not.toHaveProperty('licensedRole');expect(f.binding).not.toHaveProperty('roleLicenseId');await expect(f.verify()).resolves.toMatchObject({role:HealthcareActorRoles.Veterinarian});expect(f.licenceRead).toHaveBeenCalledTimes(1);expect(f.assignmentRead).toHaveBeenCalledTimes(1);});
for(const field of ['status','role','employeeLink','organizationLink'])it('rejects mismatched authoritative assignment '+field,async()=>{const f=await fixture();f.assignment[field]=field==='status'?'revoked':field==='role'?HealthcareActorRoles.NursingProfessional:e.didWeb;await expect(f.verify()).rejects.toThrow(/assignment/i);});
for(const field of ['id','status','stableContactIdentifier','licensedRole','organizationOfficialId','jurisdiction'])it('rejects mismatched authoritative licence '+field,async()=>{const f=await fixture();f.licence[field]=field==='status'?'revoked':field==='licensedRole'?HealthcareActorRoles.NursingProfessional:e.didWeb;await expect(f.verify()).rejects.toThrow(/licence|license/i);});
it('rejects revoked key relationships before assignment authority',async()=>{const f=await fixture();f.binding.status='revoked';await expect(f.verify()).rejects.toThrow(/binding/i);expect(f.assignmentRead).not.toHaveBeenCalled();});

it('rejects a relationship for another subject type',async()=>{const f=await fixture();f.binding.subjectType='person';await expect(f.verify()).rejects.toThrow(/binding/i);});
it('requires the authoritative assignment link',async()=>{const f=await fixture();delete f.binding.professionalAssignmentLink;await expect(f.verify()).rejects.toThrow(/binding/i);});
it('rejects an altered protected licence holder',async()=>{const f=await fixture();await f.put(f.seat.id,'device-licenses',{...f.seat,activatedBy:e.didWeb});await expect(f.verify()).rejects.toThrow(/holder|licence/i);});
