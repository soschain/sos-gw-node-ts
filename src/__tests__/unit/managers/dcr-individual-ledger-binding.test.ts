// Flow contract: real personal DCR binds a verified account, its licensed controller contact, its own actor DID and a distinct authorized animal/individual target. Encrypted current records govern member identity and person-key registration on identity-global. Manager input models already-authenticated initial-access metadata; ledger spies do not claim live Fabric execution.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {EXAMPLE_ACCOUNT_OWNER_ID} from 'sos-data-utils-ts/gateway-flow-examples';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {DataspaceSectors} from 'sos-data-utils-ts/dataspace-sectors';
import {IdentityAuthActions,IdentityDcrMetadataFields} from 'sos-data-utils-ts/identity-auth-wire-contract';
import {JobStatus,type JobRequest} from 'sos-data-utils-ts/confidential-job';
import {SecureIdTypesIndividual} from 'sos-data-utils-ts/identity-identifiers';
import {buildIndividualDidWeb,buildIndividualMemberDidWebFromPrivateIdentifiers,buildSecureIdValueIndividual} from 'sos-data-utils-ts/hosted-did';
import {buildOrganizationAuthorizationUrnCds} from 'sos-data-utils-ts/organization-authorization-urn';
import {getIndividualMemberIdentityVC} from 'sos-data-utils-ts/individual-smart';
import {deriveDeterministicEcJwkPair,buildDeterministicSignedJwt} from '../../utils/deterministic-jwt-fixtures';
import {AdapterCryptoSdkNode} from '../../../gdc-backend-utils-node/adapters/node/crypto';
import {VaultMemRepository} from '../../../database/repositories/vault/vault.mem.repository';
import {KmsService} from '../../../services/KmsService';
import {TenantsCacheManager} from '../../../managers/TenantsCacheManager';
import {getTenantVaultId} from '../../../utils/tenant';
import {getEnvSectionId} from '../../../utils/section-env';
import {verifyRegisteredIndividualMemberIdentity} from '../../../services/registered-individual-member-authority';
const unexpectedFabric=()=>{throw new Error('Unexpected Fabric transport in personal DCR unit.');};
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:unexpectedFabric,signers:{newPrivateKeySigner:unexpectedFabric},checkpointers:{inMemory:unexpectedFabric,file:unexpectedFabric}}));
const {DeviceRegistrationManager}=await import('../../../managers/DeviceRegistrationManager');
const {ManageAssetCryptographicKey}=await import('../../../blockchain/fabric/v3/manageAssetCryptographicKey');
const {buildLocalClearingHouseVerifier}=await import('../../../bootstrap/build-clearing-house-verifier');
const {tryGetJwkThumbprint}=await import('../../../utils/ledger-organization-registration-helpers');
const {ManageAssetSubjectKeyBinding}=await import('../../../blockchain/fabric/v3/manageAssetSubjectKeyBinding');
const {revokeSubjectKeysOnLedger}=await import('../../../utils/ledger-device-registration');
const original=process.env;
let vault:VaultMemRepository,kms:KmsService,manager:InstanceType<typeof DeviceRegistrationManager>,job:JobRequest;
let keyWrite:any,bindingWrite:any;
const personId=e.resourceUuid;
const vaultId=getTenantVaultId(DataspaceSectors.HealthCare,e.tenantId);
const actorDid=buildIndividualMemberDidWebFromPrivateIdentifiers({providerDidWeb:e.subjectCardProviders.humanIndexDid,secureIdTypeIndividual:SecureIdTypesIndividual.Uuid,privateIdValueIndividual:personId,secureIdTypeMember:SecureIdTypesIndividual.Email,privateIdValueMember:e.individualEmail,roleType:'v3-RoleCode',roleValue:HealthcareActorRoles.Controller});
const subjectDid=buildIndividualDidWeb({providerDidWeb:e.subjectCardProviders.animalIndexDid,secureIdTypeIndividual:SecureIdTypesIndividual.Uuid,secureIdValueIndividual:buildSecureIdValueIndividual({secureIdTypeIndividual:SecureIdTypesIndividual.Uuid,privateIdValueIndividual:e.demoOrganizationUuids.animalCare})});
const licenseId=e.demoOrganizationUuids.healthCare;
const signingKey=deriveDeterministicEcJwkPair({seed:e.resourceUuid,purpose:e.tenantId}).publicJwk;
const personActorId=buildStableActorIdentifier({contactKind:'email',contact:e.individualEmail});
async function store(id:string,section:string,content:Record<string,unknown>){
 const doc=await kms.protectConfidentialData({id,status:String(content.status||'active'),sequence:0,content} as any,vaultId);
 expect(doc.content).toBeUndefined();expect(doc.jwe||doc.blob).toBeTruthy();await vault.put(vaultId,[doc],getEnvSectionId(section));
}
async function open(id:string,section:string){const doc=await vault.get<any>(vaultId,id,getEnvSectionId(section));return kms.unprotectConfidentialData<any>(doc,vaultId);}
async function enroll(){const result=await manager.process(job);const entry=(result.body as any).data[0];expect(entry.response.status).toBe('201');return String(entry.resource.client_id);}
function credential(target=subjectDid){return getIndividualMemberIdentityVC({actorDid,subjectDid:target,relationship:HealthcareActorRoles.Controller,email:e.individualEmail});}
function verify(holder:string,value=credential()){return verifyRegisteredIndividualMemberIdentity({credential:value,holder,vaultId,kmsService:kms,vaultRepository:vault});}
beforeEach(async()=>{
 process.env={...original,NETWORK_MODE:'test-network',SECURITY_MODE:'strict',NODE_ENV:'test',LEDGER_PROVIDER_DEFAULT:'fabric',LEDGER_PROVIDER_MAP:'test-network=fabric',LEDGER_MSP_ID:e.tenantId,HOST_JURISDICTION:e.secondaryCountryIso2,LEDGER_IDENTITY_CHANNEL_DEFAULT:'',LEDGER_ORGANIZATION_IDENTITY_CHANNEL_DEFAULT:''};
 keyWrite=jest.spyOn(ManageAssetCryptographicKey.prototype,'registerKey').mockResolvedValue({});bindingWrite=jest.spyOn(ManageAssetSubjectKeyBinding.prototype,'upsertSubjectKeyBinding').mockResolvedValue({});
 vault=new VaultMemRepository();let localKms:KmsService;const tenants=new TenantsCacheManager(vault,()=>localKms,e.tenantId);localKms=new KmsService(new CryptographyService(new AdapterCryptoSdkNode()),tenants);kms=localKms;await kms.init();await kms.provisionKeys(vaultId);
 manager=new DeviceRegistrationManager(e.httpsBaseUrl,vault,kms,{getCollectionName:async()=>vaultId,getOrganizationIdentifierUrn:async()=>buildOrganizationAuthorizationUrnCds({jurisdiction:e.secondaryCountryIso2,identifierType:e.organizationIdentifierType,identifierValue:e.organizationBusinessNumber})});
 const code=e.demoOrganizationUuids.publicHealth;
 await store(licenseId,'device-licenses',{id:licenseId,tenantId:e.tenantId,orderId:e.demoOrganizationUuids.healthCare,activationCode:code,userClass:'individual',type:'mobile',status:'issued',plan:'default',renewalCycle:'12m',reactivationEnabled:false,exp:Math.floor(Date.now()/1000)+600,subjectId:personId,ownerOrganizationId:personId,authorizedSubjectDid:subjectDid,issuedToEmail:e.individualEmail,issuedToRole:HealthcareActorRoles.Controller});
 job={id:e.resourceUuid,status:JobStatus.DRAFT,sequence:0,createdAtTimestamp:Date.now(),tenantId:e.tenantId,jurisdiction:e.secondaryCountryIso2,sector:DataspaceSectors.HealthCare,section:'identity',format:'openid',resourceType:'Device',action:IdentityAuthActions.Dcr,content:{body:{code,redirect_uris:[e.httpsBaseUrl],token_endpoint_auth_method:'private_key_jwt',application_type:'web',jwks:{keys:[signingKey]},ext_device_info:{device_id:e.demoOrganizationUuids.healthCare},[IdentityDcrMetadataFields.ActorDid]:actorDid,[IdentityDcrMetadataFields.ProfileDid]:actorDid},meta:{bearer:{jwt:{payload:{sub:EXAMPLE_ACCOUNT_OWNER_ID,email:e.individualEmail,scope:'dcr:register',act_code:code}}}}} as any} as JobRequest;
});
afterEach(()=>{kms?.destroy();vault?.clear();process.env=original;jest.restoreAllMocks();});
describe('current personal DCR and global identity key binding',()=>{
 it('verifies a real signed registered-member VP against the global plane selected from protected authority',async()=>{
  const holder=await enroll();const identity=await verify(holder);const thumbprint=tryGetJwkThumbprint(signingKey)!;
  jest.spyOn(ManageAssetCryptographicKey.prototype,'read').mockImplementation(async function(this:any,_msp:string,id:string){if(this.channel!=='identity-global')throw new Error('Personal key queried another identity plane.');if(id!==thumbprint)throw new Error('Unknown fixture key.');return {status:'active',thumbprint};});
  let bindingStatus='active';
  jest.spyOn(ManageAssetSubjectKeyBinding.prototype,'read').mockImplementation(async function(this:any,_msp:string,id:string){if(this.channel!=='identity-global')throw new Error('Personal binding queried another identity plane.');const payload=bindingWrite.mock.calls.find((call:any[])=>call[2].bindingId===id)?.[2];if(!payload)throw new Error('Unknown fixture person binding.');return {...payload,status:bindingStatus};});
  const scope=`organization/Composition.rs?subject=${encodeURIComponent(subjectDid)}`;
  const verifier=buildLocalClearingHouseVerifier({network:'test-network',ledgerKind:'fabric',tenants:{getDidDocument:async()=>({id:e.didWeb}),isTenantOperational:async()=>true,getCollectionName:async()=>vaultId} as any,ledger:{getCredentialStatus:async()=>{throw new Error('Unexpected issued-credential lookup for a registered identity projection.');}} as any,vaultRepository:vault,kmsService:kms,cryptography:new CryptographyService(new AdapterCryptoSdkNode()),authorize:async(request,current)=>{if(current?.subjectDid!==subjectDid||request.tokenScope!==scope)throw new Error('Requested target is not authorized.');}});
  const now=Math.floor(Date.now()/1000);const vp=await buildDeterministicSignedJwt({seed:e.resourceUuid,purpose:e.tenantId,payload:{iss:holder,sub:actorDid,aud:e.didWeb,jti:e.resourceUuid,iat:now,exp:now+60,vp:{holder,verifiableCredential:[credential()]}}});
  const request={tenantDid:e.didWeb,tenantVaultId:vaultId,holderVaultId:vaultId,authenticatedClientId:holder,tokenSubject:actorDid,tokenScope:scope,acrValues:[identity.acr],vpToken:vp.compactToken};
  await expect(verifier.verifyVpToken(request)).resolves.toMatchObject({acr:identity.acr});
  bindingStatus='revoked';await expect(verifier.verifyVpToken(request)).rejects.toThrow(/Personal key binding/);
 });
 it('requires an explicit governed channel for an independently configured credential issuer',async()=>{
  const issuer=e.subjectCardProviders.humanIndexDid;const key=deriveDeterministicEcJwkPair({seed:e.demoOrganizationUuids.healthCare,purpose:e.tenantId}).publicJwk;const thumbprint=tryGetJwkThumbprint(key)!;
  process.env.CREDENTIAL_TRUSTED_ISSUERS_JSON=JSON.stringify({[issuer]:{status:'active',channelName:'identity-global',jwks:{keys:[key]}}});
  const read=jest.spyOn(ManageAssetCryptographicKey.prototype,'read').mockImplementation(async function(this:any,_msp:string,id:string){if(this.channel!=='identity-global'||id!==thumbprint)throw new Error('Issuer key queried outside its governed channel.');return {status:'active',thumbprint};});
  const verifier=buildLocalClearingHouseVerifier({network:'test-network',ledgerKind:'fabric',tenants:{} as any,ledger:{} as any,vaultRepository:vault,kmsService:kms,cryptography:new CryptographyService(new AdapterCryptoSdkNode()),authorize:async()=>{throw new Error('Unexpected authorization call in issuer-channel unit.');}});
  await expect((verifier as any).options.assertActiveKey(issuer,key,{})).resolves.toBeUndefined();expect(read).toHaveBeenCalledTimes(1);
  process.env.CREDENTIAL_TRUSTED_ISSUERS_JSON=JSON.stringify({[issuer]:{status:'active',jwks:{keys:[key]}}});await expect((verifier as any).options.assertActiveKey(issuer,key,{})).rejects.toThrow(/channel|configured/i);
 });

 it('preserves actual phone-only DCR authority without an email identity',async()=>{
  const licence=await open(licenseId,'device-licenses');await store(licenseId,'device-licenses',{...licence,issuedToEmail:undefined,issuedToPhone:e.phoneE164});
  const phoneActor=buildIndividualMemberDidWebFromPrivateIdentifiers({providerDidWeb:e.subjectCardProviders.humanIndexDid,secureIdTypeIndividual:SecureIdTypesIndividual.Uuid,privateIdValueIndividual:personId,secureIdTypeMember:SecureIdTypesIndividual.Phone,privateIdValueMember:e.phoneE164,roleType:'v3-RoleCode',roleValue:HealthcareActorRoles.Controller});
  Object.assign((job.content as any).body,{[IdentityDcrMetadataFields.ActorDid]:phoneActor,[IdentityDcrMetadataFields.ProfileDid]:phoneActor});
  const holder=await enroll();await expect(verify(holder,getIndividualMemberIdentityVC({actorDid:phoneActor,subjectDid,relationship:HealthcareActorRoles.Controller,telephone:e.phoneE164}))).resolves.toMatchObject({actorDid:phoneActor,subjectDid});
 });
 it('retains a protected legacy phone actor only while that canonical contact remains licensed',async()=>{
  const holder=await enroll();const licence=await open(licenseId,'device-licenses');const phoneActor=buildStableActorIdentifier({contactKind:'phone',contact:e.phoneE164});
  await store(licenseId,'device-licenses',{...licence,issuedToPhone:e.phoneE164,activatedBy:phoneActor});
  await expect(verify(holder)).resolves.toMatchObject({actorDid,subjectDid});
  await store(licenseId,'device-licenses',{...licence,activatedBy:phoneActor});await expect(verify(holder)).rejects.toThrow(/stable actor|licensed contact/);
 });
 it('revokes the same personal key and global binding without changing its governed relationship',async()=>{
  const holder=await enroll();const thumbprint=tryGetJwkThumbprint(signingKey)!;const revokedAt=Math.floor(Date.now()/1000);
  const submit=jest.spyOn(ManageAssetCryptographicKey.prototype,'submit').mockResolvedValue({});
  await revokeSubjectKeysOnLedger({jurisdiction:e.secondaryCountryIso2,organizationId:buildOrganizationAuthorizationUrnCds({jurisdiction:e.secondaryCountryIso2,identifierType:e.organizationIdentifierType,identifierValue:e.organizationBusinessNumber}),subjectType:'person',subjectId:personActorId,subjectDid:actorDid,deviceId:holder,revokedAtEpochSec:revokedAt,verificationMethods:[{id:`${actorDid}#${signingKey.kid}`,type:'JsonWebKey',controller:actorDid,publicKeyJwk:signingKey as any}]});
  expect(submit).toHaveBeenCalledWith(e.tenantId,'UpdateKeyStatus',thumbprint,'revoked',String(revokedAt));expect((submit.mock.contexts[0] as any).channel).toBe('identity-global');
  const last=bindingWrite.mock.calls.at(-1);expect(last[1]).toBe(`person_${personActorId}__${thumbprint}`);expect(last[2]).toMatchObject({subjectType:'person',subjectId:personActorId,keyId:thumbprint,status:'revoked',relationship:'person-device-signing'});expect((bindingWrite.mock.contexts.at(-1) as any).channel).toBe('identity-global');
 });
 it('registers person keys on identity-global using the existing opaque actor identity',async()=>{
  const holder=await enroll();expect(holder).not.toBe(EXAMPLE_ACCOUNT_OWNER_ID);expect(personId).not.toBe(EXAMPLE_ACCOUNT_OWNER_ID);expect(actorDid).not.toBe(subjectDid);
  expect(keyWrite).toHaveBeenCalled();expect(bindingWrite).toHaveBeenCalledWith(e.tenantId,expect.any(String),expect.objectContaining({subjectType:'person',subjectId:personActorId,relationship:'person-device-signing'}));expect((bindingWrite.mock.contexts[0] as any).channel).toBe('identity-global');
  expect(personActorId).not.toBe(personId);expect(personActorId).not.toBe(subjectDid);expect(personActorId).not.toBe(EXAMPLE_ACCOUNT_OWNER_ID);
 });
 it('accepts the real Windows account/organization/actor/animal tuple from encrypted current DCR records',async()=>{
  const holder=await enroll();await expect(verify(holder)).resolves.toMatchObject({actorDid,subjectDid,role:HealthcareActorRoles.Controller});
 });
 it('retains authorization when old protected profiles lack optional contact/ledger projection fields',async()=>{
  const holder=await enroll();const profile=await open(holder,'device-profiles');delete profile.authenticatedEmail;delete profile.authenticatedTelephone;delete profile.stableActorIdentifier;await store(holder,'device-profiles',profile);await expect(verify(holder)).resolves.toMatchObject({actorDid,subjectDid});
 });
 it('rejects another requested individual while preserving the permitted target',async()=>{
  const holder=await enroll();await expect(verify(holder,credential(actorDid))).rejects.toThrow(/subject|individual|actor/i);await expect(verify(holder)).resolves.toMatchObject({subjectDid});
 });
 it('rejects inactive and expired current licences',async()=>{
  const holder=await enroll();const licence=await open(licenseId,'device-licenses');await store(licenseId,'device-licenses',{...licence,status:'revoked'});await expect(verify(holder)).rejects.toThrow(/inactive|licence/i);await store(licenseId,'device-licenses',{...licence,exp:Math.floor(Date.now()/1000)-1});await expect(verify(holder)).rejects.toThrow(/expired|inactive/i);
 });
 it('rejects a changed current licensed contact instead of giving another person the actor key',async()=>{
  const holder=await enroll();const licence=await open(licenseId,'device-licenses');await store(licenseId,'device-licenses',{...licence,issuedToEmail:e.firstContactEmail});await expect(verify(holder)).rejects.toThrow(/contact|member|licence/i);
 });
});
