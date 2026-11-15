// Flow contract: current phone controller creates exact phone Dentist, separately reserves a seat, and verified recipient exchanges it before DCR; real memory persistence must bind actor/role/installation/JWKS and deny another contact or excess device. Crypto, cloud persistence and blockchain acceptance have separate gates.
import {mock} from 'jest-mock-extended';
import {EmployeeManager} from '../../managers/EmployeeManager';
import {LicenseManager} from '../../managers/LicenseManager';
import {IdentityTokenManager} from '../../managers/IdentityTokenManager';
import {AppAuthorizationManager} from '../../managers/AppAuthorizationManager';
import {DeviceRegistrationManager} from '../../managers/DeviceRegistrationManager';
import {VaultMemRepository} from '../../database/repositories/vault/vault.mem.repository';
import type {IKmsService} from '../../gdc-backend-utils-node/models/IKmsService';
import type {ITokenVerifier} from '../../auth/ITokenVerifier';
import type {ICryptography} from 'antifraud-data-utils-ts/cryptography';
import {buildStableActorIdentifier,buildOrganizationEmployeeDidWeb} from 'antifraud-data-utils-ts/organization-identity';
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product,SchemaOrgOrganizationClaim as Organization} from 'antifraud-data-utils-ts/schema-org-claims';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {JobStatus,type JobRequest} from 'sos-data-utils-ts/confidential-job';
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';
import {resolveLedgerOrganizationId} from '../../utils/ledger-organization-registration-helpers';
import {createOrganizationUrn} from '../../utils/urn';
import {getEnvSectionId} from '../../utils/section-env';
import {getClinicalCreatorBindingsSectionId} from '../../utils/clinical-creator-binding';
import {generateKeyPairSync} from 'node:crypto';

describe('phone workforce actual manager persistence',()=>{
 it.each(['normal','wrong-role','malformed-subject','ambiguous'] as const)('binds phone workforce persistence and denies invalid assignment state: %s',async scenario=>{
  const previousEnv=process.env;
  process.env={...previousEnv,LEDGER_ENABLED:'false'};
  try{
   const tenantId=SAFE.tenantId,sector='health-care',vaultId=`${sector}_${tenantId}`;
   const providerDid=`${SAFE.didWeb}:${tenantId}:cds-es-md:v1:${sector}`;
   const contact={contactKind:'phone' as const,contact:SAFE.phoneE164},role=HealthcareActorRoles.Dentist;
   const stableActor=buildStableActorIdentifier(contact);
   const employeeDid=buildOrganizationEmployeeDidWeb({...contact,organizationDidWeb:providerDid,role});
   const controllerDid=`${providerDid}:employee:${stableActor.replace('urn:multibase:','')}:RESPRSN`;
   const tenantUrn=createOrganizationUrn({namespace:'cds',network:'test-network',jurisdiction:'ES-MD',sector,idType:'taxid',idValue:SAFE.organizationBusinessNumber});
   // Match TenantsCacheManager.toRuntimeView's actual ledger identifier source;
   // the separate clinical assignment owner is authored by EmployeeManager.
   const organizationLedgerIdentifier=resolveLedgerOrganizationId({[Organization.IdentifierType]:'taxid',[Organization.IdentifierValue]:SAFE.organizationBusinessNumber});
   const repository=new VaultMemRepository();
   const kms=mock<IKmsService>();
   kms.protectConfidentialData.mockImplementation(async document=>document);
   kms.unprotectConfidentialData.mockImplementation(async document=>(document as any).content);
   kms.getHmacBase64Url.mockImplementation(async value=>`protected:${value}`);
   kms.protectAttributesNameAndValue.mockImplementation(async attributes=>attributes.map(attribute=>({...attribute,name:`protected:${attribute.name}`,value:`protected:${attribute.value}`})));
   const tenants={getTenantIdentifierUrn:jest.fn(async()=>tenantUrn),getCollectionName:jest.fn(async()=>vaultId),
    getOrganizationIdentifierUrn:jest.fn(async()=>organizationLedgerIdentifier),tenantExists:jest.fn(async()=>true),
    getDidDocument:jest.fn(async()=>({id:providerDid,controller:[controllerDid]}))};
   await repository.put(vaultId,[{id:SAFE.demoOrganizationUuids.publicHealth,status:'available',sequence:0,content:{
    id:SAFE.demoOrganizationUuids.publicHealth,tenantId,userClass:'employee',type:'web',status:'available',orderId:'synthetic-seat-order',
    exp:Math.floor(Date.now()/1000)+3600,maxDevices:1,
   }}],getEnvSectionId('device-licenses'));
   const {publicKey:actorPublicKey}=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
   const publicKeys=[{kty:'AKP',alg:'ML-DSA-44',kid:'synthetic-recipient-signing',pub:'synthetic-public-signing',use:'sig'},
    {kty:'OKP',crv:'ML-KEM-768',kid:'synthetic-recipient-encryption',x:'synthetic-public-encryption',use:'enc'},
    {...actorPublicKey.export({format:'jwk'}),alg:'ES384',kid:'synthetic-recipient-actor-signing',use:'sig'}];
   const job=(resourceType:string,action:string,body:unknown,issuer=controllerDid):JobRequest=>({
    id:SAFE.resourceUuid,status:JobStatus.DRAFT,sequence:0,createdAtTimestamp:Date.now(),tenantId,sector,jurisdiction:'ES-MD',
    section:resourceType==='Employee'?'entity':'identity',format:resourceType==='Employee'?'org.schema':'openid',resourceType,action,
    contentType:'application/x-www-form-urlencoded',content:{iss:issuer,aud:providerDid,thid:SAFE.resourceUuid,jti:SAFE.resourceUuid,type:'application/api+json',body,
     meta:{bearer:{token:'Bearer synthetic-verified-phone-token',jwt:{payload:{phone_number:contact.contact,phone_number_verified:true,sub:'verified-controller'}}},
      jws:{protected:{alg:'ML-DSA-44',kid:'synthetic-controller-signing',jwk:{...publicKeys[0],kid:'synthetic-controller-signing',pub:'synthetic-controller-public'} as any}},
      jwe:{header:{enc:'A256GCM',jwk:{...publicKeys[1],kid:'synthetic-controller-encryption',x:'synthetic-controller-public-encryption'} as any}}}},
   } as unknown as JobRequest);
   const employeeClaims={[Person.Identifier]:employeeDid,[Person.SameAs]:employeeDid,[Person.Telephone]:contact.contact,[Person.HasOccupation]:role};
   const employeeManager=new EmployeeManager(repository,kms,tenants as any,{addVerificationMethodToTenant:jest.fn()} as any,{hostCollectionName:'host',hostDid:SAFE.didWeb});
   const created=await employeeManager.process(job('Employee','_batch',{data:[{type:'Employee-form-v1.0',request:{method:'POST'},resource:{id:SAFE.resourceUuid,meta:{claims:employeeClaims}}}]}));
   expect((created.body as any).data[0].response.status).toBe('201');
   const employeeResourceId=(created.body as any).data[0].resource.id;
   const employeeReplay=await employeeManager.process(job('Employee','_batch',{data:[{type:'Employee-form-v1.0',request:{method:'POST'},resource:{id:SAFE.demoOrganizationUuids.healthCare,meta:{claims:employeeClaims}}}]}));
   expect((employeeReplay.body as any).data[0]).toMatchObject({response:{status:'200'},resource:{id:employeeResourceId}});
   const employeeRows=await repository.getContainersInSection<any>(vaultId,getEnvSectionId('employees'));
   expect(employeeRows.filter(row=>row.content?.type==='Person')).toHaveLength(1);
   expect(employeeRows.filter(row=>row.type==='Occupation')).toHaveLength(1);
   const licenseManager=new LicenseManager(repository,kms,tenants as any);
   const issued=await licenseManager.process(job('License','_issue',{data:[{type:'License-issue-request-v1.0',meta:{subjectId:employeeResourceId,subjectDid:employeeDid},resource:{meta:{claims:{
    [Person.Telephone]:contact.contact,[Person.HasOccupation]:role,[Product.Category]:'professional',[Product.AdditionalType]:'web',
   }}}}]}));
   const seat=(issued.body as any).data[0];
   expect(seat).toMatchObject({response:{status:'201'}});
   const activationCode=seat.resource.meta.claims[Product.SerialNumber];
   const verifier=mock<ITokenVerifier>();
   verifier.verify.mockResolvedValue({valid:true,payload:{sub:'verified-phone-recipient',phone_number:contact.contact}} as any);
   const auth=new AppAuthorizationManager(repository,verifier,kms,mock<ICryptography>());
   await expect(auth.verifyAndConsumeActivationCode(activationCode,tenantId,sector,{subject:'foreign-account',email:SAFE.firstContactEmail,emailVerified:true},'foreign-installation')).rejects.toThrow('licensed phone');
   const tokens=new IdentityTokenManager(auth,{createInitialAccessToken:jest.fn(async()=> 'synthetic-host-initial-token')} as any);
   const exchange=job('Token','_exchange',{subject_token:activationCode,client_instance_id:'synthetic-installation'},employeeDid);
   const token=await tokens.process(exchange);
   expect((token.body as any).initial_access_token).toBe('synthetic-host-initial-token');
   const originalAssignments=await repository.getContainersInSection<any>(vaultId,getClinicalCreatorBindingsSectionId());
   expect(originalAssignments).toHaveLength(1);
   if(scenario==='wrong-role'||scenario==='ambiguous')await repository.put(vaultId,[{...originalAssignments[0],
    id:`urn:uuid:${SAFE.demoOrganizationUuids.healthCare}`,authorIdentifier:`urn:uuid:${SAFE.demoOrganizationUuids.healthCare}`,
    ...(scenario==='wrong-role'?{role:HealthcareActorRoles.MedicalDoctors}:{}),
   }],getClinicalCreatorBindingsSectionId());
   if(scenario==='malformed-subject'){
    const malformed=await repository.get<any>(vaultId,seat.meta.licenseId,getEnvSectionId('device-licenses'));
    await repository.put(vaultId,[{...malformed,content:{...malformed!.content,subjectId:'malformed-employee-id'}}],getEnvSectionId('device-licenses'));
   }
   const dcr=job('Device','_dcr',{code:activationCode,application_type:'web',redirect_uris:['http://localhost:4338/__/auth/handler'],
    actor_did:employeeDid,profile_did:employeeDid,jwks:{keys:publicKeys},ext_device_info:{device_id:'synthetic-installation'}},employeeDid);
   (dcr.content!.meta as any).bearer={token:'Bearer synthetic-host-initial-token',jwt:{payload:{sub:'verified-phone-recipient',act_code:activationCode,scope:'dcr:register'}}};
   const registered=await new DeviceRegistrationManager('https://example.invalid',repository,kms,tenants as any).process(dcr);
   const device=(registered.body as any).data[0];
   if(scenario==='malformed-subject'||scenario==='ambiguous'){
    expect(device).toMatchObject({response:{status:'409'}});
    expect(await repository.getContainersInSection(vaultId,getEnvSectionId('device-profiles'))).toHaveLength(0);
    const untouched=await repository.getContainersInSection<any>(vaultId,getClinicalCreatorBindingsSectionId());
    expect(untouched.every(binding=>!binding.actorDids&&!binding.dcrClientIds)).toBe(true);
    return;
   }
   expect(device.response.status).toBe('201');
   const persisted=await repository.get<any>(vaultId,device.resource.client_id,getEnvSectionId('device-profiles'));
   expect(persisted?.content).toMatchObject({clientId:device.resource.client_id,subjectId:employeeResourceId,stableActorIdentifier:stableActor,
    ext_device_info:{device_id:'synthetic-installation'},jwks:{keys:publicKeys},redirect_uris:['http://localhost:4338/__/auth/handler']});
   const assignments=await repository.getContainersInSection<any>(vaultId,getClinicalCreatorBindingsSectionId());
   expect(assignments).toHaveLength(scenario==='wrong-role'?2:1);
   expect(assignments.find(binding=>binding.role===role)).toMatchObject({actorIdentifier:`urn:uuid:${employeeResourceId}`,role,
    actorDids:expect.arrayContaining([employeeDid]),dcrClientIds:expect.arrayContaining([device.resource.client_id])});
   if(scenario==='wrong-role')expect(assignments.find(binding=>binding.role===HealthcareActorRoles.MedicalDoctors)).not.toHaveProperty('dcrClientIds');
   const licence=await repository.get<any>(vaultId,seat.meta.licenseId,getEnvSectionId('device-licenses'));
   expect(licence?.content).toMatchObject({issuedToPhone:contact.contact,issuedToRole:role,subjectId:employeeResourceId,activatedBy:stableActor,status:'active',maxDevices:1});
   expect(licence?.content.issuedToEmail).toBeFalsy();
   expect(await repository.getContainersInSection(vaultId,getEnvSectionId('device-licenses'))).toHaveLength(1);
   if(scenario==='normal'){
    // A retry after an unobserved acknowledgement uses new transport correlation,
    // while the exact authenticated installation and public key request stay fixed.
    const replayRequest=structuredClone(dcr);
    replayRequest.content!.thid=SAFE.demoOrganizationUuids.healthCare;
    replayRequest.content!.jti=SAFE.demoOrganizationUuids.publicHealth;
    const replayed=await new DeviceRegistrationManager('https://example.invalid',repository,kms,tenants as any).process(replayRequest);
    expect((replayed.body as any).data[0]).toMatchObject({response:{status:'201'},resource:{id:device.resource.id,client_id:device.resource.client_id}});
    expect(await repository.getContainersInSection(vaultId,getEnvSectionId('device-profiles'))).toHaveLength(1);
    const exchangedAgain=await tokens.process(exchange);
    expect((exchangedAgain.body as any).initial_access_token).toBe('synthetic-host-initial-token');
    const replaySeat=await repository.get<any>(vaultId,seat.meta.licenseId,getEnvSectionId('device-licenses'));
    expect(replaySeat?.content.deviceBindings.filter((binding:any)=>binding.status==='active')).toHaveLength(1);
    const employee=await repository.get<any>(vaultId,employeeResourceId,getEnvSectionId('employees'));
    expect(employee?.content.didDocument.verificationMethod.filter((method:any)=>publicKeys.some(key=>key.kid===method.publicKeyJwk.kid))).toHaveLength(publicKeys.length);
    expect(await repository.getContainersInSection(vaultId,getEnvSectionId('device-licenses'))).toHaveLength(1);
   }
   await expect(auth.verifyAndConsumeActivationCode(activationCode,tenantId,sector,{subject:'verified-phone-recipient',phone:contact.contact},'another-installation')).rejects.toThrow('Device allowance exhausted');
  }finally{process.env=previousEnv;}
 });
});
