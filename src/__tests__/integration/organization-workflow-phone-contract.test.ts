// Flow contract: real phone Employee/Occupation, licence and DCR writers feed actual routed Group/workflow Consent managers. Assignment requires current controller/provider/member authority; exact revocation preserves other groups. The test injects verified principal/transport ports and identity KMS, so it is not HTTP cryptography, Firebase or chain proof.
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
import {buildStableActorIdentifier,buildOrganizationEmployeeDidWeb,buildAuthorityDidWeb} from 'antifraud-data-utils-ts/organization-identity';
import {SchemaOrgPersonClaim as Person,SchemaOrgIndividualProductClaim as Product,SchemaOrgOrganizationClaim as Organization,SchemaOrgServiceClaim as Service} from 'antifraud-data-utils-ts/schema-org-claims';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {JobStatus,type JobRequest} from 'sos-data-utils-ts/confidential-job';
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';
import {resolveLedgerOrganizationId} from '../../utils/ledger-organization-registration-helpers';
import {createOrganizationUrn} from '../../utils/urn';
import {getEnvSectionId} from '../../utils/section-env';
import {getClinicalCreatorBindingsSectionId} from '../../utils/clinical-creator-binding';
import {generateKeyPairSync} from 'node:crypto';

import {GroupManager,buildGroupMemberProjectionId,buildGroupMemberSectionId} from '../../managers/GroupManager';
import {ResearchStudyConsentManager,ORGANIZATION_WORKFLOW_CONSENT_SECTION} from '../../managers/ResearchStudyConsentManager';
import {ConsentManager} from '../../managers/ConsentManager';
import {ClaimConsent,ConsentStatuses,ConsentDecisions,HealthcareConsentPurposes} from 'fhir-data-utils-ts';
import {buildOrganizationControllerWorkflowAssignment,buildOrganizationSubjectRegisterCapability,OrganizationWorkflowGroupKinds,OrganizationWorkflowCapabilities} from 'sos-data-utils-ts/organization-workflow-access';
import {admitIndividualRegistration} from '../../utils/individual-registration-admission';
import {computeRfc7638JwkThumbprint} from 'antifraud-data-utils-ts/jwk-thumbprints';
import type {ITenantsManager} from '../../managers/ITenantsManager';

const cleanups:(()=>void)[]=[];
afterEach(()=>{for(const cleanup of cleanups.splice(0))cleanup()});
async function fixture(){
 const previousEnv=process.env;process.env={...previousEnv,LEDGER_ENABLED:'false'};
 try{
   const tenantId=SAFE.tenantId,sector='health-care',vaultId=`${sector}_${tenantId}`;
   const providerDid=`${buildAuthorityDidWeb({authority:SAFE.httpsBaseUrl})}:${tenantId}:cds-es-md:v1:${sector}`;
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
   const tenants=mock<ITenantsManager>();
   tenants.getTenantIdentifierUrn.mockResolvedValue(tenantUrn);
   tenants.getCollectionName.mockResolvedValue(vaultId);
   tenants.getOrganizationIdentifierUrn.mockResolvedValue(organizationLedgerIdentifier);
   tenants.getTenantDid.mockResolvedValue(providerDid);
   tenants.getTenantJurisdiction.mockResolvedValue('ES-MD');
   tenants.tenantExists.mockResolvedValue(true);
   tenants.getDidDocument.mockResolvedValue({'@context':['https://www.w3.org/ns/did/v1'],id:providerDid,controller:[controllerDid]});
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
   const employeeManager=new EmployeeManager(repository,kms,tenants,{addVerificationMethodToTenant:jest.fn()} as any,{hostCollectionName:'host',hostDid:SAFE.didWeb});
   const created=await employeeManager.process(job('Employee','_batch',{data:[{type:'Employee-form-v1.0',request:{method:'POST'},resource:{id:SAFE.resourceUuid,meta:{claims:employeeClaims}}}]}));
   expect((created.body as any).data[0].response.status).toBe('201');
   const employeeResourceId=(created.body as any).data[0].resource.id;
   const employeeReplay=await employeeManager.process(job('Employee','_batch',{data:[{type:'Employee-form-v1.0',request:{method:'POST'},resource:{id:SAFE.demoOrganizationUuids.healthCare,meta:{claims:employeeClaims}}}]}));
   expect((employeeReplay.body as any).data[0]).toMatchObject({response:{status:'200'},resource:{id:employeeResourceId}});
   const employeeRows=await repository.getContainersInSection<any>(vaultId,getEnvSectionId('employees'));
   expect(employeeRows.filter(row=>row.content?.type==='Person')).toHaveLength(1);
   expect(employeeRows.filter(row=>row.type==='Occupation')).toHaveLength(1);
   const licenseManager=new LicenseManager(repository,kms,tenants);
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
   const dcr=job('Device','_dcr',{code:activationCode,application_type:'web',redirect_uris:['http://localhost:4338/__/auth/handler'],
    actor_did:employeeDid,profile_did:employeeDid,jwks:{keys:publicKeys},ext_device_info:{device_id:'synthetic-installation'}},employeeDid);
   (dcr.content!.meta as any).bearer={token:'Bearer synthetic-host-initial-token',jwt:{payload:{sub:'verified-phone-recipient',act_code:activationCode,scope:'dcr:register'}}};
   const registered=await new DeviceRegistrationManager('https://example.invalid',repository,kms,tenants as any).process(dcr);
   const device=(registered.body as any).data[0];

   expect(device.response.status).toBe('201');
   const occupations=await repository.getContainersInSection<any>(vaultId,getEnvSectionId('employees'));
   const occupation=occupations.find(record=>record.type==='Occupation'&&record.employeeId===employeeResourceId);
   if(!occupation)throw new Error('actual_employee_occupation_missing');
   const organizationReference=`Organization/${tenantId}`,memberReference=`PractitionerRole/${occupation.id}`;
   const workflowJob=(resourceType:string,entries:readonly unknown[],issuer=controllerDid):JobRequest=>{
    const base=job(resourceType,'_batch',{data:entries},issuer);
    return {...base,section:'organization',format:'org.hl7.fhir.r5'};
   };
   const groups=new GroupManager({vaultRepository:repository,kmsService:kms,tenantManager:tenants});
   const consents=new ResearchStudyConsentManager({vaultRepository:repository,kmsService:kms,tenantManager:tenants});
   const plan=(groupId:string,subjectRegistration=false)=>buildOrganizationControllerWorkflowAssignment({networkKind:'test-network',controller:{authorityKind:'organization-controller',organizationReference,accountId:SAFE.resourceUuid},member:{accountId:SAFE.resourceUuid,practitionerRoleReference:memberReference,role},groupKind:subjectRegistration?OrganizationWorkflowGroupKinds.SubjectRegistration:OrganizationWorkflowGroupKinds.EncounterOperations,groupReference:`Group/${groupId}`,capabilities:subjectRegistration?[buildOrganizationSubjectRegisterCapability(organizationReference)]:[OrganizationWorkflowCapabilities.EncounterCruds,OrganizationWorkflowCapabilities.EncounterHistoryCruds],assignedAt:new Date().toISOString()});
   const assign=async(value:ReturnType<typeof plan>)=>{
    expect(((await groups.process(workflowJob('Group',[value.group]))).body as any).data[0].response.status).toBe('201');
    expect(((await groups.process(workflowJob('Group',[value.membership]))).body as any).data[0].response.status).toBe('200');
    return consents.process(workflowJob('Consent',[value.authorization]));
   };
   const professionalJob=job('Organization','_register',{},employeeDid);
   if(!professionalJob.content)throw new Error('fixture_envelope_missing');
   Object.assign(professionalJob.content,{client_id:device.resource.client_id});
   const signingKey=publicKeys.find(key=>key.kid==='synthetic-recipient-signing');
   if(!signingKey)throw new Error('actual_registered_key_missing');
   const admittedJob=Object.assign(professionalJob,{authenticatedTransport:{kind:'registered-didcomm' as const,actorDid:employeeDid,signingKeyId:signingKey.kid,signingKeyThumbprint:await computeRfc7638JwkThumbprint(signingKey),signedClientId:device.resource.client_id}});
   const admission=()=>admitIndividualRegistration({job:admittedJob,claims:{[Service.Category]:sector,[Organization.OwnerTelephone]:SAFE.secondContactPhoneE164},vaultRepository:repository,kmsService:kms,tenantManager:tenants});
   return {repository,kms,tenants,groups,consents,workflowJob,plan,assign,admission,vaultId,employeeResourceId,memberReference,controllerDid,employeeDid,cleanup:()=>{process.env=previousEnv}};
 }catch(error){process.env=previousEnv;throw error}
}
async function ready(){const value=await fixture();cleanups.push(value.cleanup);return value}
it('actual phone writer and explicit governed workflow grant authorize subject registration',async()=>{
 const f=await ready(),value=f.plan(SAFE.demoOrganizationUuids.publicHealth,true);
 expect(((await f.assign(value)).body as any).data[0].response.status).toBe('201');
 await expect(f.admission()).resolves.toEqual({sector:'health-care'});
});
it('full inactive PUT preserves an independent group grant until that grant is separately revoked',async()=>{
 const f=await ready(),first=f.plan(SAFE.demoOrganizationUuids.publicHealth,true),second=f.plan(SAFE.demoOrganizationUuids.healthCare,true);
 expect(((await f.assign(first)).body as any).data[0].response.status).toBe('201');
 expect(((await f.assign(second)).body as any).data[0].response.status).toBe('201');
 const before=await f.repository.getContainersInSection<any>(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION);expect(before).toHaveLength(2);
 const inactive={...first.authorization,request:{method:'PUT',url:`Consent/${first.authorization.resource.id}`},resource:{...first.authorization.resource,meta:{claims:{...first.authorization.resource.meta.claims,[ClaimConsent.status]:ConsentStatuses.Inactive}}}};
 const revoked=await f.consents.process(f.workflowJob('Consent',[inactive]));expect((revoked.body as any).data[0].response.status).toBe('200');
 const rows=await f.repository.getContainersInSection<any>(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION);expect(rows).toHaveLength(2);
 const stored=(id:string)=>rows.find(row=>row.id===id)?.content.claims;
 expect(stored(first.authorization.resource.id)[ClaimConsent.status]).toEqual([ConsentStatuses.Inactive]);
 expect(stored(second.authorization.resource.id)[ClaimConsent.status]).toEqual([ConsentStatuses.Active]);
 await expect(f.admission()).resolves.toEqual({sector:'health-care'});
 const secondInactive={...second.authorization,request:{method:'PUT',url:`Consent/${second.authorization.resource.id}`},resource:{...second.authorization.resource,meta:{claims:{...second.authorization.resource.meta.claims,[ClaimConsent.status]:ConsentStatuses.Inactive}}}};
 expect(((await f.consents.process(f.workflowJob('Consent',[secondInactive]))).body as any).data[0].response.status).toBe('200');
 await expect(f.admission()).rejects.toThrow('verified controller or an authorized licensed professional');
});
it('matching controller DID with a foreign verified bearer cannot create workflow authority',async()=>{
 const f=await ready(),value=f.plan(SAFE.demoOrganizationUuids.publicHealth,true);
 await f.groups.process(f.workflowJob('Group',[value.group]));await f.groups.process(f.workflowJob('Group',[value.membership]));
 const request=f.workflowJob('Consent',[value.authorization]);
 if(!request.content?.meta?.bearer?.jwt)throw new Error('fixture_verified_bearer_missing');
 request.content.meta.bearer.jwt.payload={sub:'foreign-verified-account',phone_number:SAFE.secondContactPhoneE164};
 await expect(f.consents.process(request)).rejects.toThrow('authenticated current tenant controller');
 expect(await f.repository.getContainersInSection(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION)).toHaveLength(0);
});
it('an employee cannot self-grant and ordinary patient Consent still requires its evidence attachment',async()=>{
 const f=await ready(),value=f.plan(SAFE.demoOrganizationUuids.publicHealth,true);
 await f.groups.process(f.workflowJob('Group',[value.group]));await f.groups.process(f.workflowJob('Group',[value.membership]));
 await expect(f.consents.process(f.workflowJob('Consent',[value.authorization],f.employeeDid))).rejects.toThrow('current tenant controller');
 const ordinary=new ConsentManager({vaultRepository:f.repository,tenantsCacheManager:f.tenants});
 const base=f.workflowJob('Consent',[{resource:{resourceType:'Consent',id:SAFE.resourceUuid,meta:{claims:{[ClaimConsent.status]:ConsentStatuses.Active,[ClaimConsent.decision]:ConsentDecisions.Permit,[ClaimConsent.subject]:SAFE.resourceUuid,[ClaimConsent.identifier]:`urn:uuid:${SAFE.resourceUuid}`,[ClaimConsent.date]:new Date().toISOString(),[ClaimConsent.purpose]:HealthcareConsentPurposes.Operations,[ClaimConsent.action]:'read',[ClaimConsent.actorRole]:HealthcareActorRoles.Dentist,[ClaimConsent.actorIdentifier]:f.memberReference}}},request:{method:'POST',url:'Consent'}}]);
 const denied=await ordinary.process({...base,section:'individual',format:'org.hl7.fhir.api'});
 expect((denied.body as any).data[0].response.status).toBe('400');
 expect((denied.body as any).data[0].response.outcome.issue[0].diagnostics).toContain('attachment');
});

it('full PUT cannot replace stored targets, scope or provenance while claiming revocation',async()=>{
 const f=await ready(),value=f.plan(SAFE.demoOrganizationUuids.publicHealth,true);
 expect(((await f.assign(value)).body as any).data[0].response.status).toBe('201');
 const before=await f.repository.getContainersInSection<any>(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION);
 for(const change of [{[ClaimConsent.actorRole]:HealthcareActorRoles.MedicalDoctors},{[ClaimConsent.sourceReference]:`Group/${SAFE.demoOrganizationUuids.healthCare}`},{[ClaimConsent.action]:OrganizationWorkflowCapabilities.CompositionCuds},{[ClaimConsent.date]:new Date(Date.now()+1000).toISOString()}]){
  const changed={...value.authorization,request:{method:'PUT',url:`Consent/${value.authorization.resource.id}`},resource:{...value.authorization.resource,meta:{claims:{...value.authorization.resource.meta.claims,...change,[ClaimConsent.status]:ConsentStatuses.Inactive}}}};
  const result=await f.consents.process(f.workflowJob('Consent',[changed]));
  expect((result.body as any).data[0].response.status).toBe('400');
  expect(await f.repository.getContainersInSection(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION)).toEqual(before);
 }
});
it('the current controller may revoke the exact stale grant and legacy status-only PATCH remains supported',async()=>{
 const f=await ready(),value=f.plan(SAFE.demoOrganizationUuids.publicHealth,true);
 expect(((await f.assign(value)).body as any).data[0].response.status).toBe('201');
 const removed=await f.groups.process(f.workflowJob('Group',[{...value.membership,request:{method:'DELETE',url:value.groupReference}}]));
 expect((removed.body as any).data[0].response.status).toBe('204');
 expect(await f.repository.get(f.vaultId,buildGroupMemberProjectionId(SAFE.demoOrganizationUuids.publicHealth,f.memberReference),buildGroupMemberSectionId(SAFE.demoOrganizationUuids.publicHealth))).toBeUndefined();
 const inactive={...value.authorization,request:{method:'PUT',url:`Consent/${value.authorization.resource.id}`},resource:{...value.authorization.resource,meta:{claims:{...value.authorization.resource.meta.claims,[ClaimConsent.status]:ConsentStatuses.Inactive}}}};
 expect(((await f.consents.process(f.workflowJob('Consent',[inactive]))).body as any).data[0].response.status).toBe('200');
 const before=await f.repository.getContainersInSection(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION);
 expect(((await f.consents.process(f.workflowJob('Consent',[inactive]))).body as any).data[0].response.status).toBe('200');
 expect(await f.repository.getContainersInSection(f.vaultId,ORGANIZATION_WORKFLOW_CONSENT_SECTION)).toEqual(before);
 const patch={request:{method:'PATCH',url:`Consent/${value.authorization.resource.id}`},resource:{resourceType:'Consent',id:value.authorization.resource.id,meta:{claims:{[ClaimConsent.status]:ConsentStatuses.Inactive}}}};
 expect(((await f.consents.process(f.workflowJob('Consent',[patch]))).body as any).data[0].response.status).toBe('200');
});
