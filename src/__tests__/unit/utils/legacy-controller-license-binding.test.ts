// Flow contract: resolve an old controller seat only from the protected current tenant designation and exact active employee; preserve actor keys and licence authority across an additional installation.
import { describe, expect, it, jest } from '@jest/globals';
import {SchemaOrgOrganizationClaim,SchemaOrgPersonClaim,SchemaOrgServiceClaim} from 'antifraud-data-utils-ts/schema-org-claims';
import { HealthcareActorRoles, HealthcareActorRoleCodes } from 'sos-data-utils-ts/healthcare-roles';
import { HL7_CODING_SYSTEM_V3_ROLE_CODE } from 'fhir-data-utils-ts';
import { EXAMPLE_CONTROLLER_DID, EXAMPLE_EMAIL_PROFESSIONAL, EXAMPLE_LEGAL_ORGANIZATION_TAX_ID, EXAMPLE_TENANT_ROUTE_CONTEXT, EXAMPLE_KYC_CONTROLLER_USER_UUID, EXAMPLE_EMAIL_CONTROLLER_INDIVIDUAL, EXAMPLE_FORM_CONTROLLER_PHONE, EXAMPLE_PROVIDER_ORGANIZATION_AUTHORIZATION_URN_CDS } from 'sos-data-utils-ts/gateway-flow-examples';
import { issueActivationCodeFromPool } from '../../../utils/license-issuance';
import { resolveHostPhysicalCollectionName } from '../../../config/storage-layout';
import { getEnvSectionId } from '../../../utils/section-env';
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:()=>{throw new Error('Unexpected Fabric transport in isolated controller licence unit.');},signers:{newPrivateKeySigner:()=>{throw new Error('Unexpected Fabric signer in controller licence unit.');}},checkpointers:{inMemory:()=>({}),file:()=>({})}}));
const {DeviceRegistrationManager}=await import('../../../managers/DeviceRegistrationManager');
import { DCR_REGISTRATION_JOB } from '../../data/example-jobs';
import cloneDeep from 'lodash.clonedeep';
import {normalizeControllerAlias as normalizeSameAsHash} from 'antifraud-data-utils-ts/public-aliases';
import {buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity';
import { createEmployeeUrn, createEmployeeUrnFromStableActorIdentifier, getTenantIdentifierUrnPrefix,parseTenantUrn } from '../../../utils/urn';
import { generateTenantCollectionNameFromClaims, getTenantVaultId } from '../../../utils/tenant';
import { URN_NAMESPACE, URN_NETWORK, URN_VERSION } from '../../data/urn.data';
import {testTenant1IdType} from '../../data/organization.data';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import {VaultMemRepository} from '../../../database/repositories/vault/vault.mem.repository';
import {EXAMPLE_EMPLOYEE_ACTIVE_DEVICE_BINDINGS} from 'sos-data-utils-ts/gateway-resource-flow-examples';
import {DCR_REPLAY_PUBLIC_KEYS} from '../../data/dcr-replay-public-keys';
import {IdentityAuthActions,IdentityAuthRequestFields} from 'sos-data-utils-ts/identity-auth-wire-contract';
import { HttpStatusCodes } from 'sos-data-utils-ts/bff-wire-contract';

const URN_ORGANIZATION_ID_TYPE=testTenant1IdType;
function fixture() {
  const route = EXAMPLE_TENANT_ROUTE_CONTEXT;
  const role = HealthcareActorRoles.GeneralistMedicalPractitioner;
  const claims: Record<string, unknown> = {
    [SchemaOrgOrganizationClaim.AlternateName]: route.tenantId,
    [SchemaOrgOrganizationClaim.AddressCountry]: route.jurisdiction,
    [SchemaOrgOrganizationClaim.IdentifierType]: URN_ORGANIZATION_ID_TYPE,
    [SchemaOrgOrganizationClaim.IdentifierValue]: EXAMPLE_LEGAL_ORGANIZATION_TAX_ID,
    [SchemaOrgServiceClaim.Category]: route.sector,
  };
  const tenantVaultId = getTenantVaultId(route.sector, route.tenantId);
  const employeeUrn = createEmployeeUrn({namespace: URN_NAMESPACE, network: URN_NETWORK, jurisdiction: route.jurisdiction, version: URN_VERSION, sector: route.sector, idType: URN_ORGANIZATION_ID_TYPE, idValue: EXAMPLE_LEGAL_ORGANIZATION_TAX_ID, email: EXAMPLE_EMAIL_PROFESSIONAL, role});
  claims[SchemaOrgOrganizationClaim.IdentifierReference] = getTenantIdentifierUrnPrefix(employeeUrn);
  const tenant = { status: 'active', claims, didDocument: {controller: [EXAMPLE_CONTROLLER_DID]} };
  const employee = {id: EXAMPLE_CONTROLLER_DID, status: 'active', claims: {[SchemaOrgPersonClaim.Email]: EXAMPLE_EMAIL_PROFESSIONAL, [SchemaOrgPersonClaim.HasOccupation]: role, [SchemaOrgPersonClaim.AdditionalType]: HealthcareActorRoles.Controller} as Record<string, unknown>, didDocument: {id: EXAMPLE_CONTROLLER_DID, alsoKnownAs: [employeeUrn], verificationMethod: []}};
  const license: any = {ownerOrganizationId:EXAMPLE_LEGAL_ORGANIZATION_TAX_ID,userClass: 'employee', status: 'active', activatedBy: normalizeSameAsHash(EXAMPLE_EMAIL_PROFESSIONAL), issuedToEmail: EXAMPLE_EMAIL_PROFESSIONAL, issuedToRole: role, exp: Math.floor(Date.now()/1000)+600};
  const repository = {get: jest.fn(async (collection: string, id: string) => collection === resolveHostPhysicalCollectionName() && id === tenantVaultId ? {id, jwe: {ciphertext: 'tenant'}} : collection === generateTenantCollectionNameFromClaims(claims) && id === employee.id ? {id, jwe: {ciphertext: 'employee'}} : undefined)};
  const kms = {unprotectConfidentialData: jest.fn(async (doc: any, _vault?:string) => doc.jwe.ciphertext === 'tenant' ? tenant : employee)};
  const manager = new DeviceRegistrationManager('http://localhost:3001', repository as any, kms as any, {getCollectionName: async () => generateTenantCollectionNameFromClaims(claims)});
  const job = cloneDeep(DCR_REGISTRATION_JOB);
  Object.assign(job, route);
  const resolveSubject = () => (manager as any).prepareEmployeeDeviceIdentityContext({job, vaultId: tenantVaultId, license, registrationRequest: {...job.content!.body,actor_did:employee.didDocument.id,profile_did:employee.didDocument.id}, clientId:'new-device'});
  return {tenant,employee,license, repository,kms, resolveSubject};
}

describe('protected legacy controller licence subject', () => {
  it('resolves the real controller id without replacing its original occupational licence role', async () => {
    const f=fixture();
    expect(await f.resolveSubject()).toMatchObject({subjectId:f.employee.id, licensedRole:f.license.issuedToRole});
    expect(f.license.issuedToRole).not.toBe(HealthcareActorRoles.Controller);
    expect(f.kms.unprotectConfidentialData).toHaveBeenCalledWith(expect.anything(), 'host');
  });
  it.each(['tenant-inactive','employee-inactive','wrong-role','wrong-contact','foreign-actor','not-controller','wrong-sector','wrong-tenant','expired','revoked'] as const)('rejects %s without writing', async (change) => {
    const f=fixture();
    if(change==='tenant-inactive') f.tenant.status='inactive';
    if(change==='employee-inactive') f.employee.status='inactive';
    if(change==='wrong-role') f.license.issuedToRole=HealthcareActorRoles.Veterinarian;
    if(change==='wrong-contact') f.employee.claims[SchemaOrgPersonClaim.Email]='';
    if(change==='foreign-actor') f.license.activatedBy=normalizeSameAsHash(EXAMPLE_EMAIL_CONTROLLER_INDIVIDUAL);
    if(change==='not-controller') f.tenant.didDocument.controller=[];
    if(change==='wrong-sector') f.tenant.claims[SchemaOrgServiceClaim.Category]='';
    if(change==='wrong-tenant') f.tenant.claims[SchemaOrgOrganizationClaim.AlternateName]='';
    if(change==='expired') f.license.exp=1;
    if(change==='revoked') f.license.status='revoked';
    await expect(f.resolveSubject()).rejects.toThrow();
  });
  it.each(['inactive', 'revoked', 'foreign-record'] as const)('rejects a %s tenant envelope even when its protected content is active', async (status) => {
    const f = fixture();
    const originalGet = f.repository.get.getMockImplementation()!;
    f.repository.get.mockImplementation(async (collection: string, id: string) => {
      const document = await originalGet(collection, id);
      return collection === resolveHostPhysicalCollectionName() && document
        ? {...document, ...(status === 'foreign-record' ? {id: EXAMPLE_KYC_CONTROLLER_USER_UUID} : {status})}
        : document;
    });
    await expect(f.resolveSubject()).rejects.toMatchObject({code: IssueType.Forbidden});
  });
  it('does not guess from a contact when the protected tenant is absent', async () => {
    const f=fixture(); f.repository.get.mockResolvedValue(undefined);
    await expect(f.resolveSubject()).rejects.toThrow();
  });
  it('reports an unverified controller binding as an authorization denial', async () => {
    const f=fixture(); f.tenant.didDocument.controller=[];
    await expect(f.resolveSubject()).rejects.toMatchObject({ code: IssueType.Forbidden, status: String(HttpStatusCodes.Forbidden) });
  });
  it('rechecks an inactive controller even when its licence already has a subject link', async () => {
    const f=fixture(); f.license.subjectId=f.employee.id; f.employee.status='inactive';
    await expect(f.resolveSubject()).rejects.toMatchObject({ code: IssueType.Forbidden, status: String(HttpStatusCodes.Forbidden) });
  });
  it('does not let an existing subject link override a removed current controller designation', async () => {
    const f=fixture(); f.license.subjectId=f.employee.id; f.tenant.didDocument.controller=[];
    await expect(f.resolveSubject()).rejects.toMatchObject({ code: IssueType.Forbidden, status: String(HttpStatusCodes.Forbidden) });
  });
  it('resolves a designated technical controller from its protected sameAs and controller licence without rewriting its occupation or keys', async () => {
    const f=fixture();
    const occupation=f.employee.claims[SchemaOrgPersonClaim.HasOccupation];
    f.license.issuedToRole=HealthcareActorRoles.Controller;
    f.employee.claims={
      [SchemaOrgPersonClaim.Identifier]:f.employee.id,
      [SchemaOrgPersonClaim.SameAs]:f.license.activatedBy,
      [SchemaOrgPersonClaim.AdditionalType]:HealthcareActorRoles.Controller,
      [SchemaOrgPersonClaim.OccupationalCategory]:[occupation],
    };
    f.employee.didDocument.alsoKnownAs=[];
    const before=structuredClone(f.employee);
    const employeeUrn=createEmployeeUrnFromStableActorIdentifier({
      organizationUrn:String(f.tenant.claims[SchemaOrgOrganizationClaim.IdentifierReference]),
      stableActorIdentifier:f.license.activatedBy,role:f.license.issuedToRole,
    });
    expect(await f.resolveSubject()).toMatchObject({subjectId:f.employee.id,licensedRole:HealthcareActorRoles.Controller,employeeUrn});
    expect(f.employee).toEqual(before);
  });
  it('repairs the missing subject link idempotently without rotating the code, seat or existing devices', async () => {
    const f=fixture();
    const original = {id:'legacy-seat',status:'active',sequence:7,content:{...f.license,activationCode:'retained-test-credential',deviceBindings:[{clientId:'first-installation',clientInstanceId:'first-installation',status:'active'}]}};
    let stored=structuredClone(original);
    const put=jest.fn(async (_vault:any, docs:any[], _section?:string) => {stored=structuredClone(docs[0]);return true;});
    const repo={...f.repository,getContainersInSection:async()=>[stored],put};
    const args={vaultRepository:repo as any,kmsService:f.kms as any,tenantVaultId:getTenantVaultId(EXAMPLE_TENANT_ROUTE_CONTEXT.sector,EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId),userClass:'employee' as const,type:'mobile' as const,email:f.license.issuedToEmail,role:f.license.issuedToRole,subjectId:f.employee.id};
    const first=await issueActivationCodeFromPool(args);
    expect(stored.content).toEqual({...original.content,subjectId:f.employee.id});
    expect(stored.sequence).toBe(8);
    expect(first).toMatchObject({licenseId:original.id,activationCode:original.content.activationCode});
    expect(await issueActivationCodeFromPool(args)).toEqual(first);
    expect(put).toHaveBeenCalledTimes(1);
    expect(put).toHaveBeenCalledWith(args.tenantVaultId,expect.anything(),getEnvSectionId('device-licenses'));
  });
  it('keeps an encrypted licence encrypted while repairing its subject link', async () => {
    const f = fixture();
    const license = {...f.license, activationCode: 'retained-test-credential'};
    const original = {id: 'protected-legacy-seat', status: 'active', sequence: 2, jwe: {ciphertext: 'seat'}};
    const originalUnprotect = f.kms.unprotectConfidentialData.getMockImplementation()!;
    f.kms.unprotectConfidentialData.mockImplementation(async (document: any) =>
      document.jwe.ciphertext === 'seat' ? license : originalUnprotect(document));
    const protect = jest.fn(async (document: any, _vault?:string) => ({id: document.id, status: document.status, sequence: document.sequence, jwe: {ciphertext: 'reprotected-seat'}}));
    const put = jest.fn(async (..._args:any[]) => true);
    const repository = {...f.repository, getContainersInSection: async () => [original], put};
    const kms = {...f.kms, protectConfidentialData: protect};
    const vaultId = getTenantVaultId(EXAMPLE_TENANT_ROUTE_CONTEXT.sector, EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId);
    const result = await issueActivationCodeFromPool({vaultRepository: repository as any, kmsService: kms as any, tenantVaultId: vaultId, userClass: 'employee', type: 'mobile', email: license.issuedToEmail, role: license.issuedToRole, subjectId: f.employee.id});
    expect(result.activationCode).toBe(license.activationCode);
    expect(protect).toHaveBeenCalledWith(expect.objectContaining({content: {...license, subjectId: f.employee.id}}), vaultId);
    expect(put).toHaveBeenCalledWith(vaultId, [{...original, sequence: 3, jwe: {ciphertext: 'reprotected-seat'}}], getEnvSectionId('device-licenses'));
    expect(license.subjectId).toBeUndefined();
  });
  it('refuses to redirect a licence already linked to another employee', async () => {
    const f=fixture();
    const put=jest.fn(async(..._args:any[])=>true);
    const repo={...f.repository,getContainersInSection:async()=>[{id:'legacy-seat',content:{...f.license,activationCode:'retained-test-credential',subjectId:'different-existing-employee'}}],put};
    await expect(issueActivationCodeFromPool({vaultRepository:repo as any,kmsService:f.kms as any,tenantVaultId:getTenantVaultId(EXAMPLE_TENANT_ROUTE_CONTEXT.sector,EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId),userClass:'employee',type:'mobile',email:f.license.issuedToEmail,role:f.license.issuedToRole,subjectId:f.employee.id})).rejects.toMatchObject({ code: IssueType.Conflict, status: String(HttpStatusCodes.Conflict) });
    expect(put).not.toHaveBeenCalled();
  });
  it('reuses the original personal member seat and code without changing its existing device bindings', async () => {
    const f=fixture();
    const stored={id:'personal-seat',content:{...f.license,userClass:'individual',issuedToRole:`${HL7_CODING_SYSTEM_V3_ROLE_CODE}|${HealthcareActorRoleCodes.Controller}`,activationCode:'retained-test-credential'}};
    const put=jest.fn(async(..._args:any[])=>true);
    const repo={getContainersInSection:async()=>[stored],put};
    const result=await issueActivationCodeFromPool({vaultRepository:repo as any,tenantVaultId:getTenantVaultId(EXAMPLE_TENANT_ROUTE_CONTEXT.sector,EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId),userClass:'individual',type:'mobile',email:f.license.issuedToEmail,role:stored.content.issuedToRole,subjectId:EXAMPLE_KYC_CONTROLLER_USER_UUID});
    expect(result.activationCode).toBe(stored.content.activationCode);
    expect(put).not.toHaveBeenCalled();
  });
  it('resolves a designated phone-only technical controller from the protected actor alias',async()=>{
    const f=fixture();
    delete f.license.issuedToEmail;
    f.license.issuedToPhone=EXAMPLE_FORM_CONTROLLER_PHONE;
    f.license.activatedBy=buildStableActorIdentifier({contactKind:'phone',contact:EXAMPLE_FORM_CONTROLLER_PHONE});
    f.license.issuedToRole=HealthcareActorRoles.Controller;
    f.employee.claims={
      [SchemaOrgPersonClaim.SameAs]:f.license.activatedBy,
      [SchemaOrgPersonClaim.AdditionalType]:HealthcareActorRoles.Controller,
      [SchemaOrgPersonClaim.OccupationalCategory]:[HealthcareActorRoles.GeneralistMedicalPractitioner],
    };
    f.employee.didDocument.alsoKnownAs=[];
    expect(await f.resolveSubject()).toMatchObject({subjectId:f.employee.id,licensedRole:HealthcareActorRoles.Controller,actorIdentifier:f.license.activatedBy});
  });
  it('preserves an older account marker during authorized seat repair and still requires fresh exchange before DCR', async () => {
    const f=fixture();
    f.license.activatedBy='firebase:historical-test-account';
    let stored={id:'legacy-seat',status:'active',sequence:1,content:{...f.license,activationCode:'retained-test-credential'}};
    const put=jest.fn(async (_vault:unknown,rows:any[])=>{stored=structuredClone(rows[0]);return true;});
    const repo={...f.repository,getContainersInSection:async()=>[stored],put};
    const result=await issueActivationCodeFromPool({vaultRepository:repo as any,kmsService:f.kms as any,tenantVaultId:getTenantVaultId(EXAMPLE_TENANT_ROUTE_CONTEXT.sector,EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId),userClass:'employee',type:'mobile',email:f.license.issuedToEmail,role:f.license.issuedToRole,subjectId:f.employee.id});
    expect(result.activationCode).toBe('retained-test-credential');
    expect(stored.content.activatedBy).toBe(f.license.activatedBy);
    expect(stored.content.subjectId).toBe(f.employee.id);
    await expect(f.resolveSubject()).rejects.toMatchObject({code:IssueType.BusinessRule});
    expect(put).toHaveBeenCalledTimes(1);
  });
  it('revokes only one controller device when the DID retains an occupational URN before its controller URN',async()=>{
    const f=fixture(),repository=new VaultMemRepository(),route=EXAMPLE_TENANT_ROUTE_CONTEXT;
    const vaultId=getTenantVaultId(route.sector,route.tenantId),collection=generateTenantCollectionNameFromClaims(f.tenant.claims);
    const manager=new DeviceRegistrationManager('http://localhost:3001',repository,undefined,{getCollectionName:async()=>collection,getOrganizationIdentifierUrn:async()=>String(f.tenant.claims[SchemaOrgOrganizationClaim.IdentifierReference])});
    const employee:any=structuredClone(f.employee),role=HealthcareActorRoles.Controller;
    const controllerUrn=createEmployeeUrnFromStableActorIdentifier({organizationUrn:String(f.tenant.claims[SchemaOrgOrganizationClaim.IdentifierReference]),stableActorIdentifier:f.license.activatedBy,role});
    employee.didDocument.alsoKnownAs.push(controllerUrn);
    const methods=(manager as any).buildVerificationMethodsForDid(employee.didDocument.id,{keys:DCR_REPLAY_PUBLIC_KEYS.slice(0,2)});
    employee.didDocument.verificationMethod=methods;
    employee.didDocument.authentication=methods.map((method:any)=>method.id);
    await repository.put(collection,[{id:employee.id,status:'active',content:employee} as any],getEnvSectionId('employees'));
    const bindings=structuredClone(EXAMPLE_EMPLOYEE_ACTIVE_DEVICE_BINDINGS),first=bindings[0],second=bindings[1];
    await repository.put(vaultId,[{id:EXAMPLE_KYC_CONTROLLER_USER_UUID,status:'active',content:{...f.license,id:EXAMPLE_KYC_CONTROLLER_USER_UUID,subjectId:employee.id,issuedToRole:role,deviceBindings:bindings}} as any],getEnvSectionId('device-licenses'));
    await repository.put(vaultId,[first,second].map((binding,index)=>({id:binding.clientId,status:'active',content:{clientId:binding.clientId,status:'active',verificationMethodIds:[methods[index].id]}})) as any,getEnvSectionId('device-profiles'));
    const job=cloneDeep(DCR_REGISTRATION_JOB);Object.assign(job,route);job.action=IdentityAuthActions.Revoke;
    job.content!.body={[IdentityAuthRequestFields.LicenseId]:EXAMPLE_KYC_CONTROLLER_USER_UUID,[IdentityAuthRequestFields.ClientId]:first.clientId} as any;
    const previous=process.env.NETWORK_MODE;process.env.NETWORK_MODE='test';
    try{
      const result=await manager.process(job);
      expect((result.body as any).data[0].response.status).toBe(String(HttpStatusCodes.Ok));
      const updated:any=await repository.get(collection,employee.id,getEnvSectionId('employees'));
      expect(updated.content.didDocument.verificationMethod.map((method:any)=>method.id)).toEqual([methods[1].id]);
      expect(updated.content.didDocument.alsoKnownAs).toEqual(employee.didDocument.alsoKnownAs);
      const other:any=await repository.get(vaultId,second.clientId,getEnvSectionId('device-profiles'));
      expect(other.status).toBe('active');
    }finally{if(previous===undefined)delete process.env.NETWORK_MODE;else process.env.NETWORK_MODE=previous;}
  });

});
