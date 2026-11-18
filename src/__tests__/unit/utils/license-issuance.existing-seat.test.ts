// Flow contract: retrieving an existing usable licence preserves its original activation credential, active state, device bindings and subject; a first postal issue still uses its verified code, and ledger callbacks must complete before any local mutation.
import {describe,it,expect,jest} from '@jest/globals';
import {issueActivationCodeFromPool} from '../../../utils/license-issuance';
import {EXAMPLE_LICENSE_ACTIVE_RECORD,EXAMPLE_EMPLOYEE_ACTIVE_DEVICE_BINDINGS} from 'sos-data-utils-ts/gateway-resource-flow-examples';
import {EXAMPLE_EMAIL_PROFESSIONAL,EXAMPLE_FORM_CONTROLLER_PHONE,EXAMPLE_KYC_CONTROLLER_USER_UUID,EXAMPLE_PRIVATE_INDIVIDUAL_UUID,EXAMPLE_PROVIDER_ORGANIZATION_AUTHORIZATION_URN_CDS,EXAMPLE_TENANT_ROUTE_CONTEXT} from 'sos-data-utils-ts/gateway-flow-examples';
import {HealthcareActorRoles} from 'sos-data-utils-ts/healthcare-roles';
import {buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity';
import {DEFAULT_LICENSE_DEVICE_ALLOWANCE} from '../../../constants/domain';
import {DCR_REGISTRATION_JOB} from '../../data/example-jobs';

function fixture(){
 let stored:any={id:EXAMPLE_KYC_CONTROLLER_USER_UUID,status:'active',sequence:7,content:{...structuredClone(EXAMPLE_LICENSE_ACTIVE_RECORD),userClass:'employee',status:'active',issuedToEmail:EXAMPLE_EMAIL_PROFESSIONAL,issuedToRole:HealthcareActorRoles.GeneralistMedicalPractitioner,subjectId:EXAMPLE_KYC_CONTROLLER_USER_UUID,ownerOrganizationId:EXAMPLE_PROVIDER_ORGANIZATION_AUTHORIZATION_URN_CDS,activatedBy:buildStableActorIdentifier({contactKind:'email',contact:EXAMPLE_EMAIL_PROFESSIONAL}),deviceBindings:structuredClone(EXAMPLE_EMPLOYEE_ACTIVE_DEVICE_BINDINGS),maxDevices:DEFAULT_LICENSE_DEVICE_ALLOWANCE,exp:Math.floor(Date.now()/1000)+600}};
 const repository={getContainersInSection:jest.fn(async()=>[stored]),put:jest.fn(async(_vault:unknown,documents:any[])=>{stored=structuredClone(documents[0]);return true;})};
 const args={vaultRepository:repository as any,tenantVaultId:`${EXAMPLE_TENANT_ROUTE_CONTEXT.sector}_${EXAMPLE_TENANT_ROUTE_CONTEXT.tenantId}`,userClass:'employee' as const,type:'mobile' as const,email:EXAMPLE_EMAIL_PROFESSIONAL,role:HealthcareActorRoles.GeneralistMedicalPractitioner,subjectId:EXAMPLE_KYC_CONTROLLER_USER_UUID,ownerOrganizationId:EXAMPLE_PROVIDER_ORGANIZATION_AUTHORIZATION_URN_CDS,EXAMPLE_TENANT_ROUTE_CONTEXT};
 return {repository,args,get stored(){return stored;}};
}

describe('existing issued seat retrieval',()=>{
 it('returns the same credential and retains every active device without rewriting the seat',async()=>{
  const f=fixture(),before=structuredClone(f.stored);
  const first=await issueActivationCodeFromPool(f.args),second=await issueActivationCodeFromPool(f.args);
  expect(first.activationCode).toBe(before.content.activationCode);expect(second).toEqual(first);
  expect(f.stored).toEqual(before);expect(f.repository.put).not.toHaveBeenCalled();
 });
 it('preserves an existing credential when a repeated initial Order supplies a new first-issue hint',async()=>{
  const f=fixture(),before=structuredClone(f.stored);
  const result=await issueActivationCodeFromPool({...f.args,activationCode:String(DCR_REGISTRATION_JOB.content!.body!.code)});
  expect(result.activationCode).toBe(before.content.activationCode);expect(f.stored).toEqual(before);
 });
 it('honors a preverified postal credential on the first unused seat only',async()=>{
  const f=fixture();f.stored.status='available';f.stored.content.status='available';delete f.stored.content.activationCode;delete f.stored.content.issuedToEmail;delete f.stored.content.issuedToRole;delete f.stored.content.subjectId;delete f.stored.content.deviceBindings;
  const activationCode=String(DCR_REGISTRATION_JOB.content!.body!.code);
  expect((await issueActivationCodeFromPool({...f.args,activationCode})).activationCode).toBe(activationCode);
  expect(f.repository.put).toHaveBeenCalledTimes(1);
 });
 it('does not redirect an existing seat to another employee subject',async()=>{
  const f=fixture(),before=structuredClone(f.stored);
  await expect(issueActivationCodeFromPool({...f.args,subjectId:EXAMPLE_PRIVATE_INDIVIDUAL_UUID})).rejects.toThrow();
  expect(f.stored).toEqual(before);expect(f.repository.put).not.toHaveBeenCalled();
 });
 it.each(['revoked','inactive'])('does not reactivate a %s seat through ordinary issue',async status=>{
  const f=fixture();f.stored.status=status;f.stored.content.status=status;const before=structuredClone(f.stored);
  await expect(issueActivationCodeFromPool(f.args)).rejects.toThrow();
  expect(f.stored).toEqual(before);expect(f.repository.put).not.toHaveBeenCalled();
 });
 it('uses the canonical five-device fallback in the receipt without changing a historical seat',async()=>{
  const f=fixture();delete f.stored.content.maxDevices;const before=structuredClone(f.stored);
  expect((await issueActivationCodeFromPool(f.args)).maxDevices).toBe(DEFAULT_LICENSE_DEVICE_ALLOWANCE);
  expect(f.stored).toEqual(before);
 });
 it.each([EXAMPLE_FORM_CONTROLLER_PHONE,`tel:${EXAMPLE_FORM_CONTROLLER_PHONE}`])('retains a phone-only employee code and device list for normalized contact %s',async phone=>{
  const f=fixture();delete f.stored.content.issuedToEmail;f.stored.content.issuedToPhone=EXAMPLE_FORM_CONTROLLER_PHONE;f.stored.content.activatedBy=buildStableActorIdentifier({contactKind:'phone',contact:EXAMPLE_FORM_CONTROLLER_PHONE});const before=structuredClone(f.stored);
  expect((await issueActivationCodeFromPool({...f.args,email:undefined,phone})).activationCode).toBe(before.content.activationCode);
  expect(f.stored).toEqual(before);
 });
 it('still verifies the ledger callback against the retained code before returning it',async()=>{
  const f=fixture(),before=structuredClone(f.stored),beforePersist=jest.fn(async(license:any)=>{expect(license.activationCode).toBe(before.content.activationCode);});
  await issueActivationCodeFromPool({...f.args,beforePersist});
  expect(beforePersist).toHaveBeenCalledTimes(1);expect(f.stored).toEqual(before);
 });
 it('does not mutate existing local state if the ledger callback rejects issuance',async()=>{
  const f=fixture(),before=structuredClone(f.stored);
  await expect(issueActivationCodeFromPool({...f.args,beforePersist:async()=>{throw new Error('ledger authorization unavailable');}})).rejects.toThrow('ledger authorization unavailable');
  expect(f.stored).toEqual(before);expect(f.repository.put).not.toHaveBeenCalled();
 });
});
