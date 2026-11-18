// Flow contract: Communication write/search responses target the authenticated
// request actor, retaining provider issuer and thread. A SMART token issuer is
// the tenant trust authority and never selects the response recipient.
import { jest } from '@jest/globals';
import { CommunicationManager } from '../../../managers/CommunicationManager';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { buildOrganizationEmployeeDidWeb } from 'antifraud-data-utils-ts/organization-identity';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { buildCommunicationParticipantSearchParameters } from 'fhir-data-utils-ts/communication-participant-search';
import { buildExampleCommunicationParticipantSearchInput } from 'sos-data-utils-ts/gateway-resource-flow-examples';

const providerDid = SAFE.didWeb;
const actorDid = buildOrganizationEmployeeDidWeb({organizationDidWeb:providerDid,contactKind:'email',contact:SAFE.firstContactEmail,role:HealthcareActorRoles.Controller});
for (const action of ['_batch', '_search']) {
  it(`${action} binds response audience to request issuer rather than SMART issuer`, async () => {
    const manager = new CommunicationManager({
      tenantsCacheManager:{getTenantDid:jest.fn(async()=>providerDid)} as any,
      vaultRepository:{getAllSections:jest.fn(async()=>[]),listContainersInSection:jest.fn(async()=>[])} as any,
      kmsService:{getHmacBase64Url:jest.fn(async(value:string)=>value),protectAttributesNameAndValue:jest.fn(async(value:unknown)=>value)} as any,
    });
    const body=action==='_search'?buildCommunicationParticipantSearchParameters(buildExampleCommunicationParticipantSearchInput()):{data:[]};
    const response=await manager.process({tenantId:SAFE.resourceUuid,sector:'health-tech',resourceType:'Communication',action,content:{iss:actorDid,aud:providerDid,thid:SAFE.resourceUuid,body,meta:{bearer:{jwt:{payload:{iss:providerDid,sub:actorDid}}}}}} as any);
    expect(response.iss).toBe(providerDid);
    expect(response.aud).toBe(actorDid);
    expect(response.thid).toBe(SAFE.resourceUuid);
  });
}
