// Flow contract: the tenant DID points to compact identity discovery metadata;
// SMART metadata advertises the tenant's authenticated verification endpoint.
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {DidServiceIds,DidServiceTypes} from 'sos-data-utils-ts/gateway-did-profile';
import {populateDidDocumentServices} from '../../../utils/did-document';
import {DiscoveryService} from '../../../services/DiscoveryService';

describe('identity discovery metadata',()=>{
 it('links the two identity metadata documents from a healthcare tenant DID',()=>{
  const context={alternateName:e.tenantId,jurisdiction:e.countryIso2,version:'v1',sector:e.sector};
  const services=populateDidDocumentServices(e.didWeb,e.httpsBaseUrl,[],true,context);
  expect(services).toEqual(expect.arrayContaining([
   expect.objectContaining({id:e.didWeb+DidServiceIds.OpenIdConfiguration,type:DidServiceTypes.OpenIdProvider}),
   expect.objectContaining({id:e.didWeb+DidServiceIds.SmartConfiguration,type:DidServiceTypes.SmartOnFhirConfiguration}),
  ]));
 });
 it('does not advertise healthcare identity documents for an unrelated sector',()=>{
  const context={alternateName:e.tenantId,jurisdiction:e.countryIso2,version:'v1',sector:'unrelated'};
  const services=populateDidDocumentServices(e.didWeb,e.httpsBaseUrl,[],true,context);
  expect(services.some(s=>s.id===e.didWeb+DidServiceIds.SmartConfiguration)).toBe(false);
 });
 it('publishes the operational introspection URL and private key authentication',async()=>{
  const discovery=new DiscoveryService({getTenantDomainUrl:async()=>e.httpsBaseUrl,getTenantOperationalUrl:async()=>e.httpsBaseUrl+'/'+e.tenantId} as any);
  expect(await discovery.getSmartConfiguration(e.tenantId)).toMatchObject({
   introspection_endpoint:`${e.httpsBaseUrl}/${e.tenantId}/identity/openid/smart/token/_verify`,
   introspection_endpoint_auth_methods_supported:['private_key_jwt'],
  });
 });
});
