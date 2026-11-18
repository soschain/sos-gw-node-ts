// Flow contract: 1. Reject anonymous or unsupported-media verifier requests.
// 2. Pass only the server-bound route context and signed inputs to the manager.
// 3. Return its original signed receipt/credential and prevent caching.
// These routing contracts do not substitute for native signature/state tests.
import express from 'express';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {createApiRouter} from '../../../routes/api';
import {invokeExpress} from '../helpers/invokeExpress';

describe('tenant verification routes',()=>{
 const prefix=`/${e.tenantId}/cds-${e.countryIso2}/v1/${e.sector}/identity`;
 const clientType='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
 function fixture(legacyPublicUrls: readonly string[] = []){
  const compliance={verify:jest.fn().mockResolvedValue({credentialJwt:'original.signed.credential'})};
  const presentations={verify:jest.fn().mockResolvedValue('original.signed.receipt')};
  const app=express();app.use(express.json());app.use(express.urlencoded({extended:true}));
  app.use((createApiRouter as any)({}, {}, {}, {}, {}, {},e.httpsBaseUrl,undefined,undefined,undefined,undefined,false,compliance,presentations,legacyPublicUrls));
  return{app,compliance,presentations};
 }
 it('requires backend authentication before invoking the native verifier',async()=>{
  const f=fixture();const response=await invokeExpress(f.app,{method:'POST',url:prefix+'/openid/presentation/_verify',headers:{'content-type':'application/json'},body:{}});
  expect(response.status).toBe(401);expect(f.presentations.verify).not.toHaveBeenCalled();
 });
 it('binds the signed backend request to the configured server URL and returns its receipt',async()=>{
  const f=fixture();const url=prefix+'/openid/presentation/_verify';
  const response=await invokeExpress(f.app,{method:'POST',url,headers:{'content-type':'application/json',authorization:'Bearer backend.signed.assertion',host:'untrusted.invalid'},body:{vp_token:'signed.wallet.presentation'}});
  expect(response.status).toBe(200);expect(response.text).toBe('original.signed.receipt');
  expect(response.headers['cache-control']).toBe('no-store');
  expect(f.presentations.verify).toHaveBeenCalledWith(expect.objectContaining({requestUrl:e.httpsBaseUrl+url,assertion:'backend.signed.assertion'}));
 });
 it('preserves the standard-compliance credential and exact tenant route context',async()=>{
  const f=fixture();const response=await invokeExpress(f.app,{method:'POST',url:prefix+'/gaia-x/standard-compliance',headers:{'content-type':'application/x-www-form-urlencoded'},body:{vp_token:'signed.tenant.presentation',client_assertion:'signed.client.assertion',client_assertion_type:clientType}});
  expect(response.status).toBe(201);expect(response.text).toBe('original.signed.credential');
  expect(response.headers['content-type']).toContain('application/vc+jwt');
  expect(f.compliance.verify).toHaveBeenCalledWith(expect.objectContaining({tenantId:e.tenantId,sector:e.sector,jurisdiction:e.countryIso2,clientAssertionType:clientType}));
 });
 it.each(['openid/presentation/_verify','gaia-x/standard-compliance'])('uses only an explicitly approved Host origin for %s assertion audience',async endpoint=>{
  const legacy=new URL(e.httpsBaseUrl);legacy.port='8443';const f=fixture([legacy.origin]);const url=prefix+'/'+endpoint;
  const isPresentation=endpoint.startsWith('openid');
  const response=await invokeExpress(f.app,{method:'POST',url,headers:{host:legacy.host,'x-forwarded-host':'untrusted.invalid','content-type':isPresentation?'application/json':'application/x-www-form-urlencoded',authorization:'Bearer backend.signed.assertion'},body:{vp_token:'signed.wallet.presentation',client_assertion:'signed.client.assertion',client_assertion_type:clientType}});
  expect(response.status).toBe(isPresentation?200:201);
  expect((isPresentation?f.presentations:f.compliance).verify).toHaveBeenCalledWith(expect.objectContaining({requestUrl:legacy.origin+url}));
 });
 it('rejects the wrong media type before standard-compliance verification',async()=>{
  const f=fixture();const response=await invokeExpress(f.app,{method:'POST',url:prefix+'/gaia-x/standard-compliance',headers:{'content-type':'application/json'},body:{}});
  expect(response.status).toBe(415);expect(f.compliance.verify).not.toHaveBeenCalled();
 });
});
