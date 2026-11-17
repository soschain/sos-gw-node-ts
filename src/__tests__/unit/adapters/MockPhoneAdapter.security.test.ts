// Flow contract: a mock never authenticates a webhook outside explicit local Demo; strict/local-test and deployed profiles deny synthetic signatures, while direct injected unit doubles retain deterministic OTP behavior without a real provider or external request.
import { MockPhoneAdapter } from '../../../adapters/phone/MockPhoneAdapter';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
const saved={...process.env};
beforeEach(()=>{process.env.NODE_ENV='test';process.env.DEPLOYMENT_ENV='local';process.env.NETWORK_MODE='test';process.env.SECURITY_MODE='strict';});
afterEach(()=>{process.env={...saved};});
it.each([
 {SECURITY_MODE:'strict'},
 {SECURITY_MODE:undefined},
 {SECURITY_MODE:'demo',NODE_ENV:'staging'},
 {SECURITY_MODE:'demo',DEPLOYMENT_ENV:'production'},
 {SECURITY_MODE:'demo',NETWORK_MODE:'test-network'},
])('denies synthetic webhook authentication in a non-Demo profile %o',overrides=>{
 Object.assign(process.env,overrides);if(overrides.SECURITY_MODE===undefined)delete process.env.SECURITY_MODE;
 expect(new MockPhoneAdapter().validateWebhookSignature(e.httpsBaseUrl,{},e.resourceUuid)).toBe(false);
});
it('permits simulated webhook authentication only in the explicit local Demo profile',()=>{
 process.env.SECURITY_MODE='demo';expect(new MockPhoneAdapter().validateWebhookSignature(e.httpsBaseUrl,{},e.resourceUuid)).toBe(true);
});
it('preserves deterministic OTP behavior for a directly injected unit double',async()=>{
 const adapter=new MockPhoneAdapter({fixedOtpCode:'123456'});await adapter.startVerify({to:e.phoneE164});
 await expect(adapter.checkVerify({to:e.phoneE164,code:'654321'})).resolves.toMatchObject({valid:false});
 await expect(adapter.checkVerify({to:e.phoneE164,code:'123456'})).resolves.toMatchObject({valid:true});
});
