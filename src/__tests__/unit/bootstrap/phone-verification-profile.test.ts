// Flow contract: composing enabled phone verification requires a configured real provider outside explicit local Demo, including actual deployment labels that disagree with an injected test config. No Twilio request is sent and route-level injected unit doubles remain outside this composition boundary.
import { buildPhoneVerificationAdapter } from '../../../bootstrap/build-phone-verification-adapter';
import { MockPhoneAdapter } from '../../../adapters/phone/MockPhoneAdapter';
import { TwilioPhoneAdapter } from '../../../adapters/phone/TwilioPhoneAdapter';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
const saved={...process.env};
beforeEach(()=>{process.env.NODE_ENV='test';process.env.DEPLOYMENT_ENV='local';process.env.NETWORK_MODE='test';process.env.SECURITY_MODE='strict';});
afterEach(()=>{process.env={...saved};});
const config=(overrides:Record<string,unknown>={})=>({nodeEnv:'test',securityMode:'strict',networkMode:'test',uhcTelephony:{verifyEnabled:true,provider:'mock'},...overrides} as any);
it('does not substitute a mock when strict local verification lacks a real provider',()=>{
 expect(()=>buildPhoneVerificationAdapter(config())).toThrow(/provider|twilio/i);
});
it.each(['staging','production'])('honors the actual deployed %s label over a demo test config',nodeEnv=>{
 process.env.NODE_ENV=nodeEnv;process.env.SECURITY_MODE='demo';
 expect(()=>buildPhoneVerificationAdapter(config({securityMode:'demo'}))).toThrow(/provider|twilio/i);
});
it('preserves explicit local UI Demo with a simulated provider',()=>{
 process.env.SECURITY_MODE='demo';expect(buildPhoneVerificationAdapter(config({securityMode:'demo'}))).toBeInstanceOf(MockPhoneAdapter);
});
it('does not let a demo config hide actual strict security',()=>{
 expect(()=>buildPhoneVerificationAdapter(config({securityMode:'demo'}))).toThrow(/provider|twilio/i);
});
it('selects a configured real Twilio Verify adapter without contacting Twilio',()=>{
 const suffix=e.resourceUuid.replaceAll('-','');
 expect(buildPhoneVerificationAdapter(config({uhcTelephony:{verifyEnabled:true,provider:'twilio',twilio:{accountSid:`AC${suffix}`,authToken:e.resourceUuid,verifyServiceSid:`VA${suffix}`}}}))).toBeInstanceOf(TwilioPhoneAdapter);
});
it.each(['accountSid','authToken','verifyServiceSid'])('rejects missing real Verify configuration %s',missing=>{
 const suffix=e.resourceUuid.replaceAll('-','');const twilio:any={accountSid:`AC${suffix}`,authToken:e.resourceUuid,verifyServiceSid:`VA${suffix}`};delete twilio[missing];
 expect(()=>buildPhoneVerificationAdapter(config({uhcTelephony:{verifyEnabled:true,provider:'twilio',twilio}}))).toThrow(/provider|twilio/i);
});

it('rejects blank Verify configuration rather than treating whitespace as a real service',()=>{
 const suffix=e.resourceUuid.replaceAll('-','');
 expect(()=>buildPhoneVerificationAdapter(config({uhcTelephony:{verifyEnabled:true,provider:'twilio',twilio:{accountSid:`AC${suffix}`,authToken:e.resourceUuid,verifyServiceSid:'   '}}}))).toThrow(/provider|twilio/i);
});
