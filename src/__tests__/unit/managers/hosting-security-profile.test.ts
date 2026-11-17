// Flow contract: host activation and controller fallbacks use only the explicit local Demo security profile. A deployment label, NODE_ENV=demo, staging or a Fabric network never grants permission to bypass cryptographic checks.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import {assertConfiguredRuntimeSecurityProfile,isLocalDemoSecurityModeForConfiguration} from '../../../security/runtime-security-policy';
const unexpectedFabric=()=>{throw new Error('Unexpected Fabric transport in security-profile unit.');};
jest.unstable_mockModule('@hyperledger/fabric-gateway',()=>({connect:unexpectedFabric,signers:{newPrivateKeySigner:unexpectedFabric},checkpointers:{inMemory:unexpectedFabric,file:unexpectedFabric}}));
const {HostingManager}=await import('../../../managers/HostingManager');
const previous=process.env;
const mode=(config:Record<string,string>)=>(HostingManager.prototype as any).isDemoSecurityMode.call({config});
beforeEach(()=>{process.env={...previous,SECURITY_MODE:'strict',NETWORK_MODE:'test',NODE_ENV:'test'};});
afterEach(()=>{process.env=previous;});
describe('host activation security profile',()=>{
 it('exposes one startup assertion over both actual and configured profiles',()=>{
  const config={securityMode:'demo',networkMode:'test',nodeEnv:'test'};
  expect(()=>assertConfiguredRuntimeSecurityProfile(config)).not.toThrow();
  for(const env of [{NODE_ENV:'production'},{DEPLOYMENT_ENV:'staging'},{NETWORK_MODE:'test-network'}]){
   expect(isLocalDemoSecurityModeForConfiguration(config,{...process.env,...env})).toBe(false);
   expect(()=>assertConfiguredRuntimeSecurityProfile(config,{...process.env,...env})).toThrow(/demonstration profile/);
  }
  expect(()=>assertConfiguredRuntimeSecurityProfile({securityMode:'strict',networkMode:'test-network',nodeEnv:'production'})).not.toThrow();
 });

 it('requires explicit Demo in an entirely local test profile',()=>{
  expect(mode({securityMode:'demo',networkMode:'test',nodeEnv:'test'})).toBe(true);
  expect(mode({securityMode:'strict',networkMode:'test',nodeEnv:'demo'})).toBe(false);
 });
 it('rejects Demo shortcuts in staging, production and every Fabric profile',()=>{
  for(const nodeEnv of ['staging','production'])expect(mode({securityMode:'demo',networkMode:'test',nodeEnv})).toBe(false);
  for(const networkMode of ['local-network','test-network','network'])expect(mode({securityMode:'demo',networkMode,nodeEnv:'test'})).toBe(false);
  for(const actualEnvironment of ['production','staging']){process.env.NODE_ENV=actualEnvironment;expect(mode({securityMode:'demo',networkMode:'test',nodeEnv:'test'})).toBe(false);}
  process.env.NODE_ENV='test';
  for(const actualNetwork of ['local-network','test-network','network']){process.env.NETWORK_MODE=actualNetwork;expect(mode({securityMode:'demo',networkMode:'test',nodeEnv:'test'})).toBe(false);}
  process.env.NETWORK_MODE='test';
  process.env.DEPLOYMENT_ENV='staging';expect(mode({securityMode:'demo',networkMode:'test',nodeEnv:'test'})).toBe(false);
 });
});
