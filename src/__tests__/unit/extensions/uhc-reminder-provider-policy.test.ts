/** Flow contract: optional unconfigured voice stays unavailable; explicitly enabled network voice requires usable real credentials, while only the explicit local demo may select a synthetic phone provider. */
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import express from 'express';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { registerUhcReminderExtension } from '../../../extensions/unid/register-uhc-reminders.js';
const original={...process.env};
afterEach(()=>{process.env={...original};jest.restoreAllMocks();});
function register(telephony:any={}) {
 const app=express(),use=jest.spyOn(app,'use');
 registerUhcReminderExtension({app,config:{tasksCore:{enabled:true,apiEnabled:true,workerEnabled:false},uhcTelephony:telephony,apiBaseUrl:SAFE.httpsBaseUrl} as any,taskService:{} as any,vaultRepository:{} as any,kmsService:{} as any,tenantManager:{} as any});
 return use;
}
describe('voice provider registration',()=>{
 it('does not expose phone routes when optional network voice is unconfigured',()=>{
  process.env.SECURITY_MODE='strict';process.env.NETWORK_MODE='test';process.env.DEPLOYMENT_ENV='staging';
  expect(register()).not.toHaveBeenCalled();
 });
 it('rejects explicitly enabled network voice without real provider credentials',()=>{
  process.env.SECURITY_MODE='strict';process.env.NETWORK_MODE='test';process.env.DEPLOYMENT_ENV='staging';
  expect(()=>register({voiceEnabled:true,provider:'mock'})).toThrow();
  expect(()=>register({voiceEnabled:true,provider:'twilio'})).toThrow();
 });
 it('keeps synthetic providers confined to an explicitly configured local demo',()=>{
  process.env.SECURITY_MODE='demo';process.env.NETWORK_MODE='test';process.env.DEPLOYMENT_ENV='local';process.env.NODE_ENV='test';
  expect(register({voiceEnabled:true,provider:'mock'})).toHaveBeenCalled();
 });
});
