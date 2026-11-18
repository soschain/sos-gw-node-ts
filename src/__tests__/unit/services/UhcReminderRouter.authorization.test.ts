/** Flow contract: a voice callback is processed only after provider signature verification and stored task authorization; invalid callbacks do not disclose prompts, mutate reminders or advance grouped tasks. */
import { describe, it, expect, jest } from '@jest/globals';
import express from 'express';
import request from 'supertest';
import { createUhcTaskReminderRouter } from '../../../routes/uhc-task-reminders.js';
import { encodeReminderPermissionBundle } from 'sos-data-utils-ts/reminder-metadata';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
const policy = () => encodeReminderPermissionBundle({subject: SAFE.didWeb, purpose:'reminder-delivery',rules:[{actorKind:'assistant',actorId:'voice-assistant',decision:'allow',actions:['execute'],entities:['dispatch-window'],channels:['phone'],purpose:'reminder-delivery'}]});
function harness({authorized=true,signature=true,debug=false}={}) {
 const task:any={id:'example-reminder',subjectId:SAFE.didWeb,status:'scheduled',createdAt:'2026-01-01T00:00:00Z',scheduledFor:'2026-01-01T00:00:00Z',metadata:authorized?policy():{}};
 const tasks=[task];
 const save=jest.fn(async()=>undefined),closeTask=jest.fn(async(input: {taskId:string;status?:string})=>{const entry=tasks.find(value=>value.id===input.taskId);if(entry)entry.status=input.status??'completed';return entry;}),scheduleTask=jest.fn(async()=>task);
 const service={getTask:jest.fn(async(id:string)=>tasks.find(entry=>entry.id===id)),listTasks:jest.fn(async()=>tasks),getRepository:()=>({save}),closeTask,scheduleTask};
 const verify=jest.fn((_url:string,_params:Record<string,string>,_signature:string)=>signature);
 const router=createUhcTaskReminderRouter({taskService:service as any,phoneAdapter:{validateWebhookSignature:verify} as any,apiBaseUrl:SAFE.httpsBaseUrl,voiceEnabled:true,debugApiEnabled:debug,maxAttempts:1,retryIntervalMinutes:5,groupWindowMinutes:5,autoRescheduleOnNoResponse:false});
 const app=express();app.use('/reminders',router);return{app,task,tasks,service,save,closeTask,scheduleTask,verify};
}
describe('reminder callback authority',()=>{
 it('rejects a forged provider callback before rendering its supplied prompt',async()=>{
  const h=harness({signature:false});const response=await request(h.app).post('/reminders/voice/prompt?taskId=example-reminder&prompt=private-prompt').set('X-Twilio-Signature','invalid-signature').type('form').send({});
  expect(response.status).toBe(403);expect(response.text).not.toContain('private-prompt');expect(h.verify).toHaveBeenCalled();expect(h.service.getTask).not.toHaveBeenCalled();expect(h.save).not.toHaveBeenCalled();
 });
 it('rejects an unsigned callback before task mutation',async()=>{
  const h=harness();const response=await request(h.app).post('/reminders/voice/dtmf?taskId=example-reminder').type('form').send({Digits:'1'});
  expect(response.status).toBe(403);expect(h.save).not.toHaveBeenCalled();expect(h.closeTask).not.toHaveBeenCalled();
 });
 it('rejects validly signed callbacks for tasks without explicit policy',async()=>{
  const h=harness({authorized:false});const response=await request(h.app).post('/reminders/voice/dtmf?taskId=example-reminder').set('X-Twilio-Signature','example-signature').type('form').send({Digits:'1'});
  expect(response.status).toBe(403);expect(h.save).not.toHaveBeenCalled();expect(h.closeTask).not.toHaveBeenCalled();expect(h.scheduleTask).not.toHaveBeenCalled();
 });
 it('does not advance from an authorized task to an unauthorized sibling',async()=>{
  const h=harness();h.task.metadata['part-of']='example-parent';h.task.metadata.type='appointment';
  h.tasks.push({...h.task,id:'forbidden-sibling',title:'forbidden-sibling-label',metadata:{'part-of':'example-parent'}});
  const response=await request(h.app).post('/reminders/voice/dtmf?taskId=example-reminder').set('X-Twilio-Signature','example-signature').type('form').send({Digits:'1'});
  expect(response.status).toBe(200);expect(h.closeTask).toHaveBeenCalledWith(expect.objectContaining({taskId:'example-reminder'}));expect(h.scheduleTask).not.toHaveBeenCalled();expect(response.text).not.toContain('forbidden-sibling-label');
 });
 it('does not let an authorized child authorize a manual call on an unapproved parent',async()=>{
  const h=harness({authorized:false,debug:true});h.tasks.push({...h.task,id:'authorized-child',metadata:{...policy(),'part-of':h.task.id}});
  const response=await request(h.app).post('/reminders/call/start').send({taskId:h.task.id,to:SAFE.phoneE164});
  expect(response.status).toBe(403);expect(h.save).not.toHaveBeenCalled();
 });
 it('does not close an unapproved parent when an authorized child completes',async()=>{
  const h=harness();h.task.metadata['part-of']='unapproved-parent';h.task.metadata.type='appointment';h.tasks.push({...h.task,id:'unapproved-parent',metadata:{}});
  const response=await request(h.app).post('/reminders/voice/dtmf?taskId=example-reminder').set('X-Twilio-Signature','example-signature').type('form').send({Digits:'1'});
  expect(response.status).toBe(200);expect(h.closeTask).toHaveBeenCalledWith(expect.objectContaining({taskId:'example-reminder'}));expect(h.closeTask).not.toHaveBeenCalledWith(expect.objectContaining({taskId:'unapproved-parent'}));
 });
 it('validates against the configured public URL despite forged forwarding headers',async()=>{
  const h=harness();await request(h.app).post('/reminders/voice/prompt?taskId=example-reminder').set('X-Twilio-Signature','example-signature').set('X-Forwarded-Host','attacker.invalid').set('X-Forwarded-Proto','http').type('form').send({});
  expect(h.verify).toHaveBeenCalledWith(`${SAFE.httpsBaseUrl}/reminders/voice/prompt?taskId=example-reminder`,{},'example-signature');
 });
 it('renders an authorized reminder only after successful provider verification',async()=>{
  const h=harness();const response=await request(h.app).post('/reminders/voice/prompt?taskId=example-reminder').set('X-Twilio-Signature','example-signature').type('form').send({});
  expect(response.status).toBe(200);expect(h.verify).toHaveBeenCalled();expect(response.text).toContain('<Response>');
 });
});
