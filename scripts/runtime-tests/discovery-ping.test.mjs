// Flow contract: actual Express ping retains UTF-8 JSON/base64url, unsigned trailing-dot wire, host/port and bounded claims through the injected process crypto port; JSON/FHIR negotiation remains independently checked.
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import {request} from 'node:http';
import {readFileSync} from 'node:fs';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {AdapterCryptoSdkNode} from '../../src/gdc-backend-utils-node/adapters/node/crypto.ts';
import {pingHandler} from '../../src/routes/handlers/discovery/ping.handler.ts';
const instant=Date.parse('2030-01-01T10:00:00.000Z'),tenantId=safe.tenantId+'-caf\u00e9-\u6c34';
const crypto=new CryptographyService(new AdapterCryptoSdkNode());
const vector=()=>JSON.parse(readFileSync(new URL('../tests/fixtures/ping-unsigned-legacy-vector.json',import.meta.url),'utf8'));
async function server(t){
 const calls=[],port={jwsToCompact:input=>{calls.push(structuredClone(input));return crypto.jwsToCompact(input)}};
 const app=express();app.use((_req,res,next)=>{res.locals.tenantId=tenantId;next()});app.get('/ping',pingHandler(port));
 // Port zero is an atomic kernel lease; only this test owns and closes the listener.
 const listener=app.listen(0,'127.0.0.1');await once(listener,'listening');
 t.after(()=>new Promise((resolve,reject)=>{listener.close(error=>error?reject(error):resolve());listener.closeAllConnections();}));
 const address=listener.address();assert.ok(address&&typeof address==='object');
 // node:http lets this real socket request carry an explicit virtual Host;
 // Node fetch replaces that header with its connection authority.
 const get=accept=>new Promise((resolve,reject)=>{
  const outgoing=request({hostname:'127.0.0.1',port:address.port,path:'/ping',method:'GET',headers:{accept,host:`${safe.domain}:8443`}},incoming=>{
   const chunks=[];incoming.on('data',chunk=>chunks.push(chunk));incoming.on('error',reject);
   incoming.on('end',()=>resolve({status:incoming.statusCode,headers:incoming.headers,body:Buffer.concat(chunks).toString('utf8')}));
  });outgoing.setTimeout(5000,()=>outgoing.destroy(new Error('owned_ping_request_timeout')));outgoing.on('error',reject);outgoing.end();
 });
 return {get,calls};
}
test('actual form response uses the injected port with exact Unicode JSON and an empty signature',async t=>{
 t.mock.timers.enable({apis:['Date'],now:instant});const f=await server(t),response=await f.get('application/x-www-form-urlencoded');
 assert.equal(response.status,200);assert.match(response.headers['content-type'],/^application\/x-www-form-urlencoded/u);
 const body=response.body;assert.match(body,/^response=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/u);
 assert.equal(f.calls.length,1,'Handler must use its injected process-owned crypto port');
 const [input]=f.calls;assert.deepEqual(input.protected,{alg:'none'});assert.equal(input.signature,'');
 assert.equal(input.payload.iss,`did:web:${safe.domain}%3A8443`);assert.equal(input.payload.aud,'anonymous');
 assert.equal(input.payload.type,'ping-response');assert.equal(input.payload.thid,`ping-${instant}`);assert.equal(input.payload.exp,Math.floor(instant/1000)+300);
 assert.match(input.payload.jti,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
 assert.equal(input.payload.body.meta.tenantId,tenantId);assert.equal(input.payload.body.meta.timestamp,new Date(instant).toISOString());
 assert.equal(input.payload.body.data[0].issue[0].diagnostics,'Ping successful');
 const expected=Buffer.from(JSON.stringify(input.protected),'utf8').toString('base64url')+'.'+Buffer.from(JSON.stringify(input.payload),'utf8').toString('base64url')+'.';
 assert.equal(new URLSearchParams(body).get('response'),expected);
});
test('ordinary JSON remains a direct outcome envelope without invoking compact serialization',async t=>{
 t.mock.timers.enable({apis:['Date'],now:instant});const f=await server(t),response=await f.get('application/json');assert.equal(response.status,200);assert.match(response.headers['content-type'],/^application\/json/u);
 assert.equal(response.body,JSON.stringify(vector().payload.body));assert.equal(f.calls.length,0);
});
test('FHIR negotiation contains the actual OperationOutcome resource without invoking compact serialization',async t=>{
 const f=await server(t),response=await f.get('application/fhir+json'),body=JSON.parse(response.body);assert.equal(response.status,200);
 assert.deepEqual(body,{resourceType:'Bundle',type:'batch-response',total:1,entry:[{resource:vector().payload.body.data[0],response:{status:'200'}}]});
 assert.match(response.headers['content-type'],/^application\/fhir\+json/u);assert.equal(f.calls.length,0);
});
test('the fixed unsigned object profile matches the recorded legacy and independent native UTF-8 vectors',()=>{
 const fixture=vector();
 const actual=crypto.jwsToCompact({protected:fixture.header,payload:fixture.payload,signature:''});
 assert.equal(actual,fixture.compact);
 assert.equal(actual,Buffer.from(JSON.stringify(fixture.header),'utf8').toString('base64url')+'.'+Buffer.from(JSON.stringify(fixture.payload),'utf8').toString('base64url')+'.');
 assert.equal(actual.endsWith('.'),true);
});
