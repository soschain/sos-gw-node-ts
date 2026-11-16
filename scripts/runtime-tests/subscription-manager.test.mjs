// Flow contract: real encrypted IVault subscriptions preserve matching, denial and restart retry wire bytes.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {SubscriptionManager} from '../../src/managers/SubscriptionManager.ts';
import {VaultMemRepository} from '../../src/database/repositories/vault/vault.mem.repository.ts';
import {KmsService} from '../../src/services/KmsService.ts';
import {TenantsCacheManager} from '../../src/managers/TenantsCacheManager.ts';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {AdapterCryptoSdkNode} from '../../src/gdc-backend-utils-node/adapters/node/crypto.ts';
import {InMemoryEnvelopeAdapter} from '../../src/services/kms-envelope-adapter.ts';
import {InMemoryWrappedKeyRepository} from '../../src/services/wrapped-key-repository.ts';
import {getEnvSectionId} from '../../src/utils/section-env.ts';
import {getTenantVaultId} from '../../src/utils/tenant.ts';
import {JobStatus} from 'sos-data-utils-ts/confidential-job';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
const instant='2030-01-01T10:00:00.000Z',topicUrl=`${safe.httpsBaseUrl}/SubscriptionTopic/observations`;
const observation={resourceType:'Observation',id:'observation-one',status:'final',subject:{reference:`Patient/${safe.resourceUuid}`}};
function job(resources){return {id:safe.resourceUuid,status:JobStatus.SUBMITTING,sequence:0,createdAtTimestamp:Date.parse(instant),tenantId:safe.tenantId,jurisdiction:safe.countryIso2,sector:'health-care',section:'entity',format:'org.hl7.fhir.r5',resourceType:resources[0].resourceType,action:'_batch',content:{iss:safe.didWeb,aud:safe.didWeb,jti:safe.resourceUuid,thid:safe.resourceUuid,type:'batch',body:{entry:resources.map(resource=>({resource}))}}};}
function topic(resource='Observation',filters=[{resource:'Observation',filterParameter:'patient',comparator:['eq']}]){return {resourceType:'SubscriptionTopic',id:'observations-topic',url:topicUrl,status:'active',resourceTrigger:[{resource}],canFilterBy:filters};}
function subscription(extra={}){return {resourceType:'Subscription',id:'observations',topic:topicUrl,status:'requested',channelType:{code:'rest-hook'},endpoint:`${safe.httpsBaseUrl}/hooks`,filterBy:[{resourceType:'Observation',filterParameter:'patient',value:`Patient/${safe.resourceUuid}`}],...extra};}
function reverseKeys(value){return Array.isArray(value)?value.map(reverseKeys):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).reverse().map(([key,item])=>[key,reverseKeys(item)])):value;}
async function fixture(t,reorder=false){
 const saved={NODE_ENV:process.env.NODE_ENV,DEV_SEED:process.env.DEV_SEED};process.env.NODE_ENV='development';process.env.DEV_SEED='true';
 const vaultRepository=new VaultMemRepository(),vaultId=getTenantVaultId('health-care',safe.tenantId);
 await vaultRepository.put('subscription-test-host',[{id:'host'}]);
 await vaultRepository.put('subscription-test-host',[{id:vaultId}],getEnvSectionId('tenants'));
 await vaultRepository.createNewVault({id:vaultId});assert.equal(await vaultRepository.vaultExists(vaultId),true);
 let kmsService;const tenants=new TenantsCacheManager(vaultRepository,()=>kmsService,safe.tenantId);
 kmsService=new KmsService(new CryptographyService(new AdapterCryptoSdkNode()),tenants,{wrappedKeyRepository:new InMemoryWrappedKeyRepository(),envelopeAdapter:new InMemoryEnvelopeAdapter()});
 t.after(()=>{kmsService.destroy();for(const [key,value] of Object.entries(saved)){if(value===undefined)delete process.env[key];else process.env[key]=value;}});
 await kmsService.init();await kmsService.provisionKeys(vaultId);
 if(reorder){const protect=kmsService.protectConfidentialData.bind(kmsService);kmsService.protectConfidentialData=(doc,id)=>protect(doc.content===undefined?doc:{...doc,content:reverseKeys(doc.content)},id);}
 const calls=[];let failNext=false;const fetchFn=async(url,init)=>{calls.push({url,init});const status=failNext?503:200;failNext=false;return {ok:status===200,status};};
 const manager=new SubscriptionManager({vaultRepository,kmsService,fetchFn});
 const outbox=()=>vaultRepository.getContainersInSection(vaultId,getEnvSectionId('fhir-r5-subscription-notifications'));
 async function register(resource,expected='201'){const response=await manager.process(job([resource]));assert.equal(response.body.data[0].response.status,expected,JSON.stringify(response.body));}
 return {manager,register,outbox,calls,vaultRepository,kmsService,fetchFn,fail:()=>{failNext=true;}};
}
test('canonical R5 resource matching preserves exact subject scope',async t=>{
 const f=await fixture(t);await f.register(topic('http://hl7.org/fhir/StructureDefinition/Observation'));await f.register(subscription());
 await f.manager.captureEvents(job([{...observation,subject:{reference:'Patient/foreign-one'}}]));assert.equal((await f.outbox()).length,0);
 await f.manager.captureEvents(job([observation]));assert.equal((await f.outbox()).length,1);assert.equal(f.calls.length,2);
});
test('caller-owned entry identities and exact retry bytes survive encrypted storage and restart',async t=>{
 const f=await fixture(t,true);t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.parse(instant)});
 await f.register(topic('Observation',[{resourceType:'Observation',filterParameter:'patient',comparator:['eq']}]));await f.register(subscription({content:'full-resource'}));f.fail();
 await f.manager.captureEvents(job([observation]));const first=f.calls[1].init.body,bundle=JSON.parse(first);
 assert.equal(bundle.timestamp,instant);assert.equal(bundle.entry.length,2);
 for(const entry of bundle.entry)assert.match(entry.fullUrl,/^urn:uuid:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu);
 assert.notEqual(bundle.entry[0].fullUrl,bundle.entry[1].fullUrl);assert.deepEqual(bundle.entry[1].resource,observation);
 assert.deepEqual(bundle.entry[0].resource.notificationEvent,[{eventNumber:'1',timestamp:instant,focus:{reference:'Observation/observation-one'}}]);assert.equal(bundle.entry[0].resource.eventsSinceSubscriptionStart,'1');
 t.mock.timers.reset();t.mock.timers.enable({apis:['Date','setTimeout'],now:Date.parse(instant)+2000});
 const restarted=new SubscriptionManager({vaultRepository:f.vaultRepository,kmsService:f.kmsService,fetchFn:f.fetchFn});await restarted.captureEvents(job([{resourceType:'Appointment',id:'unrelated-one'}]));
 assert.equal(f.calls.length,3);assert.equal(f.calls[2].init.body,first);assert.equal((await f.outbox())[0].status,'delivered');
});
test('unsupported modifiers cannot become equality grants',async t=>{
 const f=await fixture(t);await f.register(topic('Observation',[{resource:'Observation',filterParameter:'patient'}]));await f.register(subscription({filterBy:[{resourceType:'Observation',filterParameter:'patient',modifier:'contains',value:`Patient/${safe.resourceUuid}`}]}));
 await f.manager.captureEvents(job([observation]));assert.equal((await f.outbox()).length,0);assert.equal(f.calls.length,1);
});
test('inactive topic denies subscription before handshake or persistence',async t=>{
 const f=await fixture(t);await f.register({...topic(),status:'draft'});await f.register(subscription(),'404');assert.equal(f.calls.length,0);assert.equal((await f.outbox()).length,0);
});
