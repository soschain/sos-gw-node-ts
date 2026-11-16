// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Actual gateway wire/metadata behavior and IVault persistence retain business index identity separately from clinical identifier tokens and reject ambiguous records without rekeying.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {CommunicationManager} from '../../src/managers/CommunicationManager.ts';
import {buildFhirResourceFromIndexedClaims} from '../../src/utils/fhir-resource-rehydration.ts';
import {getClaimValue} from '../../src/utils/claims.ts';
import {VaultMemRepository} from '../../src/database/repositories/vault/vault.mem.repository.ts';
import {getSubjectScopedSectionId} from '../../src/utils/individual-sections.ts';
import {getTenantVaultId} from '../../src/utils/tenant.ts';
import {getEnvSectionId} from '../../src/utils/section-env.ts';
import {CompositionClaim,ObservationClaim,ResourceTypesFhirR4} from 'fhir-data-utils-ts';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {DataCollectionIds} from 'sos-data-utils-ts/gateway-data-collections';
const fixture=()=>JSON.parse(readFileSync(new URL('../tests/fixtures/indexed-clinical-gw-wire.json',import.meta.url),'utf8'));
const plain=value=>JSON.parse(JSON.stringify(value));
const pure=()=>Object.create(CommunicationManager.prototype);
const owner=()=>import('../../src/utils/gateway-clinical-profile.ts');

test('all thirteen outbound families retain actual gateway overlays, including bookkeeping and primitive arrays',()=>{
 for(const row of fixture().outbound){
  const before=structuredClone(row.record);
  assert.deepEqual(plain(buildFhirResourceFromIndexedClaims(row.resourceType,row.record)),row.output,row.resourceType);
  assert.deepEqual(row.record,before);
 }
});
test('all fourteen semantic and five structural input families retain actual gateway projection behavior',()=>{
 const data=fixture(),manager=pure();
 for(const row of data.inbound){
  const before=structuredClone(row.input);
  assert.deepEqual(plain(manager.extractProjectedResourceClaims(row.resourceType,row.input,data.subject,data.communication,data.author)),row.output,row.resourceType);
  assert.deepEqual(row.input,before);
 }
});
test('versioned and unversioned embedded claims keep their established precedence and native status behavior',()=>{
 const data=fixture(),manager=pure();
 for(const row of data.overlays)assert.deepEqual(plain(manager.extractProjectedResourceClaims('Observation',row.input,data.subject,data.communication,data.author)),row.output,row.name);
});
test('draft Consent classification still evaluates its existing embedded-claim overlay',()=>{
 const manager=pure();
 assert.equal(manager.isDraftConsentRequestBatch([{resource:{resourceType:'Consent',meta:{claims:{'Consent.status':'draft'}}}}]),true);
 assert.equal(manager.isDraftConsentRequestBatch([{resource:{resourceType:'Consent',status:'active',meta:{claims:{'Consent.status':'draft'}}}}]),true);
 assert.equal(manager.isDraftConsentRequestBatch([{resource:{resourceType:'Consent',status:'active'}}]),false);
});
test('native identifier systems survive in clinical claims while historical raw embedded identifiers keep precedence',()=>{
 const data=fixture(),manager=pure(),row=data.identities[0];
 const claims=manager.extractProjectedResourceClaims('Observation',row.input,data.subject,data.communication,data.author);
 assert.equal(getClaimValue(claims,ObservationClaim.Identifier),'urn:synthetic:identifiers|synthetic-business-value');
 const historical=data.identities[1];
 assert.equal(getClaimValue(manager.extractProjectedResourceClaims('Observation',historical.input,data.subject,data.communication,data.author),ObservationClaim.Identifier),historical.identifier);
 const internal=data.identities[2];
 assert.equal(getClaimValue(manager.extractProjectedResourceClaims('Observation',internal.input,data.subject,data.communication,data.author),ObservationClaim.Identifier),undefined);
});
test('private gateway adapter selects declared profiles and keeps identity/index copies separate from clinical claims',async()=>{
 const profile=await owner(),data=fixture();
 for(const row of data.inbound)assert.equal(profile.projectGatewayClinicalNativeClaims(row.input)['@context'],'org.hl7.fhir.api');
 assert.throws(()=>profile.projectGatewayClinicalNativeClaims({resourceType:'Goal'}),/unsupported/i);
 assert.throws(()=>profile.projectGatewayClinicalNativeClaims({resourceType:'Medication',identifier:[{value:'synthetic-business'}]},ObservationClaim.Identifier),/index key.*selected resource/i);
 const input=data.identities[0].input,token='urn:synthetic:identifiers|synthetic-business-value';
 const identity=profile.resolveGatewayClinicalIndexIdentity(input,token);
 assert.equal(identity.indexValue,data.identities[0].identifier);
 assert.deepEqual(identity.aliases,[token,data.identities[0].identifier]);
 const claims=Object.freeze({[ObservationClaim.Identifier]:token});
 const indexed=profile.projectGatewayClinicalIndexClaims(claims,[ObservationClaim.Identifier],identity.indexValue);
 assert.equal(indexed[ObservationClaim.Identifier],data.identities[0].identifier);
 assert.equal(claims[ObservationClaim.Identifier],token);
});

async function memoryFixture(t){
 const saved=process.env.NODE_ENV;process.env.NODE_ENV='demo';
 t.after(()=>{if(saved===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=saved});
 const vaultRepository=new VaultMemRepository(),tenant=getTenantVaultId('health-care',safe.tenantId);
 await vaultRepository.put('clinical-test-host',[{id:'host'}]);
 await vaultRepository.put('clinical-test-host',[{id:tenant}],getEnvSectionId('tenants'));
 await vaultRepository.createNewVault({id:tenant});
 assert.equal(await vaultRepository.vaultExists(tenant),true);
 // These persistence methods use IVault directly; cryptographic transport is covered separately.
 const manager=new CommunicationManager({vaultRepository,tenantsCacheManager:undefined,kmsService:undefined});
 const data=fixture(),section=getSubjectScopedSectionId(data.subject,'individual',DataCollectionIds.observations);
 const job={tenantId:safe.tenantId,sector:'health-care',jurisdiction:safe.countryIso2,content:{iss:safe.didWeb,thid:safe.resourceUuid,meta:{bearer:{jwt:{payload:{sub:safe.didWeb}}}}}};
 const resource={...structuredClone(data.identities[0].input),status:'preliminary'};
 return {manager,vaultRepository,tenant,section,job,data,resource,input:()=>({job,tenantVaultId:tenant,resourceType:'Observation',resource,communicationSubject:data.subject,fhirResource:data.communication,creatorDid:safe.didWeb})};
}
test('actual IVault persistence preserves the established business record id and index key while storing its system token',async t=>{
 const f=await memoryFixture(t),result=await f.manager.persistProjectedClinicalResource(f.input());
 assert.equal(result.recordId,'synthetic-business-value');
 const record=await f.vaultRepository.get(f.tenant,result.recordId,f.section);
 assert.equal(getClaimValue(record,ObservationClaim.Identifier),'urn:synthetic:identifiers|synthetic-business-value');
 assert.ok(record.indexed.attributes.some(attribute=>attribute.name.endsWith(ObservationClaim.Identifier)&&attribute.value==='synthetic-business-value'));
 assert.equal(record.audit.creatorDid,safe.didWeb);
});
test('ambiguous raw/token aliases fail before any clinical record is rekeyed or overwritten',async t=>{
 const f=await memoryFixture(t),token='urn:synthetic:identifiers|synthetic-business-value';
 const records=[{id:'synthetic-business-value',value:'synthetic-business-value'},{id:token,value:token}].map(({id,value})=>({id,[ObservationClaim.Identifier]:value,[CompositionClaim.Author]:safe.didWeb,audit:{creatorDid:safe.didWeb},indexed:{attributes:[{name:ObservationClaim.Identifier,value,unique:true}]}}));
 await f.vaultRepository.put(f.tenant,records,f.section);
 const before=plain(await f.vaultRepository.listContainersInSection(f.tenant,f.section));
 await assert.rejects(()=>f.manager.persistProjectedClinicalResource(f.input()),/ambiguous.*identifier|identifier.*ambiguous/i);
 assert.deepEqual(plain(await f.vaultRepository.listContainersInSection(f.tenant,f.section)),before);
});
test('profile conversion never gives a foreign clinical author permission to persist',async t=>{
 const f=await memoryFixture(t);
 await assert.rejects(()=>f.manager.persistProjectedClinicalResource({...f.input(),creatorDid:`${safe.didWeb}:foreign-author`}),/authenticated actor|registered clinical author/i);
 assert.equal((await f.vaultRepository.listContainersInSection(f.tenant,f.section)).length,0);
});
test('a prior token-only index identity is not silently moved to a new raw-value record',async t=>{
 const f=await memoryFixture(t),token='urn:synthetic:identifiers|synthetic-business-value';
 const record={id:token,[ObservationClaim.Identifier]:token,[CompositionClaim.Author]:safe.didWeb,audit:{creatorDid:safe.didWeb},indexed:{attributes:[{name:ObservationClaim.Identifier,value:token,unique:true}]}};
 await f.vaultRepository.put(f.tenant,[record],f.section);
 const before=plain(await f.vaultRepository.listContainersInSection(f.tenant,f.section));
 await assert.rejects(()=>f.manager.persistProjectedClinicalResource(f.input()),/ambiguous.*identifier|identifier.*ambiguous/i);
 assert.deepEqual(plain(await f.vaultRepository.listContainersInSection(f.tenant,f.section)),before);
});
