// Flow contract: 1) provision real local KMS keys and an encrypted current registered profile; 2) authenticate a genuinely signed fixture bearer; 3) decrypt a real KEM/AES envelope and verify its registered ML-DSA-44 or supported EC signature; 4) reject missing inner signatures or a missing signed operational jti before queue/store writes; 5) admit a valid jti once and deny replay. Plain bearer bootstrap and polling do not acquire a wallet nonce requirement. This is local route admission, not Fabric or clinical authorization evidence.
import {afterEach,beforeEach,describe,expect,it,jest} from '@jest/globals';
import express from 'express';
import {importJWK,jwtVerify} from 'jose';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {DataspaceSectors} from 'sos-data-utils-ts/dataspace-sectors';
import {AdapterCryptoSdkNode} from '../../gdc-backend-utils-node/adapters/node/crypto';
import {KmsService} from '../../services/KmsService';
import {TenantsCacheManager} from '../../managers/TenantsCacheManager';
import {VaultMemRepository} from '../../database/repositories/vault/vault.mem.repository';
import {AsyncResponseStoreMem} from '../../adapters/async-response-store.mem';
import {ReplayProtectionStoreMem} from '../../adapters/replay-protection-store';
import {createApiRouter} from '../../routes/api';
import {getTenantVaultId} from '../../utils/tenant';
import {getEnvSectionId} from '../../utils/section-env';
import {buildDeterministicSignedJwt,deriveDeterministicEcJwkPair} from '../utils/deterministic-jwt-fixtures';
import {invokeExpress} from './helpers/invokeExpress';
const original=process.env;
const vaultId=getTenantVaultId(DataspaceSectors.HealthCare,e.tenantId);
const route=`/${e.tenantId}/cds-es/v1/health-care/digitaltwin/org.hl7.fhir.api/Composition/_search`;
let kms:KmsService,vault:VaultMemRepository,crypto:CryptographyService,app:express.Express,bearer:string,queue:any,store:AsyncResponseStoreMem,signature:any,signingKey:any;
const wallet=deriveDeterministicEcJwkPair({seed:e.resourceUuid,purpose:e.tenantId});
const legacyWallet=deriveDeterministicEcJwkPair({seed:e.resourceUuid,purpose:e.tenantId,alg:'ES256K'});
const clientId=e.demoOrganizationUuids.healthCare;
beforeEach(async()=>{
 process.env={...original,NODE_ENV:'test',DEPLOYMENT_ENV:'local',NETWORK_MODE:'test',SECURITY_MODE:'strict',DIDCOMM_PLAIN:'true',JSON_LEGACY:'true'};
 crypto=new CryptographyService(new AdapterCryptoSdkNode());vault=new VaultMemRepository();let current:KmsService;
 const tenantCache=new TenantsCacheManager(vault,()=>current,e.tenantId);current=new KmsService(crypto,tenantCache);kms=current;await kms.init();await kms.provisionKeys(vaultId);
 const encryptionKey=await kms.getPublicEncryptionKey(vaultId);expect(encryptionKey).toBeDefined();signingKey=await kms.getPublicVerificationKey(vaultId,'ML-DSA-44','comm_sig');expect(signingKey).toBeDefined();
 const profile={id:clientId,status:'active',sequence:0,content:{clientId,actorDid:e.didWeb,jwks:{keys:[signingKey,wallet.publicJwk,legacyWallet.publicJwk,encryptionKey]}}};
 await vault.put(vaultId,[await kms.protectConfidentialData(profile as any,vaultId)],getEnvSectionId('device-profiles'));
 const services=[{id:'#digitaltwin:org.hl7.fhir.api',type:'ApiService',serviceEndpoint:'Composition',actions:['_search'],selector:{sector:'health-care',section:'digitaltwin',format:'org.hl7.fhir.api'}}];
 const tenants={tenantExists:async()=>true,getCollectionName:async()=>vaultId,getDidServiceConfig:async()=>services,getTenant:async()=>({status:'active',authorizationStatus:'active',didConfig:{service:services}})};
 const token=await buildDeterministicSignedJwt({seed:e.resourceUuid,purpose:e.tenantId,payload:{iss:e.didWeb,sub:e.didWeb,aud:e.httpsBaseUrl,exp:Math.floor(Date.now()/1000)+300}});bearer=token.compactToken;
 const accountKey=await importJWK(wallet.publicJwk as any,'ES384');
 const auth={verifyBearerToken:async(value:string)=>{const result=await jwtVerify(value,accountKey,{issuer:e.didWeb,audience:e.httpsBaseUrl,algorithms:['ES384']});return {valid:true,payload:result.payload};}};
 queue={addJob:jest.fn(async()=>{})};store=new AsyncResponseStoreMem();jest.spyOn(store,'set');signature=jest.spyOn(crypto,'verifyDetachedJws');
 app=express();app.use(express.json());app.use(express.urlencoded({extended:true}));app.use(createApiRouter(queue,tenants as any,kms,store,vault,crypto,e.httpsBaseUrl,auth as any,new ReplayProtectionStoreMem()));
});
afterEach(()=>{kms?.destroy();vault?.clear();process.env=original;jest.restoreAllMocks();});
async function envelope(jti?:string,tamper=false,algorithm:'ML-DSA-44'|'ES384'|'ES256K'='ML-DSA-44'){
 const payload={iss:e.didWeb,aud:e.httpsBaseUrl,thid:e.resourceUuid,...(jti!==undefined?{jti}:{}),client_id:clientId,type:'application/didcomm-plain+json',body:{data:[]}};
 const signed=algorithm==='ML-DSA-44'?await kms.createCompactJws(payload,signingKey.kid,vaultId,'comm_sig'):(await buildDeterministicSignedJwt({seed:e.resourceUuid,purpose:e.tenantId,payload,alg:algorithm})).compactToken;const parts=signed.split('.');
 const content={...payload,...(tamper?{aud:e.tenantId}:{}),meta:{jws:{protected:JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8')),signature:parts[2]}}};
 return kms.encodeResponse(content,[await kms.getPublicEncryptionKey(vaultId) as any],vaultId);
}
async function unsignedEnvelope(){
 const payload={iss:e.didWeb,aud:e.httpsBaseUrl,jti:e.resourceUuid,thid:e.resourceUuid,client_id:clientId,type:'application/didcomm-plain+json',body:{data:[]}};
 return kms.encodeResponse(payload,[await kms.getPublicEncryptionKey(vaultId) as any],vaultId);
}
async function submit(request:string){return invokeExpress(app,{method:'POST',url:route,headers:{'content-type':'application/x-www-form-urlencoded',authorization:`Bearer ${bearer}`},body:{request}});}
describe('signed operational nonce admission',()=>{
 it('rejects an otherwise valid registered signed request with no authenticated message identifier',async()=>{
  const response=await submit(await envelope());expect(response.status).toBe(400);expect(signature).toHaveBeenCalled();expect(queue.addJob).not.toHaveBeenCalled();expect(store.set).not.toHaveBeenCalled();
 });
 it('rejects an empty operational jti instead of skipping durable replay admission',async()=>{
  const response=await submit(await envelope('  '));expect(response.status).toBe(400);expect(signature).toHaveBeenCalled();expect(queue.addJob).not.toHaveBeenCalled();expect(store.set).not.toHaveBeenCalled();
 });
 it('admits a valid signed jti once and rejects the exact replay before a second queue write',async()=>{
  const packed=await envelope(e.resourceUuid);expect((await submit(packed)).status).toBe(202);expect((await submit(packed)).status).toBe(409);expect(queue.addJob).toHaveBeenCalledTimes(1);expect(store.set).toHaveBeenCalledTimes(1);
 });
 it.each(['ES384','ES256K'] as const)('admits an actual encrypted request signed by its current registered %s key',async algorithm=>{
  expect((await submit(await envelope(e.resourceUuid,false,algorithm))).status).toBe(202);expect(queue.addJob).toHaveBeenCalledTimes(1);expect(store.set).toHaveBeenCalledTimes(1);expect(signature).not.toHaveBeenCalled();
 });
 it.each(['ES384','ES256K'] as const)('rejects modified business bytes under an otherwise registered %s key',async algorithm=>{
  expect((await submit(await envelope(e.resourceUuid,true,algorithm))).status).toBe(401);expect(queue.addJob).not.toHaveBeenCalled();expect(store.set).not.toHaveBeenCalled();
 });
 it('rejects a genuinely encrypted business envelope without an inner signature before admission',async()=>{
  expect((await submit(await unsignedEnvelope())).status).toBe(401);expect(signature).not.toHaveBeenCalled();expect(queue.addJob).not.toHaveBeenCalled();expect(store.set).not.toHaveBeenCalled();
 });
 it('retains unsigned encrypted demonstrations only in the explicit local Demo profile',async()=>{
  process.env.SECURITY_MODE='demo';expect((await submit(await unsignedEnvelope())).status).toBe(202);expect(signature).not.toHaveBeenCalled();expect(queue.addJob).toHaveBeenCalledTimes(1);
 });
 it('still rejects a substituted signed payload before replay or persistence',async()=>{
  expect((await submit(await envelope(e.resourceUuid,true))).status).toBe(401);expect(queue.addJob).not.toHaveBeenCalled();expect(store.set).not.toHaveBeenCalled();
 });
 it('keeps existing plain bearer requests outside the signed operational nonce requirement',async()=>{
  process.env.SECURITY_MODE='compat';const response=await invokeExpress(app,{method:'POST',url:route,headers:{'content-type':'application/json',authorization:`Bearer ${bearer}`},body:{thid:e.resourceUuid,body:{data:[]}}});expect(response.status).toBe(202);expect(queue.addJob).toHaveBeenCalledTimes(1);
 });
 it('permits the missing-nonce demonstration profile only when it is explicitly local',async()=>{
  process.env.SECURITY_MODE='demo';expect((await submit(await envelope())).status).toBe(202);expect(queue.addJob).toHaveBeenCalledTimes(1);
 });
});
