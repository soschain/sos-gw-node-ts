// Flow contract: actual KMS indexes retain HMAC-SHA3-256 UTF-8/base64url bytes and tenant-key separation. Organization and employee credentials preserve their signed JSON bytes and use the issuer's vc_sign key.
import {afterEach,describe,expect,it,jest} from '@jest/globals';
import {readFileSync} from 'node:fs';
import {createHash,createHmac} from 'node:crypto';
import {hmac} from '@noble/hashes/hmac.js';
import {sha3_256} from '@noble/hashes/sha3.js';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
import {KmsService} from '../../../services/KmsService';
import {CredentialManager} from '../../../managers/CredentialManager';
import {TenantsCacheManager} from '../../../managers/TenantsCacheManager';
import {VaultMemRepository} from '../../../database/repositories/vault/vault.mem.repository';
import {AdapterCryptoSdkNode} from '../../../gdc-backend-utils-node/adapters/node/crypto';
import {InMemoryEnvelopeAdapter} from '../../../services/kms-envelope-adapter';
import {InMemoryWrappedKeyRepository} from '../../../services/wrapped-key-repository';

const initialEnvironment={node:process.env.NODE_ENV,seed:process.env.DEV_SEED};
const services:KmsService[]=[];
afterEach(()=>{
 for(const service of services.splice(0))service.destroy();
 jest.restoreAllMocks();
 if(initialEnvironment.node===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=initialEnvironment.node;
 if(initialEnvironment.seed===undefined)delete process.env.DEV_SEED;else process.env.DEV_SEED=initialEnvironment.seed;
});
async function harness(){
 process.env.NODE_ENV='development';process.env.DEV_SEED='true';
 const vault=new VaultMemRepository(),crypto=new CryptographyService(new AdapterCryptoSdkNode());
 let service:KmsService;
 const tenants=new TenantsCacheManager(vault,()=>service,safe.tenantId);
 service=new KmsService(crypto,tenants,{wrappedKeyRepository:new InMemoryWrappedKeyRepository(),envelopeAdapter:new InMemoryEnvelopeAdapter()});
 services.push(service);await service.init();
 return {service,vault,crypto,tenants};
}
function oracle(text:string,entity:string){
 const key=createHash('sha256').update(entity+'-hmac','utf8').digest();
 return Buffer.from(hmac(sha3_256,key,new TextEncoder().encode(text))).toString('base64url');
}

describe('owned KMS and credential byte primitives',()=>{
 it('uses AF JSON bytes and the Node SHA3 HMAC runtime without legacy primitive imports',()=>{
  const kms=readFileSync(new URL('../../../services/KmsService.ts',import.meta.url),'utf8');
  const credential=readFileSync(new URL('../../../managers/CredentialManager.ts',import.meta.url),'utf8');
  expect(kms.includes("from 'gdc-common-utils-ts/hmac'")).toBe(false);
  expect(credential.includes("from 'gdc-common-utils-ts/utils/object-convert'")).toBe(false);
  expect(credential).toContain('Content.objectToBytes(unsignedVc)');
 });
 it('matches an independent SHA3 oracle for fixed synthetic managed keys and Unicode without padding',async()=>{
  const {service}=await harness();
  for(const text of ['','plain index','é🦷漢字']){
   const actual=await service.getHmacBase64Url(text,'host');
   expect(actual).toBe(oracle(text,'host'));
   expect(actual).toMatch(/^[A-Za-z0-9_-]{43}$/u);
   const key=createHash('sha256').update('host-hmac','utf8').digest();
   expect(actual).not.toBe(createHmac('sha256',key).update(text,'utf8').digest('base64url'));
  }
 });
 it('keeps protected name/value bytes and key namespaces independent',async()=>{
  const {service}=await harness();await service.provisionKeys(safe.tenantId);
  const text='é🦷';
  expect(await service.getHmacBase64Url(text,'host')).not.toBe(await service.getHmacBase64Url(text,safe.tenantId));
  expect(await service.getHmacBase64Url(text,safe.tenantId)).toBe(oracle(text,safe.tenantId));
  const result=await service.protectAttributesNameAndValue([{name:'unicode',value:text,type:'string',unique:true},{name:'quantity',value:0,type:'number'}],'host');
  expect(result).toEqual([{name:oracle('unicode','host'),value:oracle(text,'host'),unique:true},{name:oracle('quantity','host'),value:oracle('0','host'),unique:undefined,type:'number'}]);
 });
 it('passes the exact ordered UTF-8 unsigned credential transcript to its real credential key',async()=>{
  const {service,vault,crypto}=await harness();
  const manager=new CredentialManager(vault,service,{getTenantIdentifierUrn:async()=>safe.organizationScopedResources.organizationUrn},safe.domain);
  const signer=jest.spyOn(service,'signWithManagedKey');
  const credential=await manager.issueOrganizationSelfDescription(safe.organizationScopedResources.organizationUrn,{zeta:'é🦷漢字',alpha:'first'},undefined);
  const {proof:_proof,...unsigned}=credential;
  expect(signer).toHaveBeenCalledTimes(1);
  expect(signer.mock.calls[0][0]).toEqual(new TextEncoder().encode(JSON.stringify(unsigned)));
  expect(signer.mock.calls[0].slice(1)).toEqual(['host',undefined,'vc_sign']);
  expect(JSON.stringify(unsigned).indexOf('zeta')).toBeLessThan(JSON.stringify(unsigned).indexOf('alpha'));
  const proof=Array.isArray(credential.proof)?credential.proof[0]:credential.proof;
  if(!proof?.jws)throw new Error('Actual credential has no detached proof');
  const [protectedHeader,detached,signature]=proof.jws.split('.');
  if(!protectedHeader||detached!==''||!signature)throw new Error('Actual credential proof is not compact detached JWS');
  // The existing managed-key profile signs {data:base64url(bytes)}; preserve that profile too.
  const encodedPayload=Buffer.from(JSON.stringify({data:Buffer.from(signer.mock.calls[0][0]).toString('base64url')})).toString('base64url');
  const parts={protected:protectedHeader,payload:encodedPayload,signature};
  const vcKey=await service.getPublicVerificationKey('host',undefined,'vc_sign');
  const communicationKey=await service.getPublicVerificationKey('host',undefined,'comm_sig');
  if(!vcKey||!communicationKey)throw new Error('Actual managed signing keys unavailable');
  expect(await crypto.verifyJws(parts,vcKey)).toBe(true);
  expect(await crypto.verifyJws(parts,communicationKey)).toBe(false);
  expect(await crypto.verifyJws({...parts,payload:Buffer.from('{"data":"changed"}').toString('base64url')},vcKey)).toBe(false);
 });
 it('signs the employee credential with the tenant post-quantum assertion key', async () => {
  const { service, vault, crypto } = await harness();
  await service.provisionKeys(safe.tenantId);
  const tenantIdentifier = safe.organizationScopedResources.organizationUrn;
  const manager = new CredentialManager(vault, service, {
   getTenantIdentifierUrn: async () => tenantIdentifier,
  }, safe.domain);
  const employeeIdentifier = `urn:uuid:${safe.resourceUuid}`;
  const credential = await manager.issueEmployeeCredential(
   { tenantId: safe.tenantId, tenantVaultId: safe.tenantId }, employeeIdentifier, {}, undefined,
  );
  const { proof, ...unsigned } = credential;
  expect(unsigned).toMatchObject({ issuer: tenantIdentifier, credentialSubject: { identifier: employeeIdentifier } });
  const assertion = Array.isArray(proof) ? proof[0] : proof;
  if (!assertion?.jws) throw new Error('Employee credential assertion proof is missing.');
  const [protectedHeader, detached, signature] = assertion.jws.split('.');
  expect(detached).toBe('');
  expect(JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'))).toMatchObject({ alg: 'ML-DSA-44' });
  const data = Buffer.from(JSON.stringify(unsigned)).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ data })).toString('base64url');
  const tenantKey = await service.getPublicVerificationKey(safe.tenantId, undefined, 'vc_sign');
  const hostKey = await service.getPublicVerificationKey('host', undefined, 'vc_sign');
  if (!tenantKey || !hostKey) throw new Error('Managed credential keys are missing.');
  expect(assertion.verificationMethod).toBe(`${tenantIdentifier}#${tenantKey.kid}`);
  expect(await crypto.verifyJws({ protected: protectedHeader, payload, signature }, tenantKey)).toBe(true);
  expect(await crypto.verifyJws({ protected: protectedHeader, payload, signature }, hostKey)).toBe(false);
 });

});
