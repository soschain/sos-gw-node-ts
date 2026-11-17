// Flow contract: bootstrap reply custody is bound by a genuine inner ML-DSA signature over the canonical KEM thumbprint; re-encrypting that signed request with an attacker's reply key never redirects the response. This proves transport binding, not account or activation authority.
import {expect,it} from '@jest/globals';
import {randomBytes,createHash,randomUUID} from 'node:crypto';
import {CryptographyService,Content} from 'antifraud-data-utils-ts/cryptography';
import {assertBootstrapReplyKeyBinding} from '../../../auth/bootstrap-reply-key';
const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),randomUUID,digestString:async(data,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(data).digest('hex')});
it('accepts a genuinely signed bootstrap reply key and rejects substitution of the outer recipient',async()=>{
 const signing=await crypto.generateKeyPairMlDsa(),reply=await crypto.generateKeyPairMlKem(),attacker=await crypto.generateKeyPairMlKem(),gateway=await crypto.generateKeyPairMlKem();
 const payload={iss:'did:web:controller.example.invalid',aud:'did:web:provider.example.invalid',thid:randomUUID()};
 const signed=await crypto.signDataJws(payload,{alg:signing.publicJWKey.alg,kid:signing.publicJWKey.kid,skid:reply.publicJWKey.kid},signing.secretKeyBytes);
 const compact=crypto.jwsToCompact(signed);
 const modifiedHeader={alg:signing.publicJWKey.alg,kid:signing.publicJWKey.kid,skid:attacker.publicJWKey.kid};
 expect(await crypto.verifyJws({...signed,protected:Content.objectToRawBase64UrlSafe(modifiedHeader)},signing.publicJWKey)).toBe(false);
 const envelope=async(jwk:typeof reply.publicJWKey)=>crypto.encryptJweToCompact(compact,{cty:'JWS',skid:jwk.kid,jwk},{...jwk,dBytes:(jwk===reply.publicJWKey?reply:attacker).secretKeyBytes},gateway.publicJWKey);
 for(const key of [reply.publicJWKey,attacker.publicJWKey]){
  const encrypted=await envelope(key),opened=await crypto.decryptJwe(encrypted,{...gateway.publicJWKey,dBytes:gateway.secretKeyBytes});
  const inner=Content.bytesToStringUTF8(opened.decryptedBytes);
  expect(await crypto.verifyJws(inner,signing.publicJWKey)).toBe(true);
  const header=Content.base64UrlSafeToJSON(inner.split('.')[0]!) as Record<string,unknown>;
  const check=()=>assertBootstrapReplyKeyBinding(header,opened.protectedHeader as Record<string,unknown>);
  if(key===reply.publicJWKey)expect(check).not.toThrow();else expect(check).toThrow();
 }
});
it('denies missing binding, same-kid substituted bytes, private material and unsupported key families',async()=>{
 const reply=await crypto.generateKeyPairMlKem(),attacker=await crypto.generateKeyPairMlKem();
 const signed={skid:reply.publicJWKey.kid},outer={skid:reply.publicJWKey.kid,jwk:reply.publicJWKey};
 expect(()=>assertBootstrapReplyKeyBinding({},outer)).toThrow();
 expect(()=>assertBootstrapReplyKeyBinding(signed,{})).toThrow();
 for(const key of [{...attacker.publicJWKey,kid:reply.publicJWKey.kid},{...reply.publicJWKey,d:'synthetic'},{...reply.publicJWKey,dBytes:randomBytes(32)},{...reply.publicJWKey,kty:'EC'},{...reply.publicJWKey,x:'invalid'}])expect(()=>assertBootstrapReplyKeyBinding(signed,{...outer,jwk:key})).toThrow();
});
