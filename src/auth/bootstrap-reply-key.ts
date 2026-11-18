import {computeRfc7638JwkThumbprint} from 'antifraud-data-utils-ts/jwk-thumbprints';

const record=(value:unknown):Record<string,unknown>|undefined=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:undefined;

/** Called only after verifying the inner bootstrap signature; possession is not activation authority. */
export function assertBootstrapReplyKeyBinding(signedHeader:unknown,encryptionHeader:unknown):void {
  const signed=record(signedHeader),outer=record(encryptionHeader),key=record(outer?.jwk);
  const privateMembers=['d','k','priv','privateKey','privateKeyJwk','dBytes','privBytes','secretKeyBytes','p','q','dp','dq','qi','oth'];
  if(!signed||!outer||!key||key.kty!=='OKP'||typeof key.crv!=='string'
    ||!['ML-KEM-512','ML-KEM-768','ML-KEM-1024'].includes(key.crv)
    ||typeof key.x!=='string'||!/^[A-Za-z0-9_-]+$/u.test(key.x)
    ||privateMembers.some(member=>Object.hasOwn(key,member))
    ||(key.use!==undefined&&key.use!=='enc')) {
    throw new Error('Bootstrap response requires a public ML-KEM reply key.');
  }
  const expectedLength={'ML-KEM-512':800,'ML-KEM-768':1184,'ML-KEM-1024':1568}[key.crv];
  const bytes=Buffer.from(key.x,'base64url');
  if(bytes.length!==expectedLength||bytes.toString('base64url')!==key.x)throw new Error('Bootstrap reply key encoding is invalid.');
  const thumbprint=computeRfc7638JwkThumbprint({kty:key.kty,crv:key.crv,x:key.x});
  if(signed.skid!==thumbprint||outer.skid!==thumbprint||key.kid!==thumbprint) {
    throw new Error('Bootstrap reply key does not match the signed sender-key commitment.');
  }
}
