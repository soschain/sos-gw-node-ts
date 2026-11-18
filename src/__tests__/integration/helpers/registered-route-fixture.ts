// Flow contract: construct a genuinely signed inner route fixture and explicitly install its public wallet in the test vault. The caller's mocked JWE decoder and bearer verifier remain unit boundaries; this helper proves neither encryption nor production enrollment authority.
import {randomUUID} from 'node:crypto';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
import {EXAMPLE_DEVICE_CLIENT_ID} from 'sos-data-utils-ts/gateway-flow-examples';
import type {IVaultRepository} from '../../../database/repositories/vault/vault.repository';
import type {IKmsService} from '../../../gdc-backend-utils-node/models/IKmsService';
import {getEnvSectionId} from '../../../utils/section-env';
import {buildDeterministicSignedJwt,deriveDeterministicEcJwkPair} from '../../utils/deterministic-jwt-fixtures';
import {DCR_REPLAY_PUBLIC_KEYS} from '../../data/dcr-replay-public-keys';
export async function registeredRouteFixture<T extends {content?:any}>(job:T,vault:IVaultRepository,vaultId:string,kms:Partial<IKmsService>):Promise<T>{
 const old=job.content||{};const {meta,...raw}=old;
 const pair=deriveDeterministicEcJwkPair({seed:e.resourceUuid,purpose:e.tenantId});
 const signingKey={...pair.publicJwk,kid:meta?.jws?.protected?.kid||pair.publicJwk.kid};
 const reference=DCR_REPLAY_PUBLIC_KEYS.find(key=>key.kty==='OKP')!;
 const encryptionKey={...reference,...meta?.jwe?.header?.jwk,kid:meta?.jwe?.header?.skid||meta?.jwe?.header?.jwk?.kid||reference.kid};
 const payload={...raw,iss:raw.iss||e.didWeb,aud:raw.aud||e.httpsBaseUrl,jti:raw.jti||randomUUID(),client_id:raw.client_id||EXAMPLE_DEVICE_CLIENT_ID};
 const signed=await buildDeterministicSignedJwt({seed:e.resourceUuid,purpose:e.tenantId,payload,header:{kid:signingKey.kid,jwk:signingKey}});
 const profile={id:payload.client_id,status:'active',sequence:0,content:{clientId:payload.client_id,actorDid:payload.iss,jwks:{keys:[signingKey,encryptionKey]}}};
 await vault.put(vaultId,[kms.protectConfidentialData?await kms.protectConfidentialData(profile as any,vaultId):profile as any],getEnvSectionId('device-profiles'));
 return {...job,content:{...payload,meta:{...meta,jws:{protected:signed.header,signature:signed.compactToken.split('.')[2]},jwe:{...meta?.jwe,header:{...meta?.jwe?.header,skid:encryptionKey.kid,jwk:encryptionKey}}}}};
}
