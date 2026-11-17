// Flow contract: signed operational envelopes require fresh identifiers and pinned keys; unsigned encrypted input is denied. Injected ML-DSA callbacks isolate transport policy, while dedicated tests separately prove real cryptography.
/**
 * Transport security contract: encrypted post-DCR traffic resolves keys by
 * issuer and kid. The pre-DCR Token/_exchange verifies the new wallet's
 * embedded signing key only as possession proof; the verified account bearer
 * and one-use activation licence remain the authority consumed by the worker.
 */
import express from 'express';
import {DCR_REPLAY_PUBLIC_KEYS} from '../data/dcr-replay-public-keys';
const fixtureReplyKey=DCR_REPLAY_PUBLIC_KEYS.find(key=>key.kty==='OKP')!;
import request from 'supertest';
import { createApiRouter } from '../../routes/api';
import { AppAuthorizationManager } from '../../managers/AppAuthorizationManager';
import {
  buildDeterministicIdTokenFixture,
  buildDeterministicVpTokenFixture,
  DeterministicJwtTokenVerifier,
} from '../utils/deterministic-jwt-fixtures';
import {
  EXAMPLE_PROFILE_PROVIDER_DID,
  EXAMPLE_TENANT_IDENTIFIER,
} from 'sos-data-utils-ts/gateway-flow-examples';
import { buildUnsignedJwt } from 'sos-data-utils-ts/jwt';
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';
import { IdentityAuthRequestFields } from 'sos-data-utils-ts/identity-auth-wire-contract';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { computeJwkThumbprint, toBaseJwk } from '../../gdc-backend-utils-node/jwk-thumbprint';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {CryptographyService} from 'antifraud-data-utils-ts/cryptography';

const fixtureControllerDid = `${SAFE.didWeb}:cds-es:v1:health-care:employee:${buildStableActorIdentifier({ contactKind: 'email', contact: SAFE.firstContactEmail }).replace('urn:multibase:', '')}:${encodeURIComponent(HealthcareActorRoles.Controller)}`;

function buildTestApp(options?: { appAuthManager?: any; tenantsCacheManager?: any; kmsService?: any; signedPolicyEnvelope?: boolean }) {
  const app = express();
  app.use(express.json({ type: ['application/json', 'application/didcomm-plain+json', 'application/fhir+json'] }));
  app.use(express.urlencoded({ extended: true }));

  const queueAdapter = {
    addJob: jest.fn(),
  } as any;

  const tenantsCacheManager = options?.tenantsCacheManager || {
    getDidServiceConfig: jest.fn(),
    getTenant: jest.fn(),
    getCollectionName: jest.fn(),
  };

  const kmsService = options?.kmsService || {
    decodeRequest: jest.fn(),
    getHmacBase64Url: jest.fn(),
    unprotectConfidentialData: jest.fn(),
    getPublicVerificationKey: jest.fn(),
    createDetachedJws: jest.fn(),
  };

  const asyncResponseStore = {
    get: jest.fn(),
    set: jest.fn(),
    delete: jest.fn(),
  } as any;

  const vaultRepository = {
    query: jest.fn(),
  } as any;

  const cryptographyService = {
    verifyDetachedJws: jest.fn(),
  } as any;

  if (options?.signedPolicyEnvelope) {
    // These cases isolate bearer/body policy behind an explicit injected
    // ML-DSA verifier. Real signature boundary proof lives in dedicated cases.
    const signingKey = { kty: 'AKP', alg: 'ML-DSA-44', pub: 'c3ludGhldGlj', kid: 'policy-signing-key', use: 'sig' };
    const encryptionKid = fixtureReplyKey.kid;
    let senderDid = '';
    const decode = kmsService.decodeRequest;
    kmsService.decodeRequest = jest.fn(async (...args: any[]) => {
      const decoded = await decode(...args);
      senderDid = decoded.content.iss;
      decoded.content = { ...decoded.content, jti: randomUUID(), meta: { ...decoded.content.meta,
        jws: { protected: { alg: signingKey.alg, kid: signingKey.kid, jwk: signingKey, skid: encryptionKid }, signature: 'synthetic-signature' },
        jwe: { header: { skid: encryptionKid, jwk: fixtureReplyKey } },
      } };
      return decoded;
    });
    cryptographyService.verifyDetachedJws.mockResolvedValue(true);
    vaultRepository.query.mockResolvedValue([{ id: 'policy-registered-controller' }]);
    tenantsCacheManager.getCollectionName.mockResolvedValue('policy-tenant-vault');
    kmsService.getHmacBase64Url.mockImplementation(async (value: string) => value);
    kmsService.unprotectConfidentialData.mockImplementation(async () => ({ didDocument: {
      id: senderDid, verificationMethod: [
        { id: `${senderDid}#${signingKey.kid}`, publicKeyJwk: signingKey },
        { id: `${senderDid}#${encryptionKid}`, publicKeyJwk: fixtureReplyKey },
      ],
    } }));
  }

  app.use(
    createApiRouter(
      queueAdapter,
      tenantsCacheManager,
      kmsService,
      asyncResponseStore,
      vaultRepository,
      cryptographyService,
      'http://localhost:3000',
      options?.appAuthManager,
    ),
  );
  return { app, queueAdapter, tenantsCacheManager, kmsService, vaultRepository, cryptographyService };
}

describe('SECURITY_MODE content-type gates', () => {
  it.each([{valid:true,replaceReply:false},{valid:false,replaceReply:false},{valid:true,replaceReply:true}])('checks real fresh-wallet DCR signature and signed reply binding without granting registered authority: valid=$valid, replacedReply=$replaceReply', async ({valid,replaceReply}) => {
    process.env={...previousEnv,SECURITY_MODE:'strict',DEMO_ALLOW_INSECURE_BEARER:'false',JSON_LEGACY:'false',FHIR_LEGACY:'false',DIDCOMM_PLAIN:'false'};
    const crypto=new CryptographyService({getRandomBytes:async count=>randomBytes(count),
      digestString:async(value,algorithm)=>createHash(algorithm.replaceAll('-','').toLowerCase()).update(value).digest('hex'),randomUUID});
    const pair=await crypto.generateKeyPairMlDsa(randomBytes(32),'ML-DSA-44');
    const jwk={...pair.publicJWKey,kid:'synthetic-new-recipient-signing-key'};
    const body={code:'synthetic-activation-code',actor_did:`${SAFE.didWeb}:employee:synthetic-recipient`,profile_did:`${SAFE.didWeb}:employee:synthetic-recipient`,redirect_uris:['https://example.invalid/auth'],jwks:{keys:[jwk]},ext_device_info:{device_id:'synthetic-installation'}};
    const signed={iss:body.actor_did,aud:SAFE.didWeb,thid:SAFE.resourceUuid,jti:randomUUID(),type:'openid-dcr-request',body};
    const header={alg:'ML-DSA-44',kid:jwk.kid,jwk,skid:fixtureReplyKey.kid};
    const jws=await crypto.signDataJws(signed,header,pair.secretKeyBytes);
    const reply=replaceReply?(await crypto.generateKeyPairMlKem()).publicJWKey:fixtureReplyKey;
    const decoded={...signed,...(valid?{}:{body:{...body,code:'synthetic-substituted-code'}}),meta:{jws:{protected:header,signature:jws.signature},jwe:{header:{skid:reply.kid,jwk:reply}}}};
    const appAuthManager={verifyInitialAccessToken:jest.fn(async()=>({sub:'verified-recipient',act_code:body.code,scope:'dcr:register'}))};
    const kmsService={decodeRequest:jest.fn(async()=>({content:decoded})),getHmacBase64Url:jest.fn(),unprotectConfidentialData:jest.fn()};
    const tenantsCacheManager={tenantExists:jest.fn(async()=>true),getCollectionName:jest.fn(async()=> 'isolated-tenant'),getTenant:jest.fn(async()=>({authorizationStatus:'active'})),
      getDidServiceConfig:jest.fn(async()=>[{id:'#identity:openid',selector:{section:'identity',format:'openid'},serviceEndpoint:'Device',actions:['_dcr']}])};
    const harness=buildTestApp({appAuthManager,kmsService,tenantsCacheManager});
    harness.cryptographyService.verifyDetachedJws.mockImplementation((...args:Parameters<CryptographyService['verifyDetachedJws']>)=>crypto.verifyDetachedJws(...args));
    const response=await request(harness.app).post(`/${SAFE.tenantId}/cds-es-md/v1/health-care/identity/openid/Device/_dcr`)
      .set('Authorization','Bearer synthetic-host-initial-token').type('form').send({request:'synthetic-kms-encrypted-envelope'});
    expect(response.status).toBe(valid&&!replaceReply?202:401);
    expect(appAuthManager.verifyInitialAccessToken).toHaveBeenCalledWith('synthetic-host-initial-token');
    expect(harness.vaultRepository.query).not.toHaveBeenCalled();
    expect(harness.cryptographyService.verifyDetachedJws).toHaveBeenCalled();
    if(valid&&!replaceReply){expect(harness.queueAdapter.addJob).toHaveBeenCalledTimes(1);expect(harness.queueAdapter.addJob.mock.calls[0][1].authenticatedTransport).toBeUndefined();}
    else expect(harness.queueAdapter.addJob).not.toHaveBeenCalled();
  });
  const targetPath = '/host/cds-es/v1/health-care/ping/org.schema/Organization/_batch';
  const credentialPath = '/host/cds-es/v1/health-care/identity/oidc/credential';
  const previousEnv = process.env;

  afterEach(() => {
    process.env = previousEnv;
  });

  /** Transport admission must overwrite hostile principal claims before queuing real manager work. */
  it.each([true, false])('preserves the verified creator and gates employee registration on signature validity=%s', async (signatureValid) => {
    process.env = { ...previousEnv, SECURITY_MODE: 'strict', DEMO_ALLOW_INSECURE_BEARER: 'false', JSON_LEGACY: 'false', DIDCOMM_PLAIN: 'false' };
    const stable = buildStableActorIdentifier({ contactKind: 'email', contact: SAFE.firstContactEmail });
    const actorDid = `did:web:${SAFE.domain}:${SAFE.tenantId}:cds-es-md:v1:health-care:employee:${stable.replace('urn:multibase:', '')}:${encodeURIComponent(HealthcareActorRoles.Dentist)}`;
    const signingKid = 'registered-dentist-signing-key';
    const encryptionKid = 'registered-dentist-encryption-key';
    const signingKey = { kty: 'AKP', alg: 'ML-DSA-44', pub: 'c3ludGhldGlj', kid: signingKid, use: 'sig' };
    const actualPrincipal = { sub: 'verified-professional-account', email: SAFE.firstContactEmail, email_verified: true };
    const appAuthManager = { verifyBearerToken: jest.fn(async () => ({ valid: true, payload: actualPrincipal })) };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true), findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async () => 'isolated-registration-vault'),
      getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#individual:org.schema', selector: { section: 'individual', format: 'org.schema' },
        serviceEndpoint: 'Organization', actions: ['_batch'],
      }]),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({ authenticatedTransport: { kind: 'registered-didcomm', actorDid: 'forged-actor' }, content: {
        iss: actorDid, thid: 'registered-dentist-creation', jti: `registered-dentist-${signatureValid}`,
        client_id: 'caller-selected-client',
        meta: {
          bearer: { jwt: { payload: { sub: 'forged-controller', email: SAFE.individualEmail, email_verified: true } } },
          jws: { protected: { alg: 'ML-DSA-44', kid: signingKid }, signature: 'synthetic-signature' },
          jwe: { header: { skid: encryptionKid } },
        }, body: { data: [] },
      } })),
      getHmacBase64Url: jest.fn(async (value: string) => value),
      unprotectConfidentialData: jest.fn(async () => ({ didDocument: { verificationMethod: [
        { id: `${actorDid}#${signingKid}`, publicKeyJwk: signingKey },
        { id: `${actorDid}#${encryptionKid}`, publicKeyJwk: { kty: 'OKP', x: 'synthetic-encryption' } },
      ] } })),
    };
    const harness = buildTestApp({ appAuthManager, tenantsCacheManager, kmsService });
    harness.vaultRepository.query.mockResolvedValue([{ id: 'registered-employee' }]);
    harness.cryptographyService.verifyDetachedJws.mockResolvedValue(signatureValid);
    const response = await request(harness.app)
      .post(`/${SAFE.tenantId}/cds-es-md/v1/health-care/individual/org.schema/Organization/_batch`)
      .set('Authorization', 'Bearer verified-professional-token').type('form').send({ request: 'synthetic-encrypted-envelope' });
    expect(harness.cryptographyService.verifyDetachedJws).toHaveBeenCalledWith(expect.anything(), expect.any(String), signingKey);
    if (!signatureValid) {
      expect(response.status).toBe(401);
      expect(harness.queueAdapter.addJob).not.toHaveBeenCalled();
      return;
    }
    expect(response.status).toBe(202);
    const queued = harness.queueAdapter.addJob.mock.calls[0][1];
    expect(queued.content.meta.bearer.jwt.payload).toEqual(actualPrincipal);
    expect(queued.content.iss).toBe(actorDid);
    expect(queued.authenticatedTransport).toEqual({
      kind: 'registered-didcomm', actorDid, signingKeyId: signingKid, signedClientId: 'caller-selected-client',
      signingKeyThumbprint: await computeJwkThumbprint(toBaseJwk(signingKey as any)),
    });
    // Transport preserves the signed selector; it is not itself professional authority.
    // The real FamilyManager suite denies selectors missing from current DCR records.
    expect(queued.content.client_id).toBe('caller-selected-client');
  });

  it.each(['json', 'unsigned-encrypted'])('never promotes hostile transport evidence from %s bootstrap input', async (mode) => {
    process.env = { ...previousEnv, SECURITY_MODE: 'strict', DEMO_ALLOW_INSECURE_BEARER: 'false', JSON_LEGACY: 'false', DIDCOMM_PLAIN: 'false' };
    const forged = { kind: 'registered-didcomm', actorDid: `${SAFE.didWeb}:employee`, signingKeyId: 'forged-key', signedClientId: 'known-client' };
    const content = { iss: forged.actorDid, thid: `hostile-bootstrap-${mode}`, client_id: forged.signedClientId,
      authenticatedTransport: forged, meta: { authenticatedTransport: forged }, body: { data: [] } };
    const harness = buildTestApp({
      appAuthManager: { verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { sub: 'verified-professional-account', email: SAFE.firstContactEmail, email_verified: true } })) },
      tenantsCacheManager: {
        tenantExists: jest.fn(async () => true), findTenantVaultIdByIdentifierValue: jest.fn(),
        getCollectionName: jest.fn(async () => 'isolated-registration-vault'),
        getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
        getDidServiceConfig: jest.fn(async () => [{ id: '#individual:org.schema', selector: { section: 'individual', format: 'org.schema' }, serviceEndpoint: 'Organization', actions: ['_transaction'] }]),
      },
      kmsService: { decodeRequest: jest.fn(async () => ({ authenticatedTransport: forged, content })) },
    });
    const pending = request(harness.app).post(`/${SAFE.tenantId}/cds-es-md/v1/health-care/individual/org.schema/Organization/_transaction`)
      .set('Authorization', 'Bearer verified-professional-token');
    const response = mode === 'json' ? await pending.type('json').send(content)
      : await pending.type('form').send({ request: 'unsigned-envelope' });
    expect(response.status).toBe(mode === 'json' ? 202 : 401);
    if (mode === 'json') {
      expect(harness.queueAdapter.addJob).toHaveBeenCalledTimes(1);
      expect(harness.queueAdapter.addJob.mock.calls[0][1].authenticatedTransport).toBeUndefined();
    } else {
      expect(harness.queueAdapter.addJob).not.toHaveBeenCalled();
    }
    expect(harness.cryptographyService.verifyDetachedJws).not.toHaveBeenCalled();
  });

  it('rejects a registered dentist key claiming another account controller issuer for Employee mutations', async () => {
    process.env = { ...previousEnv, SECURITY_MODE: 'strict', DEMO_ALLOW_INSECURE_BEARER: 'false', JSON_LEGACY: 'false', DIDCOMM_PLAIN: 'false' };
    const provider = `did:web:${SAFE.domain}:${SAFE.tenantId}:cds-es-md:v1:health-care`;
    const did = (email: string, role: string) => `${provider}:employee:${buildStableActorIdentifier({ contactKind: 'email', contact: email }).replace('urn:multibase:', '')}:${encodeURIComponent(role)}`;
    const dentistDid = did(SAFE.individualEmail, HealthcareActorRoles.Dentist);
    const claimedControllerDid = did(SAFE.firstContactEmail, HealthcareActorRoles.Controller);
    const signingKid = 'registered-dentist-signing-key';
    const encryptionKid = 'registered-dentist-encryption-key';
    const harness = buildTestApp({
      appAuthManager: { verifyBearerToken: jest.fn(async () => ({ valid: true, payload: {
        sub: 'verified-dentist-account', email: SAFE.individualEmail, email_verified: true,
      } })) },
      tenantsCacheManager: {
        tenantExists: jest.fn(async () => true), findTenantVaultIdByIdentifierValue: jest.fn(),
        getCollectionName: jest.fn(async () => 'isolated-staff-vault'),
        getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
        getDidServiceConfig: jest.fn(async () => [{ id: '#entity:org.schema', selector: { section: 'entity', format: 'org.schema' }, serviceEndpoint: 'Employee', actions: ['_batch'] }]),
      },
      kmsService: {
        decodeRequest: jest.fn(async () => ({ content: {
          iss: claimedControllerDid, client_id: 'registered-dentist-client', jti: 'staff-controller-spoof', thid: 'staff-controller-spoof',
          meta: { jws: { protected: { alg: 'ES384', kid: signingKid }, signature: 'synthetic-registered-key-signature' }, jwe: { header: { skid: encryptionKid } } },
          body: { data: [] },
        } })),
        getHmacBase64Url: jest.fn(async (value: string) => value),
        unprotectConfidentialData: jest.fn(async () => ({ didDocument: { id: dentistDid, verificationMethod: [
          { id: `${dentistDid}#${signingKid}`, publicKeyJwk: { kty: 'EC', crv: 'P-384', x: 'synthetic-x', y: 'synthetic-y' } },
          { id: `${dentistDid}#${encryptionKid}`, publicKeyJwk: { kty: 'OKP', x: 'synthetic-encryption' } },
        ] } })),
      },
    });
    harness.vaultRepository.query.mockResolvedValue([{ id: 'registered-dentist-employee' }]);
    harness.cryptographyService.verifyDetachedJws.mockResolvedValue(true);
    const response = await request(harness.app)
      .post(`/${SAFE.tenantId}/cds-es-md/v1/health-care/entity/org.schema/Employee/_batch`)
      .set('Authorization', 'Bearer verified-dentist-token').type('form').send({ request: 'synthetic-envelope' });
    expect(response.status).toBe(401);
    expect(harness.queueAdapter.addJob).not.toHaveBeenCalled();
  });

  it('rejects application/json in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post(targetPath)
      .set('Content-Type', 'application/json')
      .send({ thid: 'thid-1' });

    expect(response.status).toBe(415);
  });

  it('accepts authenticated JSON only for the pre-DCR individual Organization bootstrap in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { sub: 'firebase-controller-uid' } })),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async () => 'animal-care-tenant'),
      getDidServiceConfig: jest.fn(),
      getTenant: jest.fn(),
    };
    const { app } = buildTestApp({ appAuthManager, tenantsCacheManager });
    const response = await request(app)
      .post('/704457076/cds-ca-bc/v1/animal-care/individual/org.schema/Organization/_transaction')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer firebase-id-token')
      .send({ thid: 'animal-bootstrap-thid' });

    expect(response.status).not.toBe(415);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith(
      'firebase-id-token',
      undefined,
      { vaultId: 'animal-care_704457076', collectionName: 'animal-care-tenant' },
    );
  });

  it('accepts authenticated JSON only for the pre-DCR host tenant bootstrap in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { sub: 'firebase-host-controller-uid' } })),
    };
    const { app } = buildTestApp({ appAuthManager });
    const response = await request(app)
      .post('/host/cds-ca-bc/v1/test-network/registry/org.schema/Organization/_batch')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer firebase-id-token')
      .send({ thid: 'tenant-bootstrap-thid' });

    expect(response.status).not.toBe(415);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith(
      'firebase-id-token',
      undefined,
      undefined,
    );
  });

  it('allows the authenticated host controller to recover a pending bootstrap Offer in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { sub: 'firebase-host-controller-uid' } })),
    };
    const { app } = buildTestApp({ appAuthManager });
    const response = await request(app)
      .post('/host/cds-ca-bc/v1/test-network/registry/org.schema/Offer/_search')
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer firebase-id-token')
      .send({ thid: 'tenant-bootstrap-offer-recovery-thid', body: { data: [] } });

    expect(response.status).not.toBe(415);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith(
      'firebase-id-token',
      undefined,
      undefined,
    );
  });

  it('accepts application/json in compat mode when JSON_LEGACY=true', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'compat',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post(targetPath)
      .set('Content-Type', 'application/json')
      .send({});

    expect(response.status).toBe(400);
  });

  it('rejects application/fhir+json in compat mode when FHIR_LEGACY=false', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'compat',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post(targetPath)
      .set('Content-Type', 'application/fhir+json')
      .send({});

    expect(response.status).toBe(415);
  });

  it('accepts didcomm-plaintext in demo mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'demo',
      DEMO_ALLOW_INSECURE_BEARER: 'true',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post(targetPath)
      .set('Content-Type', 'application/didcomm-plain+json')
      .send({});

    expect(response.status).toBe(400);
  });

+  /**
   * A professional-seat Offer belongs to the tenant, but its commercial Order
   * is submitted through the host registry. The host path must keep routing the
   * Order to the host while resolving post-DCR sender keys from the issuer
   * tenant. The restricted catalog reproduces the historical staging state.
   */
  it('resolves encrypted host Order sender keys despite a historical host catalog', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const tenantId = 'example-tenant';
    const tenantVaultId = `onehealth-research_${tenantId}`;
    const tenantCollection = 'tenant-physical-collection';
    const issuerDid = `did:web:gateway.example:${tenantId}:cds-es:v1:onehealth-research:employee:controller`;
    const signingKid = 'registered-signing-kid';
    const encryptionKid = 'registered-encryption-kid';
    const tenantsCacheManager = {
      tenantExists: jest.fn(async (vaultId: string) => vaultId === tenantVaultId),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async (vaultId: string) => vaultId === tenantVaultId ? tenantCollection : 'host'),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#registry:org.schema',
        selector: { section: 'registry', format: 'org.schema' },
        serviceEndpoint: 'Organization',
        actions: ['_batch', '_activate'],
      }]),
      getTenant: jest.fn(),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'professional-order-thid',
          iss: issuerDid,
          jti: 'professional-order-jti',
          meta: {
            jws: { protected: { alg: 'ML-DSA-44', kid: signingKid }, signature: 'signature' },
            jwe: { header: { skid: encryptionKid } },
          },
          body: { data: [] },
        },
      })),
      getHmacBase64Url: jest.fn(async (value: string, vaultId: string) => `${vaultId}:${value}`),
      unprotectConfidentialData: jest.fn(async () => ({
        didDocument: {
          verificationMethod: [
            { id: `${issuerDid}#${signingKid}`, publicKeyJwk: { kty: 'AKP', alg: 'ML-DSA-44', pub: 'c3ludGhldGlj', kid: signingKid, use: 'sig' } },
            { id: `${issuerDid}#${encryptionKid}`, publicKeyJwk: { kty: 'OKP', crv: 'ML-KEM-768', x: 'enc' } },
          ],
        },
      })),
    };
    const appAuthManager = { verifyBearerToken: jest.fn(async () => ({ sub: issuerDid })) };
    const harness = buildTestApp({ appAuthManager, tenantsCacheManager, kmsService });
    harness.vaultRepository.query.mockImplementation(async (vaultId: string) =>
      vaultId === tenantCollection ? [{ protected: 'employee-document' }] : []);
    harness.cryptographyService.verifyDetachedJws.mockResolvedValue(true);

    const response = await request(harness.app)
      .post('/host/cds-es/v1/test/registry/org.schema/Order/_batch')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .set('Authorization', 'Bearer portal-token')
      .send({ request: 'compact-jwe' });

    expect(response.status).toBe(202);
    expect(harness.vaultRepository.query).toHaveBeenCalledWith(
      tenantCollection,
      expect.objectContaining({ sectionId: expect.any(String) }),
    );
    expect(harness.queueAdapter.addJob).toHaveBeenCalledWith(
      expect.stringContaining('host:Order:_batch'),
      expect.any(Object),
    );
  });

  it('normalizes a signed encrypted SDK token exchange payload into the manager body contract', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({
        valid: true,
        payload: { sub: 'verified-account-subject' },
      })),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'profile-activation-exchange',
          iss: 'did:web:controller.example',
          subject_token: 'single-use-activation-code',
          client_instance_id: 'browser-installation',
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async () => 'tenant-physical-collection'),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#identity:openid',
        selector: { section: 'identity', format: 'openid' },
        serviceEndpoint: 'Token',
        actions: ['_exchange'],
      }]),
      getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, kmsService, tenantsCacheManager, signedPolicyEnvelope: true });

    const response = await request(app)
      .post('/example-tenant/cds-ca-bc/v1/animal-care/identity/openid/Token/_exchange')
      .set('Authorization', 'Bearer signed-account-token')
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
    expect(queueAdapter.addJob.mock.calls[0][1].content.body).toMatchObject({
      subject_token: 'single-use-activation-code',
      client_instance_id: 'browser-installation',
    });
  });

  it('verifies a new profile wallet key during pre-DCR token exchange without treating it as registered authority', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };

    const embeddedJwk = { kty: 'AKP', alg: 'ML-DSA-44', pub: 'c3ludGhldGlj', kid: 'new-wallet-signing-key', use: 'sig' };
    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({
        valid: true,
        payload: { sub: 'verified-account-subject' },
      })),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'profile-activation-exchange-signed',
          jti: randomUUID(),
          iss: 'did:web:portal.example:card:vetchain:12402:0000855138505354:family:owner:v3-RoleCode%7CRESPRSN',
          meta: {
            jws: {
              protected: { alg: 'ML-DSA-44', kid: 'new-wallet-signing-key', jwk: embeddedJwk, skid: fixtureReplyKey.kid },
              signature: 'wallet-signature',
            },
            jwe: { header: { skid: fixtureReplyKey.kid, jwk: fixtureReplyKey } },
          },
          body: {
            subject_token: 'single-use-activation-code',
            client_instance_id: 'browser-installation',
          },
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async () => 'tenant-physical-collection'),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#identity:openid',
        selector: { section: 'identity', format: 'openid' },
        serviceEndpoint: 'Token',
        actions: ['_exchange'],
      }]),
      getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
    };
    const harness = buildTestApp({ appAuthManager, kmsService, tenantsCacheManager });
    harness.cryptographyService.verifyDetachedJws.mockResolvedValue(true);

    const response = await request(harness.app)
      .post('/example-tenant/cds-ca-bc/v1/animal-care/identity/openid/Token/_exchange')
      .set('Authorization', 'Bearer signed-account-token')
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(harness.cryptographyService.verifyDetachedJws).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(String),
      embeddedJwk,
    );
    expect(harness.vaultRepository.query).not.toHaveBeenCalled();
    expect(harness.queueAdapter.addJob).toHaveBeenCalledTimes(1);
  });

  it('preserves the neutral employee authorization URN and explicit routed sector for the token worker', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'false',
    };
    const employeeAuthorizationUrn = 'urn:cds-ca-bc:v1:organization:bn:Example-123:member:zJJPb9sJCAcnFLu8tVHGF4c:2250';
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'portable-professional-exchange',
          iss: 'did:web:professional.example',
          body: {
            [IdentityAuthRequestFields.EmployeeAuthorizationUrn]: employeeAuthorizationUrn,
            [IdentityAuthRequestFields.ClientInstanceId]: 'browser-installation',
          },
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getCollectionName: jest.fn(async () => 'tenant-physical-collection'),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#identity:openid',
        selector: { section: 'identity', format: 'openid' },
        serviceEndpoint: 'Token',
        actions: ['_exchange'],
      }]),
      getTenant: jest.fn(async () => ({ authorizationStatus: 'active' })),
    };
    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({
        valid: true,
        payload: { sub: 'verified-professional-account' },
      })),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, kmsService, tenantsCacheManager, signedPolicyEnvelope: true });

    const response = await request(app)
      .post('/example-tenant/cds-ca-bc/v1/animal-research/identity/openid/Token/_exchange')
      .set('Authorization', 'Bearer signed-account-token')
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
    expect(queueAdapter.addJob.mock.calls[0][1]).toMatchObject({
      tenantId: 'example-tenant',
      jurisdiction: 'ca-bc',
      sector: 'animal-research',
      content: { body: {
        [IdentityAuthRequestFields.EmployeeAuthorizationUrn]: employeeAuthorizationUrn,
      } },
    });
  });

  it('allows host organization _activate without bearer in demo mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'demo',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'false',
      DIDCOMM_PLAIN: 'true',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post('/host/cds-es/v1/test/registry/org.schema/Organization/_activate')
      .set('Content-Type', 'application/json')
      .send({});

    // If bearer were still mandatory here, we'd get 401.
    expect(response.status).toBe(400);
  });

  it('requires bearer in strict mode when insecure bearer is disabled', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const { app } = buildTestApp();
    const response = await request(app)
      .post(credentialPath)
      .set('Content-Type', 'application/json')
      .send({});

    expect(response.status).toBe(401);
    expect(response.text || '').toContain('Missing or invalid Bearer token');
  });

  it('rejects invalid bearer in strict mode when validation is enforced', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => {
        throw new Error('bad token');
      }),
    };
    const { app } = buildTestApp({ appAuthManager });
    const response = await request(app)
      .post(credentialPath)
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer invalid-token')
      .send({});

    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith('invalid-token');
    expect(response.status).toBe(401);
    expect(response.text || '').toContain('Invalid Bearer token');
  });

  it('calls verifyIdToken for valid bearer in strict mode and continues request flow', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ sub: 'test-client' })),
    };
    const { app } = buildTestApp({ appAuthManager });
    const response = await request(app)
      .post(credentialPath)
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith('valid-token');
    // Should fail later due to tenant setup in this test harness, not due to bearer auth.
    expect(response.status).toBe(404);
  });

  it('propagates verified bearer payload into Organization/_issue jobs in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({
        valid: true,
        payload: { email: SAFE.firstContactEmail, email_verified: true, sub: 'controller-sub-001' },
      })),
    };
    const tenantsCacheManager = {
      getDidServiceConfig: jest.fn(async () => [{
        id: '#registry:org.schema',
        selector: { section: 'registry', format: 'org.schema' },
        serviceEndpoint: 'organization',
        actions: ['_issue'],
      }]),
      getTenant: jest.fn(),
      getCollectionName: jest.fn(),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'issue-thid-001',
          iss: fixtureControllerDid,
          meta: {
            jwe: { header: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } },
          },
          body: {
            data: [{
              resource: { meta: { claims: {
                  'org.schema.Organization.alternateName': 'acme-health',
                  'org.schema.Service.category': 'health-care',
                } } },
            }],
          },
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, tenantsCacheManager, kmsService, signedPolicyEnvelope: true });
    const response = await request(app)
      .post('/host/cds-es/v1/health-care/registry/org.schema/Organization/_issue')
      .set('Authorization', 'Bearer valid-token')
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith('valid-token', undefined, undefined);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
    const queuedJob = queueAdapter.addJob.mock.calls[0][1];
    expect(queuedJob.content.meta.bearer.jwt.payload).toEqual({
      email: SAFE.firstContactEmail,
      email_verified: true,
      sub: 'controller-sub-001',
    });
  });

  it('accepts a deterministically signed id_token from one virtual BFF issuer in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const fixture = await buildDeterministicIdTokenFixture({
      seed: 'gw-security-mode-seed-001',
      issuer: 'did:web:bff.demo.example',
      audience: 'gw-demo-audience',
      subject: 'controller-sub-001',
      email: SAFE.firstContactEmail,
      extraClaims: {
        tenant_id: 'acme-id',
      },
    });
    const tokenVerifier = new DeterministicJwtTokenVerifier({
      issuer: 'did:web:bff.demo.example',
      audience: 'gw-demo-audience',
      publicJwk: fixture.publicJwk,
    });
    const appAuthManager = new AppAuthorizationManager(
      {
        get: jest.fn(),
        put: jest.fn(),
        createNewVault: jest.fn(),
        vaultExists: jest.fn(),
        getVaultConfig: jest.fn(),
        createNewSection: jest.fn(),
        updateSection: jest.fn(),
        getAllSections: jest.fn(),
        sectionExists: jest.fn(),
        getContainersListInSection: jest.fn(),
        getContainersInSection: jest.fn(),
        getHistory: jest.fn(),
        query: jest.fn(),
        delete: jest.fn(),
        purge: jest.fn(),
      } as any,
      tokenVerifier,
      {
        getPublicVerificationKey: jest.fn(),
        init: jest.fn(),
        provisionKeys: jest.fn(),
        getPublicJwks: jest.fn(),
        getPublicEncryptionKey: jest.fn(),
        getHostPublicJwkSet: jest.fn(),
        decodeRequest: jest.fn(),
        signWithManagedKey: jest.fn(),
        signWithReconstructedKey: jest.fn(),
        encodeResponse: jest.fn(),
        createDetachedJws: jest.fn(),
        createCompactJws: jest.fn(),
        protectConfidentialData: jest.fn(),
        unprotectConfidentialData: jest.fn(),
        getHmacBase64Url: jest.fn(),
        protectAttributesNameAndValue: jest.fn(),
      } as any,
      {
        verifyJws: jest.fn(),
      } as any,
    );
    const tenantsCacheManager = {
      getDidServiceConfig: jest.fn(async () => [{
        id: '#registry:org.schema',
        selector: { section: 'registry', format: 'org.schema' },
        serviceEndpoint: 'organization',
        actions: ['_issue'],
      }]),
      getTenant: jest.fn(),
      getCollectionName: jest.fn(),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'issue-thid-oidc-001',
          iss: fixtureControllerDid,
          meta: {
            jwe: { header: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } },
          },
          body: {
            data: [{
              resource: { meta: { claims: {
                  'org.schema.Organization.alternateName': 'acme-health',
                  'org.schema.Service.category': 'health-care',
                } } },
            }],
          },
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, tenantsCacheManager, kmsService, signedPolicyEnvelope: true });
    const response = await request(app)
      .post('/host/cds-es/v1/health-care/registry/org.schema/Organization/_issue')
      .set('Authorization', `Bearer ${fixture.compactToken}`)
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
    const queuedJob = queueAdapter.addJob.mock.calls[0][1];
    expect(queuedJob.content.meta.bearer.jwt.payload).toMatchObject({
      email: SAFE.firstContactEmail,
      tenant_id: 'acme-id',
      sub: 'controller-sub-001',
    });
  });

  it('accepts one deterministically signed controller proof bearer on host lifecycle routes in strict mode', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'true',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'true',
    };

    const fixture = await buildDeterministicVpTokenFixture({
      seed: 'gw-security-mode-vp-seed-001',
      extraPayload: { iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 },
      issuerDid: 'did:web:controller.demo.example',
      audience: 'did:web:gw.demo.example#tenant_lifecycle',
      credentials: [
        {
          credential: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
            issuer: 'did:web:ica.demo.example',
            issuanceDate: '2040-01-01T00:00:00.000Z',
            credentialSubject: {
              id: 'did:web:controller.demo.example',
              memberOf: { taxID: 'B12345678' },
              hasOccupation: { identifier: { value: 'RESPRSN' } },
            },
          },
        },
      ],
    });

    const appAuthManager = new AppAuthorizationManager(
      {
        get: jest.fn(),
        put: jest.fn(),
        createNewVault: jest.fn(),
        vaultExists: jest.fn(),
        getVaultConfig: jest.fn(),
        createNewSection: jest.fn(),
        updateSection: jest.fn(),
        getAllSections: jest.fn(),
        sectionExists: jest.fn(),
        getContainersListInSection: jest.fn(),
        getContainersInSection: jest.fn(),
        getHistory: jest.fn(),
        query: jest.fn(),
        delete: jest.fn(),
        purge: jest.fn(),
      } as any,
      {
        verify: jest.fn(async () => ({ valid: false, error: 'not an id token' })),
      } as any,
      {
        getPublicVerificationKey: jest.fn(),
        init: jest.fn(),
        provisionKeys: jest.fn(),
        getPublicJwks: jest.fn(),
        getPublicEncryptionKey: jest.fn(),
        getHostPublicJwkSet: jest.fn(),
        decodeRequest: jest.fn(),
        signWithManagedKey: jest.fn(),
        signWithReconstructedKey: jest.fn(),
        encodeResponse: jest.fn(),
        createDetachedJws: jest.fn(),
        createCompactJws: jest.fn(),
        protectConfidentialData: jest.fn(),
        unprotectConfidentialData: jest.fn(),
        getHmacBase64Url: jest.fn(),
        protectAttributesNameAndValue: jest.fn(),
      } as any,
      {
        verifyJws: jest.fn(),
      } as any,
    );
    const tenantsCacheManager = {
      getDidServiceConfig: jest.fn(async () => [{
        id: '#registry:org.schema',
        selector: { section: 'registry', format: 'org.schema' },
        serviceEndpoint: 'organization',
        actions: ['_disable'],
      }]),
      getTenant: jest.fn(),
      getCollectionName: jest.fn(),
    };
    const kmsService = {
      decodeRequest: jest.fn(async () => ({
        content: {
          thid: 'disable-thid-001',
          iss: String(fixture.payload.sub),
          meta: {
            jwe: { header: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } },
          },
          body: {
            data: [{
              resource: { meta: { claims: {
                  'org.schema.Organization.identifier.value': 'B12345678',
                } } },
            }],
          },
        },
      })),
      getHmacBase64Url: jest.fn(),
      unprotectConfidentialData: jest.fn(),
      getPublicVerificationKey: jest.fn(),
      createDetachedJws: jest.fn(),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, tenantsCacheManager, kmsService, signedPolicyEnvelope: true });
    const response = await request(app)
      .post('/host/cds-es/v1/test/registry/org.schema/Organization/_disable')
      .set('Authorization', `Bearer ${fixture.compactToken}`)
      .type('form')
      .send({ request: 'opaque-jwe' });

    expect(response.status).toBe(202);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
    const queuedJob = queueAdapter.addJob.mock.calls[0][1];
    expect(queuedJob.content.meta.bearer.jwt.payload.iss).toBe('did:web:controller.demo.example');
    expect(queuedJob.content.meta.bearer.jwt.payload.vp).toBeDefined();
  });

  it('passes the plain-DIDComm meta JWK into controller bearer verification', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'compat',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      DIDCOMM_PLAIN: 'true',
    };
    const publicJwk = { kty: 'EC', crv: 'P-384', kid: 'controller-key', x: 'x', y: 'y' };
    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { iss: 'did:web:controller.example' } })),
    };
    const tenantsCacheManager = {
      getDidServiceConfig: jest.fn(async () => [{
        id: '#registry:org.schema',
        selector: { section: 'registry', format: 'org.schema' },
        serviceEndpoint: 'organization',
        actions: ['_batch'],
      }]),
      getTenant: jest.fn(),
      getCollectionName: jest.fn(),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, tenantsCacheManager });

    const response = await request(app)
      .post('/host/cds-es/v1/test-network/registry/org.schema/Organization/_batch')
      .set('Authorization', 'Bearer controller.proof.jwt')
      .set('Content-Type', 'application/didcomm-plain+json')
      .send({ thid: 'plain-controller-submit', meta: { jws: { protected: { jwk: publicJwk } } } });

    expect(response.status).toBe(202);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith('controller.proof.jwt', publicJwk, undefined);
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
  });

  it('binds tenant plain-DIDComm verification to the post-DCR storage scope', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'compat',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      DIDCOMM_PLAIN: 'true',
    };
    const publicJwk = { kty: 'EC', crv: 'P-384', kid: 'controller-key', x: 'x', y: 'y' };
    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({ valid: true, payload: { iss: 'did:web:controller.example' } })),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#entity:org.schema:employee:_batch',
        selector: { section: 'entity', format: 'org.schema' },
        serviceEndpoint: 'employee',
        actions: ['_batch'],
      }]),
      getTenant: jest.fn(async () => ({ status: 'active' })),
      getCollectionName: jest.fn(async () => 'tenant-physical-collection'),
    };
    const { app, queueAdapter } = buildTestApp({ appAuthManager, tenantsCacheManager });

    const response = await request(app)
      .post('/VATES-B42215152/cds-eu/v1/onehealth-research/entity/org.schema/Employee/_batch')
      .set('Authorization', 'Bearer controller.proof.jwt')
      .set('Content-Type', 'application/didcomm-plain+json')
      .send({ thid: 'plain-employee-submit', meta: { jws: { protected: { jwk: publicJwk } } } });

    expect(response.status).toBe(202);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith(
      'controller.proof.jwt',
      publicJwk,
      {
        vaultId: 'onehealth-research_VATES-B42215152',
        collectionName: 'tenant-physical-collection',
      },
    );
    expect(queueAdapter.addJob).toHaveBeenCalledTimes(1);
  });

  /**
   * Journey:
   * 1. An individual data client submits one FHIR Communication with a SMART bearer.
   * 2. The route opts into tenant-signed SMART verification before scope enforcement.
   * 3. The accepted request is queued with the verified actor payload.
   * Authorization invariant: SMART opt-in is limited to an individual FHIR data route.
   * Persistence invariant: only the verified claims enter job metadata; the token is not persisted in the resource.
   */
  it('opts an individual FHIR data route into tenant-signed SMART bearer verification', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'compat',
      DEMO_ALLOW_INSECURE_BEARER: 'false',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'false',
    };
    const appAuthManager = {
      verifyBearerToken: jest.fn(async () => ({
        valid: true,
        payload: {
          iss: 'did:web:beta-gw.vetchain.app:tenant',
          sub: EXAMPLE_PROFILE_PROVIDER_DID,
          scope: 'organization/Composition.cruds?subject=did:web:animal.example:individual:001&section=*',
        },
      })),
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#individual:org.hl7.fhir.r4',
        selector: { sector: DataspaceSectors.AnimalCare, section: 'individual', format: 'org.hl7.fhir.r4' },
        serviceEndpoint: 'Communication',
        actions: ['_batch'],
      }]),
      getTenant: jest.fn(async () => ({})),
      getCollectionName: jest.fn(async () => 'animal-care-tenant-collection'),
    };
    const harness = buildTestApp({ appAuthManager, tenantsCacheManager });
    const path = `/${EXAMPLE_TENANT_IDENTIFIER}/cds-CA-BC/v1/${DataspaceSectors.AnimalCare}/individual/org.hl7.fhir.r4/Communication/_batch`;

    const response = await request(harness.app)
      .post(path)
      .set('Content-Type', 'application/fhir+json')
      .set('Authorization', 'Bearer tenant.smart.token')
      .send({
        resourceType: 'Bundle',
        type: 'batch',
        id: 'smart-fhir-communication',
        thid: 'smart-fhir-communication',
        entry: [],
      });

    expect(response.status).toBe(202);
    expect(appAuthManager.verifyBearerToken).toHaveBeenCalledWith(
      'tenant.smart.token',
      undefined,
      {
        vaultId: `${DataspaceSectors.AnimalCare}_${EXAMPLE_TENANT_IDENTIFIER}`,
        collectionName: 'animal-care-tenant-collection',
      },
      { acceptSmartAccessToken: true },
    );
  });

  /**
   * Journey:
   * 1. A local FHIR client sends one Communication Bundle with an unsigned demo bearer.
   * 2. GW accepts that bearer only because the explicit demo switch is enabled.
   * 3. The queued job preserves `sub` so managers can enforce clinical author ownership.
   * Authorization invariant: this decoding path is unavailable outside demo mode.
   * Persistence invariant: the bearer stays in job security metadata, never in the FHIR resource.
   */
  it('preserves an insecure demo bearer subject for a FHIR transport job', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'demo',
      DEMO_ALLOW_INSECURE_BEARER: 'true',
      JSON_LEGACY: 'false',
      FHIR_LEGACY: 'true',
      DIDCOMM_PLAIN: 'false',
    };
    const tenantsCacheManager = {
      tenantExists: jest.fn(async () => true),
      findTenantVaultIdByIdentifierValue: jest.fn(),
      getDidServiceConfig: jest.fn(async () => [{
        id: '#individual:org.hl7.fhir.r4',
        selector: { sector: DataspaceSectors.AnimalCare, section: 'individual', format: 'org.hl7.fhir.r4' },
        serviceEndpoint: 'Communication',
        actions: ['_batch'],
      }]),
      getTenant: jest.fn(async () => ({})),
      getCollectionName: jest.fn(),
    };
    const harness = buildTestApp({ tenantsCacheManager });
    const bearer = buildUnsignedJwt({ sub: EXAMPLE_PROFILE_PROVIDER_DID });

    const response = await request(harness.app)
      .post(`/${EXAMPLE_TENANT_IDENTIFIER}/cds-CA-BC/v1/${DataspaceSectors.AnimalCare}/individual/org.hl7.fhir.r4/Communication/_batch`)
      .set('Content-Type', 'application/fhir+json')
      .set('Authorization', `Bearer ${bearer}`)
      .send({
        resourceType: 'Bundle',
        type: 'batch',
        id: 'demo-fhir-communication',
        thid: 'demo-fhir-communication',
        entry: [],
      });

    expect(response.status).toBe(202);
    expect(harness.queueAdapter.addJob).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        content: expect.objectContaining({
          meta: expect.objectContaining({
            bearer: expect.objectContaining({
              jwt: expect.objectContaining({
                payload: expect.objectContaining({ sub: EXAMPLE_PROFILE_PROVIDER_DID }),
              }),
            }),
          }),
        }),
      }),
    );
  });
});
