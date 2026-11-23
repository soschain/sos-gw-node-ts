// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// 1. Submit the signed registered-profile proof to its pinned tenant. 2. Read the tenant wallet offer
// and metadata. 3. Redeem the age offer with the wallet's key. Authorization is tenant-scoped.
// The manager uses encrypted test storage and never accepts browser-supplied evidence.
import { randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import express from 'express';
import request from 'supertest';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { ApprovedProofOfAgeVault } from 'sos-sdk-node-ts/approved-proof-of-age-vault';
import { TransactionalMemoryVaultRepository } from 'sos-sdk-node-ts/transactional-vault';
import { WalletAuthorizationError } from '../../managers/ProfessionalWalletIssuanceManager';
import { ProofOfAgeWalletIssuanceManager } from '../../managers/ProofOfAgeWalletIssuanceManager';
import { createMemoryWalletOfferStore } from '../../adapters/professional-wallet-offer-store-mem';
import { createProfessionalWalletRouter } from '../../routes/professional-wallet';
import { ReplayProtectionStoreMem } from '../../adapters/replay-protection-store';
import { VaultMemRepository } from '../../database/repositories/vault/vault.mem.repository';
import { AdapterCryptoSdkNode } from '../../gdc-backend-utils-node/adapters/node/crypto';
import { KmsService } from '../../services/KmsService';
import { TenantsCacheManager } from '../../managers/TenantsCacheManager';
import { getTenantVaultId } from '../../utils/tenant';

it('publishes an offer and OpenID metadata only at its configured tenant', async () => {
  const profile = { tenantId: e.tenantId, jurisdiction: 'EU', sector: 'health-care',
    configurationId: 'employee', credentialSigningAlgorithm: 'ML-DSA-65' as const, vct: `${e.httpsBaseUrl}/types/employee` };
  const apiBase = e.httpsBaseUrl;
  const expectedPath = `/${profile.tenantId}/cds-${profile.jurisdiction}/v1/${profile.sector}/identity/openid/wallet`;
  const secret = randomBytes(32);
  const reference = randomBytes(32).toString('base64url');
  const proof = 'signed-registered-profile-proof';
  const order: string[] = [];
  const manager = {
    begin: async (tenant, input) => {
      expect(tenant.authorizationAudience).toBe(new URL(expectedPath + '/_authorize', apiBase).href);
      expect(input).toEqual({ clientId: e.resourceUuid, presentation: proof });
      order.push('authorize');
      return reference;
    },
    reserve: async (_tenant, supplied) => {
      expect(supplied).toBe(reference);
      order.push('reserve');
      return { command: { actorReference: reference, subjectReference: reference,
        verificationTransactionId: reference, capability: 'identity.relationship.attest' as const },
        configurationId: profile.configurationId };
    },
    issue: async () => {
      order.push('issue');
      throw new WalletAuthorizationError('Professional authorization is no longer available');
    },
  } satisfies Parameters<typeof createProfessionalWalletRouter>[0]['manager'];
  const app = express().use(express.json()).use(createProfessionalWalletRouter({
    profile, apiBase, secret, store: createMemoryWalletOfferStore(), manager,
    tenants: { isTenantOperational: async () => true, getTenantDid: async () => e.didWeb },
  }));
  const credentials = { client_id: e.resourceUuid, vp_token: proof };
  expect((await request(app).post(expectedPath.replace(profile.tenantId, `${profile.tenantId}-other`) + '/_authorize').send(credentials)).status).toBe(404);
  const begin = await request(app).post(expectedPath + '/_authorize').send(credentials);
  expect(begin.status).toBe(201);
  expect(begin.headers['cache-control']).toBe('no-store');
  const issuer = new URL(expectedPath, apiBase).href;
  expect(begin.body.offerUri).toMatch(new RegExp('/credential-offers/[A-Za-z0-9_-]{43}$', 'u'));
  expect(begin.body.offerUri.startsWith(issuer + '/')).toBe(true);
  expect(begin.body.transactionCode).toMatch(/^\d{6}$/u);
  const metadata = await request(app).get('/.well-known/openid-credential-issuer' + expectedPath);
  expect(metadata.status).toBe(200);
  expect(metadata.body.credential_issuer).toBe(issuer);
  expect(metadata.body.credential_endpoint).toBe(issuer + '/credential');
  expect(metadata.body.credential_configurations_supported[profile.configurationId]).toMatchObject({
    credential_signing_alg_values_supported: [profile.credentialSigningAlgorithm],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
  });
  const offer = await request(app).get(new URL(begin.body.offerUri).pathname);
  expect(offer.body.credential_issuer).toBe(issuer);
  expect(offer.body.credential_configuration_ids).toEqual([profile.configurationId]);
  expect((await request(app).post(expectedPath + '/_reserve')).status).toBe(404);
  expect((await request(app).post(expectedPath + '/_sign')).status).toBe(404);
  expect((await request(app).post(expectedPath + '/_authorize-proof-of-age').send(credentials)).status).toBe(404);
  expect(order).toEqual(['authorize', 'reserve']);
});

it('keeps an enabled age offer separate from the employee profile and rejects caller evidence', async () => {
  const profile = { tenantId: e.tenantId, jurisdiction: 'EU', sector: 'health-care',
    configurationId: 'employee', vct: `${e.httpsBaseUrl}/types/employee` };
  const issuerPath = `/${profile.tenantId}/cds-${profile.jurisdiction}/v1/${profile.sector}/identity/openid/wallet`;
  const ageAction = issuerPath + '/_authorize-proof-of-age';
  const age = { configurationId: 'proof_of_age', doctype: 'eu.europa.ec.av.1' };
  const denyProfessional = async (): Promise<never> => { throw new Error('Employee issuer must not authorize age'); };
  const credentials = { client_id: e.resourceUuid, vp_token: 'signed-personal-member-presentation' };
  const vault = new VaultMemRepository();
  const cache = new TenantsCacheManager(vault, () => kms, e.tenantId);
  const kms: KmsService = new KmsService(new CryptographyService(new AdapterCryptoSdkNode()), cache);
  const tenantVaultId = getTenantVaultId(profile.sector, profile.tenantId);
  const holderReference = `${e.didWeb}:member`;
  const now = Math.floor(Date.now() / 1000);
  const keyPair = await generateKeyPair('ES256');
  const key = await exportJWK(keyPair.publicKey);
  try {
    await kms.init();
    await kms.provisionKeys(tenantVaultId);
    const projection = { docType: age.doctype, namespaces: { [age.doctype]: { age_over_18: true } } };
    const signerFixture = Buffer.from([0xa0]).toString('base64url');
    let signerCalls = 0;
    const holder = { tenantVaultId, holderReference };
    const reviewer = {};
    const reviews = new ApprovedProofOfAgeVault({
      store: new TransactionalMemoryVaultRepository(),
      verifyReview: async (participant, reviewId) => participant === reviewer && reviewId === e.resourceUuid
        ? { ...holder, revision: reviewId, expiresAt: (now + 60) * 1000, projection }
        : undefined,
      resolveHolder: async identity => {
        expect(identity).toEqual(holder);
        return holder;
      },
      now: () => now * 1000,
    });
    const ageManager = new ProofOfAgeWalletIssuanceManager({
      docType: age.doctype,
      kms, repository: vault, replay: new ReplayProtectionStoreMem(),
      verify: async context => {
        expect(context).toEqual({
          tenantDid: e.didWeb, tenantVaultId, authorizationAudience: new URL(ageAction, e.httpsBaseUrl).href,
          clientId: credentials.client_id, presentation: credentials.vp_token,
        });
        return { actorDid: holderReference, subjectDid: `${e.didWeb}:individual`,
          clientId: credentials.client_id, presentationId: credentials.vp_token, expiresAt: now + 60 };
      },
      readApprovedEvidence: holder => reviews.read(holder),
      sign: async (actual, holder) => {
        expect(actual).toEqual(projection);
        expect(holder).toEqual(key);
        signerCalls++;
        // The SDK's dedicated ISO mdoc test exercises the document signer.
        return signerFixture;
      },
      now: () => now,
    });
    const app = express().use(express.json()).use(express.urlencoded({ extended: false })).use(createProfessionalWalletRouter({
      profile, apiBase: e.httpsBaseUrl, secret: randomBytes(32), store: createMemoryWalletOfferStore(),
      tenants: { isTenantOperational: async () => true, getTenantDid: async () => e.didWeb },
      manager: { begin: denyProfessional, reserve: denyProfessional, issue: denyProfessional },
      proofOfAge: { ...age, authorize: ageManager.authorize.bind(ageManager), issue: ageManager.issue.bind(ageManager) },
    }));
    expect((await request(app).post(ageAction).send({ ...credentials, age_over_18: true })).status).toBe(400);
    expect((await request(app).post(ageAction).send(credentials)).status).toBe(403);
    await reviews.record(reviewer, e.resourceUuid);
    const begin = await request(app).post(ageAction).send(credentials);
    expect(begin.status).toBe(201);
    expect(begin.headers['cache-control']).toBe('no-store');
    const offer = await request(app).get(new URL(begin.body.offerUri).pathname);
    expect(offer.body.credential_configuration_ids).toEqual([age.configurationId]);
    const metadata = await request(app).get('/.well-known/openid-credential-issuer' + issuerPath);
    expect(metadata.body.credential_configurations_supported[age.configurationId]).toMatchObject({
      format: 'mso_mdoc', doctype: age.doctype, cryptographic_binding_methods_supported: ['cose_key'],
    });
    const [grantType] = Object.keys(offer.body.grants);
    const grant = await request(app).post(issuerPath + '/token').type('form').send({
      grant_type: grantType, 'pre-authorized_code': offer.body.grants[grantType]['pre-authorized_code'],
      tx_code: begin.body.transactionCode,
    });
    expect(grant.status).toBe(200);
    const nonce = await request(app).post(issuerPath + '/nonce');
    const proof = await new SignJWT({ nonce: nonce.body.c_nonce }).setAudience(offer.body.credential_issuer)
      .setIssuedAt(now).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: key }).sign(keyPair.privateKey);
    const redeem = (configurationId: string) => request(app).post(issuerPath + '/credential')
      .set('Authorization', `Bearer ${grant.body.access_token}`)
      .send({ credential_configuration_id: configurationId, proofs: { jwt: [proof] } });
    expect((await redeem(profile.configurationId)).status).toBe(400);
    const issued = await redeem(age.configurationId);
    expect(issued.status).toBe(200);
    expect(issued.body).toEqual({ credentials: [{ credential: signerFixture }] });
    expect((await redeem(age.configurationId)).status).toBe(401);
    expect(signerCalls).toBe(1);
  } finally { kms.destroy(); vault.clear(); }
});
