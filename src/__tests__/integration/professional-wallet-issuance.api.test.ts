// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// 1. Submit the signed registered-profile proof to its pinned tenant. 2. Read the tenant wallet offer
// and metadata. Authorization is tenant-scoped. The offer is short-lived and never cacheable.
import { randomBytes } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { WalletAuthorizationError } from '../../managers/ProfessionalWalletIssuanceManager';
import { createMemoryWalletOfferStore } from '../../adapters/professional-wallet-offer-store-mem';
import { createProfessionalWalletRouter } from '../../routes/professional-wallet';

it('publishes an offer and OpenID metadata only at its configured tenant', async () => {
  const profile = { tenantId: e.tenantId, jurisdiction: 'EU', sector: 'health-care',
    configurationId: 'employee', vct: `${e.httpsBaseUrl}/types/employee` };
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
  const offer = await request(app).get(new URL(begin.body.offerUri).pathname);
  expect(offer.body.credential_issuer).toBe(issuer);
  expect(offer.body.credential_configuration_ids).toEqual([profile.configurationId]);
  expect((await request(app).post(expectedPath + '/_reserve')).status).toBe(404);
  expect((await request(app).post(expectedPath + '/_sign')).status).toBe(404);
  expect(order).toEqual(['authorize', 'reserve']);
});
