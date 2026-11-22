// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// 1. Submit the signed registered-profile proof to its pinned tenant. 2. Reserve the opaque
// reference as the ICA. 3. Issue only through the authenticated ICA boundary. Authorization is
// tenant-scoped and the response is never cacheable. No credentials are persisted by this router.
import { randomBytes } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { WalletAuthorizationError } from '../../managers/ProfessionalWalletIssuanceManager';
import { createProfessionalWalletRouter } from '../../routes/professional-wallet';

it('binds the wallet routes to the configured tenant and separately authenticates the ICA', async () => {
  const profile = { tenantId: e.tenantId, jurisdiction: 'EU', sector: 'health-care',
    configurationId: 'employee', vct: `${e.httpsBaseUrl}/types/employee` };
  const apiBase = e.httpsBaseUrl;
  const expectedPath = `/${profile.tenantId}/cds-${profile.jurisdiction}/v1/${profile.sector}/identity/openid/wallet`;
  const bearer = randomBytes(32).toString('base64url');
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
    profile, apiBase, icaBearer: bearer, manager,
    tenants: { isTenantOperational: async () => true, getTenantDid: async () => e.didWeb },
  }));
  const credentials = { client_id: e.resourceUuid, vp_token: proof };
  expect((await request(app).post(expectedPath.replace(profile.tenantId, `${profile.tenantId}-other`) + '/_authorize').send(credentials)).status).toBe(404);
  const begin = await request(app).post(expectedPath + '/_authorize').send(credentials);
  expect(begin.status).toBe(201);
  expect(begin.headers['cache-control']).toBe('no-store');
  expect(begin.body).toEqual({ authorization_reference: reference });
  const reserve = request(app).post(expectedPath + '/_reserve').send({ authorization_reference: reference });
  expect((await reserve).status).toBe(401);
  const granted = await request(app).post(expectedPath + '/_reserve').set('Authorization', `Bearer ${bearer}`)
    .send({ authorization_reference: reference });
  expect(granted.status).toBe(200);
  expect((await request(app).post(expectedPath + '/_sign').set('Authorization', `Bearer ${bearer}`)
    .send({ command: granted.body.command, holderKey: {} })).status).toBe(403);
  expect(order).toEqual(['authorize', 'reserve', 'issue']);
});
