import { createHash, timingSafeEqual } from 'node:crypto';
import { Router, type Request } from 'express';
import type { ProfessionalWalletIssuanceManager, ProfessionalWalletTenant } from '../managers/ProfessionalWalletIssuanceManager';
import type { ITenantsManager } from '../managers/ITenantsManager';
import { getTenantVaultId } from '../utils/tenant';

type WalletProfile = Readonly<{
  tenantId: string;
  jurisdiction: string;
  sector: string;
  configurationId: string;
  vct: string;
}>;

const opaque = /^[A-Za-z0-9_-]{43,128}$/u;
const digest = (value: string) => createHash('sha256').update(value).digest();

function isProfile(value: unknown): value is WalletProfile {
  const profile = value as WalletProfile | undefined;
  return Boolean(profile && typeof profile.tenantId === 'string' && /^[A-Za-z0-9_-]{1,100}$/u.test(profile.tenantId)
    && profile.tenantId !== 'host' && typeof profile.jurisdiction === 'string' && /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/u.test(profile.jurisdiction)
    && typeof profile.sector === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(profile.sector)
    && typeof profile.configurationId === 'string' && /^[A-Za-z0-9_-]{1,100}$/u.test(profile.configurationId)
    && typeof profile.vct === 'string' && /^https:\/\/[^\s#?]+$/u.test(profile.vct));
}

export function readProfessionalWalletProfile(environment: NodeJS.ProcessEnv) {
  const profileJson = environment.PROFESSIONAL_WALLET_PROFILE_JSON;
  const icaBearer = environment.PROFESSIONAL_WALLET_ICA_BEARER;
  if (!profileJson && !icaBearer) return undefined;
  const profile: unknown = JSON.parse(profileJson || 'null');
  if (!isProfile(profile) || !icaBearer || !opaque.test(icaBearer)) throw new Error('Invalid professional wallet issuer configuration.');
  return { profile, icaBearer };
}

function hasOnly(body: unknown, names: string[]): body is Record<string, unknown> {
  return Boolean(body && typeof body === 'object' && !Array.isArray(body)
    && Object.keys(body).length === names.length && names.every(name => Object.hasOwn(body, name)));
}

export function createProfessionalWalletRouter(options: {
  profile: WalletProfile;
  apiBase: string;
  icaBearer: string;
  manager: Pick<ProfessionalWalletIssuanceManager, 'begin' | 'reserve' | 'issue'>;
  tenants: Pick<ITenantsManager, 'isTenantOperational' | 'getTenantDid'>;
}) {
  const router = Router({ caseSensitive: true, strict: true });
  const { profile, manager, tenants } = options;
  const tenantVaultId = getTenantVaultId(profile.sector, profile.tenantId);
  const root = `/${profile.tenantId}/cds-${profile.jurisdiction}/v1/${profile.sector}/identity/openid/wallet`;
  const authorizationAudience = new URL(root + '/_authorize', options.apiBase).href;
  const bearerHash = digest(options.icaBearer);
  async function tenant(): Promise<ProfessionalWalletTenant | undefined> {
    const tenantDid = await tenants.getTenantDid(tenantVaultId);
    if (!tenantDid || !await tenants.isTenantOperational(tenantVaultId)) return undefined;
    return { tenantVaultId, tenantDid, authorizationAudience, configurationId: profile.configurationId, vct: profile.vct };
  }

  function authenticateIca(request: Request): boolean {
    const bearer = /^Bearer ([A-Za-z0-9_-]{43,128})$/iu.exec(request.headers.authorization || '')?.[1];
    return Boolean(bearer && timingSafeEqual(digest(bearer), bearerHash));
  }

  /**
   * @openapi
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_authorize:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Prepare private professional wallet authorization for a registered profile
   *     description: Accepts a short-lived signed registered-profile presentation for the configured tenant and exact authorization audience.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             additionalProperties: false
   *             required: [client_id, vp_token]
   *             properties:
   *               client_id: { type: string }
   *               vp_token: { type: string }
   *     responses:
   *       '201': { description: One-use opaque authorization reference }
   *       '400': { description: Invalid request format }
   *       '403': { description: Professional authorization unavailable }
   *       '415': { description: Expected JSON }
   */
  router.post(root + '/_authorize', async (request, response) => {
    response.set('Cache-Control', 'no-store');
    if (!request.is('application/json')) return response.status(415).json({ error: 'invalid_request' });
    const body: unknown = request.body;
    if (!hasOnly(body, ['client_id', 'vp_token']) || typeof body.client_id !== 'string' || !body.client_id || body.client_id.length > 256
      || typeof body.vp_token !== 'string' || !body.vp_token || body.vp_token.length > 32_768) {
      return response.status(400).json({ error: 'invalid_request' });
    }
    try {
      const context = await tenant();
      if (context) {
        const reference = await manager.begin(context, { clientId: body.client_id, presentation: body.vp_token });
        return response.status(201).json({ authorization_reference: reference });
      }
    } catch { /* Never disclose professional, device or ledger details. */ }
    return response.status(403).json({ error: 'access_denied' });
  });

  /**
   * @openapi
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_reserve:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Reserve a professional wallet authorization for the credential authority
   *     description: Backend boundary. Only the configured credential authority may reserve the one-use reference.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             additionalProperties: false
   *             required: [authorization_reference]
   *             properties:
   *               authorization_reference: { type: string }
   *     responses:
   *       '200': { description: Opaque issuance command and credential configuration }
   *       '400': { description: Invalid request format }
   *       '401': { description: Credential authority authentication required }
   *       '403': { description: Professional authorization unavailable }
   *       '415': { description: Expected JSON }
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_sign:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Sign a reserved professional credential for a verified wallet key
   *     description: Backend boundary. The configured credential authority submits the redeemed command and verified public holder key. The tenant rechecks eligibility before signing.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             additionalProperties: false
   *             required: [command, holderKey]
   *             properties:
   *               command: { type: object }
   *               holderKey: { type: object }
   *     responses:
   *       '200': { description: Issuance identifier and tenant-signed SD-JWT VC }
   *       '400': { description: Invalid request format }
   *       '401': { description: Credential authority authentication required }
   *       '403': { description: Professional authorization unavailable }
   *       '415': { description: Expected JSON }
   */
  for (const operation of ['_reserve', '_sign'] as const) {
    router.post(root + '/' + operation, async (request, response) => {
      response.set('Cache-Control', 'no-store');
      if (!authenticateIca(request)) return response.status(401).json({ error: 'invalid_client' });
      if (!request.is('application/json')) return response.status(415).json({ error: 'invalid_request' });
      const body: unknown = request.body;
      try {
        const context = await tenant();
        if (context) {
          if (operation === '_reserve' && hasOnly(body, ['authorization_reference']) && typeof body.authorization_reference === 'string') {
            return response.json(await manager.reserve(context, body.authorization_reference));
          }
          if (operation === '_sign' && hasOnly(body, ['command', 'holderKey'])) {
            return response.json(await manager.issue(context, body.command, body.holderKey));
          }
          return response.status(400).json({ error: 'invalid_request' });
        }
      } catch { /* Never disclose professional, device or ledger details. */ }
      return response.status(403).json({ error: 'access_denied' });
    });
  }
  return router;
}
