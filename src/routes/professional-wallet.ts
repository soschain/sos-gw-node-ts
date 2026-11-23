import { createOpenId4VciIssuer, type WalletIssuanceCommand, type WalletOfferStore } from 'antifraud-sdk-node-ts';
import { Router, type RequestHandler } from 'express';
import { type ProfessionalCredentialSigningAlgorithm, type ProfessionalWalletIssuanceManager, type ProfessionalWalletTenant, WalletAuthorizationError } from '../managers/ProfessionalWalletIssuanceManager';
import type { ITenantsManager } from '../managers/ITenantsManager';
import { getTenantVaultId } from '../utils/tenant';

type WalletProfile = Readonly<{
  tenantId: string;
  jurisdiction: string;
  sector: string;
  configurationId: string;
  vct: string;
  credentialSigningAlgorithm?: ProfessionalCredentialSigningAlgorithm;
}>;

type WalletProfileProof = Readonly<{ clientId: string; presentation: string }>;
type AgeIssuerContext = Pick<ProfessionalWalletTenant, 'tenantDid' | 'tenantVaultId' | 'authorizationAudience'>;
type WalletHolderKey = Parameters<Parameters<typeof createOpenId4VciIssuer>[0]['issue']>[1];
type AgeCredentialIssuer = Readonly<{
  configurationId: string;
  doctype: string;
  authorize(context: AgeIssuerContext, input: WalletProfileProof): Promise<WalletIssuanceCommand>;
  issue(context: AgeIssuerContext, command: WalletIssuanceCommand, holderKey: WalletHolderKey): Promise<string | undefined>;
}>;

function isProfile(value: unknown): value is WalletProfile {
  const profile = value as WalletProfile | undefined;
  return Boolean(profile && typeof profile.tenantId === 'string' && /^[A-Za-z0-9_-]{1,100}$/u.test(profile.tenantId)
    && profile.tenantId !== 'host' && typeof profile.jurisdiction === 'string' && /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/u.test(profile.jurisdiction)
    && typeof profile.sector === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(profile.sector)
    && typeof profile.configurationId === 'string' && /^[A-Za-z0-9_-]{1,100}$/u.test(profile.configurationId)
    && (profile.credentialSigningAlgorithm === undefined || profile.credentialSigningAlgorithm === 'ES256'
      || profile.credentialSigningAlgorithm === 'ML-DSA-65')
    && typeof profile.vct === 'string' && /^https:\/\/[^\s#?]+$/u.test(profile.vct));
}

export function readProfessionalWalletProfile(environment: NodeJS.ProcessEnv) {
  const profileJson = environment.PROFESSIONAL_WALLET_PROFILE_JSON;
  const encodedSecret = environment.PROFESSIONAL_WALLET_OFFER_SECRET;
  const publicOrigin = environment.PROFESSIONAL_WALLET_PUBLIC_ORIGIN;
  if (!profileJson && !encodedSecret && !publicOrigin) return undefined;
  const profile: unknown = JSON.parse(profileJson || 'null');
  const secret = Buffer.from(encodedSecret ?? '', 'base64url');
  if (!isProfile(profile) || secret.length < 32 || secret.toString('base64url') !== encodedSecret) {
    throw new Error('Invalid professional wallet issuer configuration.');
  }
  return { profile, secret, publicOrigin };
}

function hasOnly(body: unknown, names: string[]): body is Record<string, unknown> {
  return Boolean(body && typeof body === 'object' && !Array.isArray(body)
    && Object.keys(body).length === names.length && names.every(name => Object.hasOwn(body, name)));
}

export function createProfessionalWalletRouter(options: {
  profile: WalletProfile;
  apiBase: string;
  publicOrigin?: string;
  secret: Uint8Array;
  store: WalletOfferStore;
  manager: Pick<ProfessionalWalletIssuanceManager, 'begin' | 'reserve' | 'issue'>;
  proofOfAge?: AgeCredentialIssuer;
  tenants: Pick<ITenantsManager, 'isTenantOperational' | 'getTenantDid'>;
}) {
  const router = Router({ caseSensitive: true, strict: true });
  const { profile, manager, tenants, proofOfAge } = options;
  if (proofOfAge?.configurationId === profile.configurationId) {
    throw new Error('Age and professional credentials require distinct wallet configurations.');
  }
  const credentialSigningAlgorithm = profile.credentialSigningAlgorithm ?? 'ES256';
  const tenantVaultId = getTenantVaultId(profile.sector, profile.tenantId);
  const root = `/${profile.tenantId}/cds-${profile.jurisdiction}/v1/${profile.sector}/identity/openid/wallet`;
  const apiOrigin = new URL(options.apiBase);
  const publicOrigin = new URL(options.publicOrigin ?? apiOrigin.origin);
  const loopback = ['127.0.0.1', 'localhost'].includes(apiOrigin.hostname) && publicOrigin.hostname === apiOrigin.hostname;
  if (publicOrigin.protocol !== 'https:' || publicOrigin.href !== publicOrigin.origin + '/'
    || (publicOrigin.origin !== apiOrigin.origin && !loopback)) {
    throw new Error('Professional wallet issuer requires the public HTTPS gateway origin.');
  }
  const authorizationAudience = new URL(root + '/_authorize', apiOrigin).href;
  const ageAction = root + '/_authorize-proof-of-age';
  const ageAudience = new URL(ageAction, apiOrigin).href;
  const credentialIssuer = new URL(root, publicOrigin).href;
  async function tenant(): Promise<ProfessionalWalletTenant | undefined> {
    const tenantDid = await tenants.getTenantDid(tenantVaultId);
    if (!tenantDid || !await tenants.isTenantOperational(tenantVaultId)) return undefined;
    return { tenantVaultId, tenantDid, authorizationAudience, configurationId: profile.configurationId, vct: profile.vct, credentialSigningAlgorithm };
  }

  const credentialConfiguration = {
    format: 'dc+sd-jwt' as const,
    vct: profile.vct,
    credential_signing_alg_values_supported: [credentialSigningAlgorithm],
  };
  const ageCredentialConfiguration = proofOfAge && {
    format: 'mso_mdoc' as const,
    doctype: proofOfAge.doctype,
    credential_signing_alg_values_supported: [-7],
  };
  const issuer = createOpenId4VciIssuer({
    credentialIssuer, store: options.store, secret: options.secret,
    credentialConfigurations: {
      [profile.configurationId]: credentialConfiguration,
      ...(proofOfAge && ageCredentialConfiguration && { [proofOfAge.configurationId]: ageCredentialConfiguration }),
    },
    async issue(command, holderKey, configurationId) {
      const context = await tenant();
      if (!context) return undefined;
      try {
        if (proofOfAge && configurationId === proofOfAge.configurationId) {
          return await proofOfAge.issue({ ...context, authorizationAudience: ageAudience }, command, holderKey);
        }
        return (await manager.issue(context, command, holderKey)).credential;
      } catch (error) {
        if (error instanceof WalletAuthorizationError) return undefined;
        throw error;
      }
    },
  });

  function authorizeOffer(
    prepare: (context: ProfessionalWalletTenant, input: WalletProfileProof) => Promise<Readonly<{
      command: WalletIssuanceCommand; configurationId: string;
    }>>,
  ): RequestHandler {
    return async (request, response) => {
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
          const { command, configurationId } = await prepare(context, { clientId: body.client_id, presentation: body.vp_token });
          return response.status(201).json(await issuer.prepare(command, configurationId));
        }
      } catch { /* Never disclose device, evidence or ledger details. */ }
      return response.status(403).json({ error: 'access_denied' });
    };
  }

  /**
   * @openapi
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_authorize:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Prepare a tenant wallet offer for a registered professional profile
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
   *       '201': { description: Tenant credential offer URL and one-use transaction code }
   *       '400': { description: Invalid request format }
   *       '403': { description: Professional authorization unavailable }
   *       '415': { description: Expected JSON }
   */
  router.post(root + '/_authorize', authorizeOffer(async (context, input) => {
    const reference = await manager.begin(context, input);
    return manager.reserve(context, reference);
  }));

  /**
   * @openapi
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_authorize-proof-of-age:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Prepare an offer for the registered member's own Proof of Age
   *     description: Available when a tenant's trusted Proof of Age issuer is configured. The server supplies the evidence.
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
   *       '201': { description: Tenant credential offer URL and one-use transaction code }
   *       '400': { description: Invalid request format }
   *       '403': { description: Holder or evidence not authorized }
   *       '404': { description: Proof of Age issuer unavailable }
   *       '415': { description: Expected JSON }
   */
  if (proofOfAge) {
    router.post(ageAction, authorizeOffer(async (context, input) => ({
      command: await proofOfAge.authorize({ ...context, authorizationAudience: ageAudience }, input),
      configurationId: proofOfAge.configurationId,
    })));
  }

  const walletProtocol: RequestHandler = async (request, response) => {
    try {
      const headers = new Headers();
      const contentType = request.get('content-type');
      const authorization = request.get('authorization');
      if (contentType) headers.set('content-type', contentType);
      if (authorization) headers.set('authorization', authorization);
      let body: string | undefined;
      if (request.method === 'POST' && request.is('application/x-www-form-urlencoded')) {
        const form = new URLSearchParams();
        for (const [key, value] of Object.entries(request.body ?? {})) {
          if (typeof value !== 'string') {
            return response.set('Cache-Control', 'no-store').status(400).json({ error: 'invalid_request' });
          }
          form.append(key, value);
        }
        body = form.toString();
      } else if (request.method === 'POST' && request.is('application/json')) {
        body = JSON.stringify(request.body);
      }
      const url = new URL(publicOrigin.origin + request.path);
      const result = await issuer.handle(new globalThis.Request(url, { method: request.method, headers, body }));
      if (!result) return response.status(404).end();
      for (const [header, value] of result.headers) response.set(header, value);
      return response.status(result.status).send(await result.text());
    } catch {
      return response.set('Cache-Control', 'no-store').status(503).json({ error: 'temporarily_unavailable' });
    }
  };

  /**
   * @openapi
   * /.well-known/openid-credential-issuer/{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet:
   *   get:
   *     tags: [2. Device and Identity Registration]
   *     summary: Read OpenID4VCI Credential Issuer metadata for the tenant
   *     responses:
   *       '200': { description: Tenant issuer, supported credentials and endpoints }
   * /.well-known/oauth-authorization-server/{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet:
   *   get:
   *     tags: [2. Device and Identity Registration]
   *     summary: Read the tenant authorization server metadata
   *     responses:
   *       '200': { description: Token endpoint and supported pre-authorized grant }
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/credential-offers/{reference}:
   *   get:
   *     tags: [2. Device and Identity Registration]
   *     summary: Read an unexpired one-use tenant credential offer
   *     responses:
   *       '200': { description: Issuer, credential configuration and pre-authorized grant }
   *       '404': { description: Unknown, expired or redeemed offer }
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/token:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Exchange a one-use pre-authorized code and transaction code for an access token
   *     responses:
   *       '200': { description: Short-lived access token }
   *       '400': { description: Invalid request, code or grant }
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/nonce:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Obtain a fresh holder-key challenge
   *     responses:
   *       '200': { description: Single-use credential nonce }
   * /{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/credential:
   *   post:
   *     tags: [2. Device and Identity Registration]
   *     summary: Issue a tenant-signed credential after verifying a wallet holder proof
   *     responses:
   *       '200': { description: Signed credential in the format of the selected tenant configuration }
   *       '400': { description: Invalid request, proof or nonce }
   *       '401': { description: Invalid or redeemed access token }
   */
  router.get('/.well-known/openid-credential-issuer' + root, walletProtocol);
  router.get('/.well-known/oauth-authorization-server' + root, walletProtocol);
  router.get(root + '/credential-offers/:reference', walletProtocol);
  router.post([root + '/token', root + '/nonce', root + '/credential'], walletProtocol);
  return router;
}
