// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// The home tenant authenticates each request and accepts only its pinned,
// signed receipt for this presentation and this fresh verification attempt.
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, type KeyLike, type JWTPayload } from 'jose';
import { REPOSITORY_SAFE_EXAMPLES as examples } from 'sos-data-utils-ts/repository-privacy';
import { ClearingHouseService } from '../../../services/ClearingHouseService';

describe('Clearing House signed receipts', () => {
  const saved = { ...process.env };
  const now = Math.floor(Date.now() / 1000);
  // This existing assurance-profile wire value is the subject of the binding checks.
  const request = { tenantDid: examples.didWeb, vpToken: examples.resourceUuid, acrValues: ['urn:antifraud:acr:openid4vp:employee'] };
  const hash = createHash('sha256').update(request.vpToken).digest('hex');
  let privateKey: KeyLike;
  let publicJwk: Awaited<ReturnType<typeof exportJWK>>;
  let fetchSpy: jest.SpyInstance;
  let receipt: string;
  const sign = (payload: JWTPayload) => new SignJWT(payload).setProtectedHeader({ alg: 'ES384', kid: examples.resourceUuid }).sign(privateKey);
  beforeAll(async () => {
    const pair = await generateKeyPair('ES384');
    privateKey = pair.privateKey;
    publicJwk = { ...await exportJWK(pair.publicKey), alg: 'ES384', kid: examples.resourceUuid, use: 'sig' };
  });
  beforeEach(() => {
    process.env.CLEARING_HOUSE_MODE = 'remote';
    process.env.SECURITY_MODE = 'strict';
    process.env.DEPLOYMENT_ENV = 'staging';
    process.env.CLEARING_HOUSE_URL = examples.httpsBaseUrl;
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const wire = JSON.parse(String(init?.body));
      receipt = await sign({ iss: examples.didWeb, aud: examples.didWeb, iat: now, exp: now + 60,
        jti: examples.resourceUuid, nonce: wire.nonce, acr: request.acrValues[0], amr: ['openid4vp'],
        vp_hash: hash, ledger_verified: true });
      return new Response(receipt, { headers: { 'content-type': 'application/jwt' } });
    });
  });
  afterEach(() => { fetchSpy.mockRestore(); process.env = { ...saved }; });
  function verifier(federated = false) {
    return new (ClearingHouseService as any)({ now: () => now,
      signClientAssertion: async () => sign({ iss: examples.didWeb, aud: examples.httpsBaseUrl, iat: now, exp: now + 60, jti: examples.resourceUuid }),
      resolveTrust: () => ({ homeTenantReference: examples.didWeb, issuer: federated ? examples.subjectCardProviders.humanIndexDid : examples.didWeb,
        audience: examples.didWeb, sourceTenant: { tenantReference: federated ? examples.subjectCardProviders.humanIndexDid : examples.didWeb,
          endpoint: examples.httpsBaseUrl, capabilities: ['verifier'] }, trustedFederatedTenantReferences: [], jwks: { keys: [publicJwk] } }),
    });
  }
  it('accepts the authentic receipt bound to this presentation', async () => {
    await expect(verifier().verifyVpToken(request)).resolves.toMatchObject({ ledgerVerified: true, vpHash: hash });
  });
  it('rejects HTTP success without a signed receipt', async () => {
    fetchSpy.mockResolvedValue(new Response('{}'));
    await expect(verifier().verifyVpToken(request)).rejects.toThrow(/signed|JWT|signature/i);
  });
  it('rejects a receipt reused for a new attempt', async () => {
    const service = verifier(); await service.verifyVpToken(request);
    fetchSpy.mockResolvedValue(new Response(receipt));
    await expect(service.verifyVpToken(request)).rejects.toThrow(/nonce|request/i);
  });
  it('authenticates the backend verification request', async () => {
    await verifier().verifyVpToken(request);
    expect(fetchSpy).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ headers: expect.objectContaining({ authorization: expect.stringMatching(/^Bearer /) }) }));
  });
  it('rejects an unrecognized federated verifier before making a request', async () => {
    await expect(verifier(true).verifyVpToken(request)).rejects.toThrow(/trust/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
