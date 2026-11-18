// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// A signed SMART client assertion authenticates only its current registered
// device, exact target and validity period, and cannot be consumed twice.
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, type KeyLike } from 'jose';
import { REPOSITORY_SAFE_EXAMPLES as examples } from 'sos-data-utils-ts/repository-privacy';
import { OpenIdAuthManager } from '../../../managers/OpenIdAuthManager';

describe('registered SMART client assertions', () => {
  const saved = { ...process.env };
  const now = Math.floor(Date.now() / 1000);
  let privateKey: KeyLike;
  let publicJwk: Awaited<ReturnType<typeof exportJWK>>;
  beforeAll(async () => {
    const pair = await generateKeyPair('ES384'); privateKey = pair.privateKey;
    publicJwk = { ...await exportJWK(pair.publicKey), alg: 'ES384', kid: examples.resourceUuid, use: 'sig' };
  });
  beforeEach(() => { process.env.SECURITY_MODE = 'strict'; process.env.NETWORK_MODE = 'test'; process.env.DEPLOYMENT_ENV = 'staging'; });
  afterEach(() => { process.env = { ...saved }; });
  function manager() {
    const profile = { clientId: examples.resourceUuid, jwks: { keys: [publicJwk] } };
    return new OpenIdAuthManager({ unprotectConfidentialData: async (document: any) => document.content } as any,
      {} as any, { get: async () => ({ status: 'active', content: profile }) } as any,
      { verifyVpToken: jest.fn() } as any);
  }
  async function assertion(audience: string = examples.didWeb, expires: number = now + 60) {
    return new SignJWT({ iss: examples.resourceUuid, sub: examples.resourceUuid, aud: audience, iat: now, exp: expires, jti: randomUUID() })
      .setProtectedHeader({ alg: 'ES384', kid: examples.resourceUuid, jwk: publicJwk }).sign(privateKey);
  }
  const input = (compact: string, clientId: string | undefined = examples.resourceUuid) => ({
    // The standardized assertion-type wire value is exercised directly here.
    body: { client_assertion: compact, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' },
    clientId, issuerDid: examples.didWeb, tenantVaultId: examples.tenantId,
    requestUrl: new URL('/identity/openid/smart/token', examples.httpsBaseUrl).href,
  });
  it('requires the registered client identifier even for an authentic signature', async () => {
    const request = { ...input(await assertion()), clientId: undefined };
    await expect((manager() as any).validateClientAssertion(request)).rejects.toThrow(/client_id|registered/i);
  });
  it('rejects an expired client assertion', async () => {
    await expect((manager() as any).validateClientAssertion(input(await assertion(examples.didWeb, now - 1)))).rejects.toThrow(/valid|signature|expir/i);
  });
  it('rejects a different URL merely containing the token endpoint suffix', async () => {
    const other = new URL('/different/identity/openid/smart/token', examples.httpsBaseUrl).href;
    await expect((manager() as any).validateClientAssertion(input(await assertion(other)))).rejects.toThrow(/target|aud|signature|valid/i);
  });
  it('accepts a registered assertion once and rejects its replay', async () => {
    const verifier = manager() as any; const request = input(await assertion());
    await expect(verifier.validateClientAssertion(request)).resolves.toMatchObject({ clientId: examples.resourceUuid });
    await expect(verifier.validateClientAssertion(request)).rejects.toThrow(/replay/i);
  });
});
