// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Local test selects a ledger, not an authentication bypass. Only explicitly
// selected local demo may decode an unsigned demonstration token.
import { REPOSITORY_SAFE_EXAMPLES as examples } from 'sos-data-utils-ts/repository-privacy';
import { DemoTokenVerifier } from '../../../auth/DemoTokenVerifier';
import { resolveTokenVerifierFromEnv } from '../../../auth/token-verifier-registry';
import { ReplayProtectionStoreNoop } from '../../../adapters/replay-protection-store';

describe('non-demo authentication', () => {
  const saved = { ...process.env };
  beforeEach(() => {
    process.env.NODE_ENV = 'test'; process.env.DEPLOYMENT_ENV = 'local';
    process.env.NETWORK_MODE = 'test'; process.env.SECURITY_MODE = 'strict';
  });
  afterEach(() => { process.env = { ...saved }; });
  it('does not select demo solely because the process is a test', () => {
    delete process.env.AUTH_TOKEN_VERIFIER;
    expect(resolveTokenVerifierFromEnv(true)).not.toBeInstanceOf(DemoTokenVerifier);
  });
  it('rejects explicitly configured demo authentication in a non-demo profile', () => {
    process.env.AUTH_TOKEN_VERIFIER = 'demo';
    expect(() => resolveTokenVerifierFromEnv(true)).toThrow(/demo/i);
  });
  it('does not accept an unsigned demo token outside demo', async () => {
    // Unsigned serialization is the negative behavior under test.
    const token = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(JSON.stringify({ sub: examples.didWeb })).toString('base64url')}.unsigned`;
    await expect(new DemoTokenVerifier().verify(token)).resolves.toMatchObject({ valid: false });
  });
  it('does not disable replay protection outside demo', async () => {
    await expect(new ReplayProtectionStoreNoop().reserveIfNotExists(examples.resourceUuid, 60)).rejects.toThrow(/demo/i);
  });
});

describe('deployment demo boundaries', () => {
  it.each([
    { NODE_ENV: 'production', NETWORK_MODE: 'test', SECURITY_MODE: 'demo' },
    { NODE_ENV: 'test', DEPLOYMENT_ENV: 'staging', NETWORK_MODE: 'test', SECURITY_MODE: 'demo' },
    { NODE_ENV: 'development', NETWORK_MODE: 'test-network', SECURITY_MODE: 'demo' },
  ])('rejects a demo profile outside local demonstration: %j', async env => {
    const policy = await import('../../../security/runtime-security-policy');
    expect(() => policy.assertRuntimeSecurityProfile(env)).toThrow(/demo/i);
  });
});
