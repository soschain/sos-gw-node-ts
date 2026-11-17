// Flow contract: local tests retain OIDC verification; unsigned demo identities
// are available only in the explicit local demo profile, never staging.
import { federateOidcIdTokenToFirebaseCustomToken } from '../../../auth/OidcFederationService';

describe('OIDC federation profile', () => {
  const saved = { ...process.env };
  beforeEach(() => {
    process.env.NODE_ENV = 'test'; process.env.NETWORK_MODE = 'test';
    process.env.SECURITY_MODE = 'strict'; process.env.DEPLOYMENT_ENV = 'local';
    delete process.env.EIDAS_ISSUER;
  });
  afterEach(() => { process.env = { ...saved }; });
  it('requires the trusted provider configuration during local tests', async () => {
    await expect(federateOidcIdTokenToFirebaseCustomToken({ provider: 'eidas', idToken: 'unsigned' }))
      .rejects.toThrow(/EIDAS_ISSUER/);
  });
  it('keeps the explicit local demonstration identity', async () => {
    process.env.SECURITY_MODE = 'demo';
    await expect(federateOidcIdTokenToFirebaseCustomToken({ provider: 'eidas', idToken: 'unsigned' }))
      .resolves.toMatchObject({ provider: 'eidas', subject: 'eidas:test-subject' });
  });
  it('does not enable the demonstration identity in staging', async () => {
    process.env.SECURITY_MODE = 'demo'; process.env.DEPLOYMENT_ENV = 'staging';
    await expect(federateOidcIdTokenToFirebaseCustomToken({ provider: 'eidas', idToken: 'unsigned' }))
      .rejects.toThrow(/EIDAS_ISSUER/);
  });
});
