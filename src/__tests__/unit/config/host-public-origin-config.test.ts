// Flow contract: a canonical public gateway origin permits only explicitly configured historical origins; configuration never derives authority from a request hostname.
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { getConfig, resetServerConfig } from '../../../config/server-config';

const canonical = SAFE.httpsBaseUrl;
const legacy = new URL(canonical);
legacy.hostname = `previous.${legacy.hostname}`;

describe('host public-origin configuration', () => {
  const initialEnvironment = process.env;
  beforeEach(() => {
    process.env = { ...initialEnvironment, HOST_PUBLIC_URL: canonical, HOST_EXTERNAL_DOMAIN: SAFE.domain };
    delete process.env.HOST_LEGACY_PUBLIC_URLS;
    resetServerConfig();
  });
  afterEach(() => { process.env = initialEnvironment; resetServerConfig(); });

  const configured = (): string[] | undefined => (getConfig() as unknown as { hostLegacyPublicUrls?: string[] }).hostLegacyPublicUrls;

  it('has no historical public origins unless explicitly configured', () => {
    expect(configured()).toEqual([]);
  });

  it('normalizes and deduplicates historical origins independently from the canonical identity', () => {
    process.env.HOST_LEGACY_PUBLIC_URLS = ` ${legacy.origin}/,${legacy.origin},${canonical}`;
    expect(configured()).toEqual([legacy.origin]);
    expect(getConfig().apiBaseUrl).toBe(canonical);
  });

  it.each([
    `${legacy.origin}/other`, `${legacy.origin}?scope=all`, `${legacy.origin}#identity`,
    `https://user:password@${legacy.host}`, `file://${legacy.host}`, `https://*.${SAFE.domain}`,
  ])('rejects an origin with authority or path ambiguity: %s', value => {
    process.env.HOST_LEGACY_PUBLIC_URLS = value;
    expect(configured).toThrow(/public.*origin|legacy.*url/i);
  });

  it('allows a declared HTTP loopback origin in a local test runtime', () => {
    process.env.NODE_ENV = 'test';
    process.env.DEPLOYMENT_ENV = 'local-network';
    process.env.HOST_LEGACY_PUBLIC_URLS = 'http://localhost:3500';
    expect(configured()).toEqual(['http://localhost:3500']);
  });

  it.each(['NODE_ENV', 'DEPLOYMENT_ENV'])('requires HTTPS when %s marks a deployed runtime', variable => {
    process.env.NODE_ENV = 'demo';
    process.env.DEPLOYMENT_ENV = 'local-network';
    process.env[variable] = 'staging';
    process.env.HOST_LEGACY_PUBLIC_URLS = 'http://localhost:3500';
    expect(configured).toThrow(/HTTPS/);
  });
});
