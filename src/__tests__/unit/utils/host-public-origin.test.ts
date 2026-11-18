// Flow contract: public transport aliases are server-selected exact origins; they neither rewrite external identities nor trust arbitrary incoming Host values.
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { getPublicApiBaseUrls, resolveRequestApiBaseUrl, rewriteHostedPublicUrl } from '../../../utils/host-public-origin';

const canonical = SAFE.httpsBaseUrl;
const previous = new URL(canonical);
previous.hostname = `previous.${previous.hostname}`;
const legacy = previous.origin;

describe('configured public host origins', () => {
  it('returns canonical first and deduplicates normalized origins', () => {
    expect(getPublicApiBaseUrls(`${canonical}/`, [legacy, `${legacy}/`, canonical])).toEqual([canonical, legacy]);
  });

  it('selects only an explicitly configured legacy Host', () => {
    expect(resolveRequestApiBaseUrl(previous.host.toUpperCase(), canonical, [legacy])).toBe(legacy);
    expect(resolveRequestApiBaseUrl(new URL(canonical).host, canonical, [legacy])).toBe(canonical);
  });

  it.each([undefined, `${previous.host}.invalid`, `${previous.host},${SAFE.domain}`, `unconfigured.${SAFE.domain}`])(
    'keeps canonical authority for missing or unconfigured Host: %s', host => {
      expect(resolveRequestApiBaseUrl(host, canonical, [legacy])).toBe(canonical);
    },
  );

  it('projects only the configured historical origin while preserving path, query and fragment', () => {
    const suffix = '/resource?query=value#fragment';
    expect(rewriteHostedPublicUrl(`${legacy}${suffix}`, canonical, [legacy])).toBe(`${canonical}${suffix}`);
    expect(rewriteHostedPublicUrl(`${canonical}${suffix}`, canonical, [legacy])).toBe(`${canonical}${suffix}`);
  });

  it('leaves external domains and non-URL identities unchanged', () => {
    const external = `https://external.${SAFE.domain}/resource`;
    expect(rewriteHostedPublicUrl(external, canonical, [legacy])).toBe(external);
    expect(rewriteHostedPublicUrl(SAFE.didWeb, canonical, [legacy])).toBe(SAFE.didWeb);
    expect(rewriteHostedPublicUrl(`${legacy}.invalid/resource`, canonical, [legacy])).toBe(`${legacy}.invalid/resource`);
  });

  it.each([`${legacy}/path`, `${legacy}?q=value`, `${legacy}#fragment`, `https://user:password@${previous.host}`, `https://*.${SAFE.domain}`, `file://${previous.host}`])(
    'rejects an ambiguous or non-HTTP configured alias: %s', value => {
      expect(() => getPublicApiBaseUrls(canonical, [value])).toThrow(/public.*origin/i);
    },
  );
});
