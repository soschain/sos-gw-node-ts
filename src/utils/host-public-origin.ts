/** Normalizes a server-configured HTTP origin without accepting credentials, paths or wildcards. */
function publicOrigin(value: string): string {
  try {
    const url = new URL(value.trim());
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash || url.hostname.includes('*')) {
      throw new Error('Invalid public origin.');
    }
    return url.origin;
  } catch {
    throw new Error('Public origins must be HTTP(S) origins without credentials, paths, queries, fragments or wildcards.');
  }
}

/** Returns the canonical public origin and only its explicitly configured historical transport origins. */
export function getPublicApiBaseUrls(canonical: string, aliases: readonly string[] = []): readonly string[] {
  return [...new Set([canonical, ...aliases].map(publicOrigin))];
}

/** Selects a configured origin by exact Host; unknown Host values never supply a new authority. */
export function resolveRequestApiBaseUrl(hostHeader: string | undefined, canonical: string, aliases: readonly string[] = []): string {
  const origins = getPublicApiBaseUrls(canonical, aliases);
  const host = String(hostHeader || '').trim().toLowerCase();
  return origins.find(origin => new URL(origin).host.toLowerCase() === host) || origins[0];
}

/** Projects gateway-owned historical transport URLs without changing external domains or identity strings. */
export function rewriteHostedPublicUrl(value: string, canonical: string, aliases: readonly string[] = []): string {
  const origins = getPublicApiBaseUrls(canonical, aliases);
  let url: URL;
  try { url = new URL(value); } catch { return value; }
  if (url.username || url.password || url.origin === origins[0] || !origins.slice(1).includes(url.origin)) return value;
  return `${origins[0]}${url.pathname}${url.search}${url.hash}`;
}
