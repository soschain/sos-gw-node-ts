import { assertTenantClearingHouseTrust as assertPinnedTenantTrust, type TenantClearingHouseTrust } from 'antifraud-data-utils-ts/clearing-house';
export type { TenantClearingHouseTrust } from 'antifraud-data-utils-ts/clearing-house';

/** Deployment-owned trust selection; callers never supply endpoints or keys. */
export function resolveConfiguredClearingHouseTrust(tenantDid: string): TenantClearingHouseTrust {
  const entries = JSON.parse(process.env.CLEARING_HOUSE_TENANTS_JSON || '{}');
  const trust = Object.prototype.hasOwnProperty.call(entries, tenantDid) ? entries[tenantDid] : undefined;
  if (!trust) throw new Error('No Clearing House trust configured for this tenant.');
  return trust;
}

/** Loopback HTTP is available only to an explicitly opted-in local test. */
export function assertTenantClearingHouseTrust(trust: TenantClearingHouseTrust, tenantDid: string, allowLocalTestEndpoint = false): URL {
  return assertPinnedTenantTrust(trust, tenantDid, allowLocalTestEndpoint && process.env.NODE_ENV === 'test');
}
