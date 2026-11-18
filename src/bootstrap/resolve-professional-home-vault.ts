import { getOrganizationDidFromIndividualDid } from 'sos-data-utils-ts/individual-did-routing';
import type { ITenantsManager } from '../managers/ITenantsManager';

/** Selects an existing home registration for key resolution; employment and permissions are verified independently afterwards. */
export async function resolveProfessionalHomeVault(tenants: ITenantsManager, actorDid: string, fallbackVaultId: string): Promise<string> {
  const organizationDid = getOrganizationDidFromIndividualDid(actorDid);
  if (typeof tenants.findTenantVaultIdByDid !== 'function') throw new Error('Authoritative home tenant lookup is unavailable.');
  const homeVault = await tenants.findTenantVaultIdByDid(organizationDid);
  if (!homeVault) return fallbackVaultId;
  if (!await tenants.isTenantOperational(homeVault)) throw new Error('Professional home tenant is inactive.');
  return homeVault;
}
