import { IServerConfig } from '../config';
import { HostingManager } from '../managers/HostingManager';
import { SchemaOrgOrganizationClaim, SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { ServiceCapability } from 'sos-data-utils-ts/service-capabilities';
import { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';

function getHostEnv(key: string): string | undefined {
  const newKey = `HOST_${key}`;
  const legacyKey = `ORG_HOST_${key}`;
  return process.env[newKey] ?? process.env[legacyKey];
}

export async function bootstrapHost(hostingManager: HostingManager, bootConfig: IServerConfig): Promise<void> {
  const hostClaims: ClaimsRecord = {
    [SchemaOrgOrganizationClaim.IdentifierType]: bootConfig.host.idType,
    [SchemaOrgOrganizationClaim.IdentifierValue]: bootConfig.host.idValue,
    [SchemaOrgOrganizationClaim.AddressCountry]: bootConfig.host.jurisdiction,
    [SchemaOrgOrganizationClaim.LegalName]: bootConfig.host.legalName,
    [SchemaOrgOrganizationClaim.AlternateName]: 'host',
    [SchemaOrgPersonClaim.Email]: bootConfig.host.adminEmail,
    [SchemaOrgPersonClaim.Identifier]: `urn:uuid:${bootConfig.host.adminUid}`,
    [SchemaOrgPersonClaim.HasOccupation]: bootConfig.host.adminRole,
    [SchemaOrgServiceClaim.Category]: 'system',
    [SchemaOrgServiceClaim.IdentifierReference]: `urn:uuid:${bootConfig.host.idValue}-service`,
    [SchemaOrgServiceClaim.ServiceType]: ServiceCapability.OrganizationRegistryProvider,
  };
  const termsUrl = getHostEnv('TERMS_URL');
  if (termsUrl) {
    hostClaims[SchemaOrgServiceClaim.TermsOfService] = termsUrl;
  }

  try {
    await hostingManager.bootstrapHost(hostClaims);
  } catch (error) {
    console.error('[GW-API] FATAL: Host tenant bootstrapping failed.', error);
    throw error;
  }
}
