import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';
import { HttpStatusCodes } from 'sos-data-utils-ts/bff-wire-contract';
import type { BundleEntry, ErrorEntry } from 'sos-data-utils-ts/bundle-contract';
import type { DidCommDecodedMetadata } from 'sos-data-utils-ts/confidential-job';
import type { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import { Sector } from 'gdc-common-utils-ts/models/urlPath';
import { BundleEntryType } from '../../gdc-backend-utils-node/models/enums';
import type { IVaultRepository } from '../../database/repositories/vault/vault.repository';
import { normalizeContextualizedClaims } from '../../utils/claims';
import { validateNewOrganizationClaims } from '../../utils/claims-validator';
import { getTenantVaultId, isValidTenantAlternateName } from '../../utils/tenant';

type ProcessRegistrationEntryDeps = Readonly<{
  entry: BundleEntry;
  environment?: string;
  jobMeta?: DidCommDecodedMetadata;
  registrationControllerDid?: string;
  sectorsAllowed: string[];
  vaultRepository: IVaultRepository;
  applyLegalOrganizationIdentityCompatibility: (claims: ClaimsRecord) => ClaimsRecord;
  extractResources: (claims: ClaimsRecord, environment?: string) => { organization: any; person?: any; service: any };
  handleServiceAttachment: (service?: any) => Promise<any>;
  persistHostConfig: (org: any, allClaims: ClaimsRecord, contained: Array<any>) => Promise<any>;
  createPendingTenantRegistrationFromClaims: (params: {
    claims: ClaimsRecord;
    environment?: string;
    jobMeta?: DidCommDecodedMetadata;
    registrationControllerDid?: string;
  }) => Promise<ClaimsRecord>;
  handleError: (error: any, entryType?: string, meta?: any) => ErrorEntry;
}>;

/**
 * Processes the first registration request that creates either a host record or
 * a pending tenant registration offer.
 */
export async function processRegistrationEntry(
  deps: ProcessRegistrationEntryDeps,
): Promise<BundleEntry | ErrorEntry> {
  const rawClaims = deps.entry?.resource?.meta?.claims;
  const claims = rawClaims ? normalizeContextualizedClaims(rawClaims) : rawClaims;
  const entryType = deps.entry.type || 'Organization-unknown';

  if (!claims) {
    return deps.handleError(new ManagerError('Malformed entry: missing meta.claims', IssueType.Required), entryType, deps.entry.meta);
  }

  try {
    const normalizedClaims = deps.applyLegalOrganizationIdentityCompatibility(claims);
    validateNewOrganizationClaims(normalizedClaims);
    const alternateName = normalizedClaims[SchemaOrgOrganizationClaim.AlternateName] as string;

    if (!alternateName) {
      throw new ManagerError(`Missing required claim: '${SchemaOrgOrganizationClaim.AlternateName}'`, IssueType.Required);
    }

    if (alternateName !== 'host') {
      if (!isValidTenantAlternateName(alternateName)) {
        throw new ManagerError(`Invalid alternateName format: '${alternateName}'`, IssueType.Value);
      }

      const requestedSector = normalizedClaims[SchemaOrgServiceClaim.Category] as Sector;
      if (!requestedSector) {
        throw new ManagerError(`Missing required claim for new tenant: '${SchemaOrgServiceClaim.Category}'`, IssueType.Required);
      }
      if (requestedSector === Sector.SYSTEM) {
        throw new ManagerError("The 'system' sector is a reserved keyword and cannot be used by tenants.", IssueType.Forbidden);
      }
      if (!deps.sectorsAllowed.includes(requestedSector)) {
        throw new ManagerError(`The requested sector '${requestedSector}' is not supported by this gateway.`, IssueType.Value);
      }

      const vaultId = getTenantVaultId(requestedSector, alternateName);
      if (await deps.vaultRepository.vaultExists(vaultId)) {
        throw new ManagerError(`Conflict: a vault for '${vaultId}' already exists`, IssueType.Conflict);
      }
    }

    const { organization, person, service } = deps.extractResources(normalizedClaims, deps.environment);
    const processedService = await deps.handleServiceAttachment(service);
    let processedClaims = { ...normalizedClaims, ...(processedService?.meta?.claims || {}) };

    if (alternateName === 'host') {
      await deps.persistHostConfig(organization, processedClaims, [person, processedService]);
    } else {
      processedClaims = await deps.createPendingTenantRegistrationFromClaims({
        claims: normalizedClaims,
        environment: deps.environment,
        jobMeta: deps.jobMeta,
        registrationControllerDid: deps.registrationControllerDid,
      });
    }

    return {
      type: BundleEntryType.OrgRegistrationOffer,
      resource: {
        resourceType: ResourceTypesFhirR4.Organization,
        id: organization.id,
        meta: { claims: processedClaims },
      },
      response: { status: String(HttpStatusCodes.Created) },
    };
  } catch (error: any) {
    console.log('--- DEBUG: Caught error in processRegistrationEntry ---', error);
    return deps.handleError(error, entryType, deps.entry.meta);
  }
}
