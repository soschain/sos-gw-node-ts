// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.
// Always create JSDoc, do not use strings inline in keys nor values, use types instead, and reuse the data test examples.
// File: src/__tests__/data/organization.data.ts

import { OrganizationConfig } from "../../gdc-backend-utils-node/models/entity";
import { URN_NAMESPACE, URN_NETWORK, URN_VERSION } from "./urn.data";
import { SchemaOrgOrganizationClaim, SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { serializeServiceCapabilityTokens } from 'sos-data-utils-ts/service-capabilities';
import { ServiceCapability } from 'sos-data-utils-ts/service-capabilities';
import { Sector } from "gdc-common-utils-ts/models/urlPath";
import { EntityLifecycleStatus, EntityType } from "../../gdc-backend-utils-node/models/enums";
import { testTenant1Vc } from "./credential.data";
import { testHostDidWeb, testRootOrgDidWeb, testHostDomain, testTenant1IdentifierUrn } from "./organization.constants";

/**
 * This file contains foundational data objects for test organizations.
 * It defines the atomic constants that are imported by other test files,
 * including `example-payloads.ts`, to ensure a single source of truth.
 */

// ===================================================================================
// RAW CLAIM SETS
// ===================================================================================

/**
 * The canonical set of claims for registering a new tenant.
 * This is the source of truth for values used in ORGANIZATION_REGISTRATION_REQUEST.
 */
export const testDefaultTenantServiceTypeClaim = serializeServiceCapabilityTokens([
  ServiceCapability.IndexProvider,
  ServiceCapability.DigitalTwinReader,
]) as string;

export const testDefaultHostServiceTypeClaim = serializeServiceCapabilityTokens([
  ServiceCapability.OrganizationRegistryProvider,
]) as string;

export const testClaimsRegisterTenantExpanded = {
  [SchemaOrgOrganizationClaim.AddressCountry]: "ES",
  [SchemaOrgOrganizationClaim.AlternateName]: "acme-id",
  [SchemaOrgOrganizationClaim.IdentifierType]: "TAX",
  [SchemaOrgOrganizationClaim.IdentifierValue]: "acme-id",
  [SchemaOrgOrganizationClaim.LegalName]: "Acme Organization SL",
  [SchemaOrgOrganizationClaim.Name]: "Acme Org",
  [SchemaOrgOrganizationClaim.NumberOfEmployees]: 2,
  [SchemaOrgOrganizationClaim.Url]: "api.acme.org",
  [SchemaOrgPersonClaim.Email]: "admin1@acme.org",
  [SchemaOrgPersonClaim.HasOccupation]: "ISCO-08|1120",
  [SchemaOrgServiceClaim.Category]: "health-care",
  [SchemaOrgServiceClaim.IdentifierReference]: "did:web:api-provider.example.com",
  [SchemaOrgServiceClaim.ServiceType]: testDefaultTenantServiceTypeClaim,
};

// ===================================================================================
// HOST ORGANIZATION DATA
// ===================================================================================
const testHostUuid = "d1d2d3d4-e5f6-7890-1234-567890abcdef";
export const testHostAlternateName = "host";
export const testHostAddressCountry = "ES";
export const testHostIdType = "TAX";
export const testHostIdValue = "A12345678";
export const testHostLegalName = "Hosting Organization";
export { testHostDomain, testHostDidWeb };
const testServiceManufacturerDidWebIdentifier = `urn:web:<manufacturer>`;
const testServiceManufacturerCategory = "system";
const testServiceManufacturerTerms = "https://github.com/<manufacturer>/<software>/terms";
const testServiceManufacturerPurposeType = testDefaultHostServiceTypeClaim;
export { testRootOrgDidWeb }; // https://testca.unid.es/.well-known/did.json

export const testConfigDataHost: OrganizationConfig = {
  id: testHostUuid,
  meta: { lastUpdated: '' },
  status: EntityLifecycleStatus.Active,
  type: EntityType.Organization,
  claims: {
    [SchemaOrgOrganizationClaim.AlternateName]: testHostAlternateName,
    [SchemaOrgOrganizationClaim.LegalName]: testHostLegalName,
    [SchemaOrgOrganizationClaim.IdentifierType]: testHostIdType,
    [SchemaOrgOrganizationClaim.IdentifierValue]: testHostIdValue,
    [SchemaOrgOrganizationClaim.IdentifierReference]: testHostDidWeb,
    [SchemaOrgOrganizationClaim.AddressCountry]: testHostAddressCountry,
  },
  didConfig: { service:[] },
  didDocument: { '@context': ``, id: `` },
  provider: {
    service: {
      identifier: testServiceManufacturerDidWebIdentifier,
      sectorCategory: testServiceManufacturerCategory,
      serviceType: testServiceManufacturerPurposeType,
      termsOfService: testServiceManufacturerTerms,
    },
  },
  networkStatus: [], // Host does not participate in networks.
};

// ===================================================================================
// TENANT 1 ORGANIZATION DATA (DERIVED FROM `testClaimsRegisterTenantExpanded`)
// ===================================================================================
const testTenant1Uuid = "c1c2c3d4-e5f6-7890-1234-567890abcdef";
export const testTenant1LegalName = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.LegalName];
export const testTenant1AddressCountry = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.AddressCountry];
export const testTenant1IdType = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.IdentifierType];
export const testTenant1IdValue = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.IdentifierValue];
/**
 * Canonical tenant id used across legal-organization tests.
 *
 * For legal organizations in the current contract, tests should anchor on the
 * tax-id / identifier value (`acme-id` here), not on a separate marketing alias.
 */
export const testTenant1TenantId = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.IdentifierValue];
/**
 * Legacy compatibility alias. Prefer `testTenant1TenantId` in new tests.
 */
export const testTenant1AlternateName = testTenant1TenantId;
export const testTenant1Domain = testClaimsRegisterTenantExpanded[SchemaOrgOrganizationClaim.Url];
export const testTenant1ServiceProviderCategory = testClaimsRegisterTenantExpanded[SchemaOrgServiceClaim.Category] as Sector;
export const testTenant1Admin1Email = testClaimsRegisterTenantExpanded[SchemaOrgPersonClaim.Email] as string;

// --- EXPORTED FOR DEPENDENCIES ---
export const testTenant1UrlExternal = `https://${testTenant1Domain}/`;
export const testTenant1DidWebExternal = `did:web:${testTenant1Domain}`;
export const testTenant1DidWebHosted = `did:web:${testHostDomain}:${testTenant1AlternateName}:${testTenant1AddressCountry}:v1:${testTenant1ServiceProviderCategory}`;
export const testTenant1VaultId = `${testTenant1ServiceProviderCategory}_${testTenant1AlternateName}`;

export { testTenant1IdentifierUrn };

export const testConfigTenant1: OrganizationConfig = {
  id: testTenant1Uuid,
  meta: { lastUpdated: '' },
  status: EntityLifecycleStatus.Active,
  type: EntityType.Organization,
  claims: {
    [SchemaOrgOrganizationClaim.LegalName]: testTenant1LegalName,
    [SchemaOrgOrganizationClaim.IdentifierType]: testTenant1IdType,
    [SchemaOrgOrganizationClaim.IdentifierValue]: testTenant1IdValue,
    [SchemaOrgOrganizationClaim.IdentifierReference]: testTenant1IdentifierUrn,
    [SchemaOrgOrganizationClaim.AlternateName]: testTenant1AlternateName,
    [SchemaOrgOrganizationClaim.AddressCountry]: testTenant1AddressCountry,
  },
  didConfig: { service:[] },
  didDocument: { '@context': ``, id: `` },  
  provider: {
    service: {
      category: testTenant1ServiceProviderCategory,
      serviceType: testDefaultTenantServiceTypeClaim,
    },
  },
  networkStatus: [], // This is populated by the manager during the registration flow.
  verifiablePresentation: [testTenant1Vc]
};
