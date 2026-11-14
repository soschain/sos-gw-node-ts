// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.
// File: src/models/indexing.ts

import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';

/**
 * Defines which claims are allowed to be indexed for different resource types.
 * This provides a single, strongly-typed source of truth for indexing strategies.
 */
export const AllowedIndexableClaims = {
  /**
   * Defines the claims that can be indexed in the central tenant registry for an Organization.
   */
  organizationRegistry: [
    SchemaOrgOrganizationClaim.AlternateName,
    SchemaOrgOrganizationClaim.IdentifierValue,
    SchemaOrgOrganizationClaim.IdentifierType,
    SchemaOrgOrganizationClaim.AddressCountry,
  ] as const, // Use 'as const' to provide strong typing for the array elements
};
