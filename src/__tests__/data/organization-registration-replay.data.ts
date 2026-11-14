import type { PublicJwk } from 'antifraud-data-utils-ts/cryptography';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';
import type { Sector } from 'gdc-common-utils-ts/models/urlPath';
import { testClaimsRegisterTenantExpanded } from './organization.data';

export const testRegistrationControllerDid = 'did:web:controller.example.test:organization:representative';

export const testRegistrationSignerJwk = {
  kid: 'registration-signing-key',
  kty: 'AKP',
  alg: 'ML-DSA-44',
  pub: 'registration-signing-public-material',
  use: 'sig',
} as PublicJwk;

export const testRegistrationEncrypterJwk = {
  kid: 'registration-encryption-key',
  kty: 'OKP',
  crv: 'ML-KEM-768',
  x: 'registration-encryption-public-material',
  use: 'enc',
} as PublicJwk;

export const testAnimalResearchSector = DataspaceSectors.AnimalResearch as Sector;

export const testAnimalResearchRegistrationClaims = {
  ...testClaimsRegisterTenantExpanded,
  [SchemaOrgOrganizationClaim.AddressCountry]: 'CA',
  [SchemaOrgOrganizationClaim.AddressRegion]: 'CA-BC',
  [SchemaOrgOrganizationClaim.IdentifierType]: 'BN',
  [SchemaOrgOrganizationClaim.IdentifierValue]: '7654321',
  [SchemaOrgOrganizationClaim.AlternateName]: '7654321',
  [SchemaOrgOrganizationClaim.LegalName]: 'Animal Research Organization',
  [SchemaOrgServiceClaim.Category]: testAnimalResearchSector,
};
