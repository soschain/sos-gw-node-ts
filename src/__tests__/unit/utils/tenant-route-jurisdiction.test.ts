// Flow contract: independent identity and commerce claim catalogs preserve exact stored keys and authorization boundaries.
/**
 * Flow contract: organization storage, URNs and hosted routes use the
 * jurisdiction that issued the official identifier. An ISO 3166-2 region
 * therefore overrides the postal country, while national identifiers keep the
 * ISO 3166-1 country. Both values remain present as distinct legal evidence.
 */
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { resolveOrganizationRouteJurisdiction } from '../../../utils/tenant';

describe('organization route jurisdiction', () => {
  it('uses the ISO subdivision when regional official-id evidence is present', () => {
    expect(resolveOrganizationRouteJurisdiction({
      [SchemaOrgOrganizationClaim.AddressCountry]: 'CA',
      [SchemaOrgOrganizationClaim.AddressRegion]: 'CA-BC',
    })).toBe('CA-BC');
  });

  it('uses the country when no ISO subdivision evidence is present', () => {
    expect(resolveOrganizationRouteJurisdiction({
      [SchemaOrgOrganizationClaim.AddressCountry]: 'CA',
      [SchemaOrgOrganizationClaim.AddressRegion]: 'British Columbia',
    })).toBe('CA');
  });
});
