// Flow contract: validated ICA legal identity is reused during legacy activation without requiring duplicate caller claims.
import { describe, expect, it } from '@jest/globals';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { applyLegalOrganizationIdentityCompatibility } from '../../../managers/hosting/activation-helpers';

const LEGAL_NAME = 'Example Veterinary Organization';
const OFFICIAL_LEGAL_ID = 'CA-EXAMPLE-001';
const ADDRESS_COUNTRY = 'CA';

describe('legacy activation legal identity compatibility', () => {
  it('derives the Gaia-X legal identity from the validated ICA OrganizationCredential', () => {
    const normalizedClaims = applyLegalOrganizationIdentityCompatibility({}, {
      credentialSubject: {
        legalName: LEGAL_NAME,
        taxID: OFFICIAL_LEGAL_ID,
        address: [{ addressCountry: ADDRESS_COUNTRY }],
      },
    });

    expect(normalizedClaims).toEqual(expect.objectContaining({
      [SchemaOrgOrganizationClaim.LegalName]: LEGAL_NAME,
      [SchemaOrgOrganizationClaim.IdentifierValue]: OFFICIAL_LEGAL_ID,
      [SchemaOrgOrganizationClaim.AddressCountry]: ADDRESS_COUNTRY,
    }));
  });
});
