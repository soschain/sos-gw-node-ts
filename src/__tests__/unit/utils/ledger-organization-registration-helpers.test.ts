// Flow contract: independent identity and commerce claim catalogs preserve exact stored keys and authorization boundaries.
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';

import {
  buildLedgerOrganizationId,
  resolveLedgerOrganizationId,
} from '../../../utils/ledger-organization-registration-helpers';

describe('ledger organization registration helpers', () => {
  it('builds the canonical ledger organization id as urn:org:*', () => {
    expect(buildLedgerOrganizationId('TAX', 'VATES-B12345678'))
      .toBe('urn:org:tax:VATES-B12345678');
  });

  it('resolves the canonical ledger organization id from claims', () => {
    expect(resolveLedgerOrganizationId({
      [SchemaOrgOrganizationClaim.IdentifierType]: 'TAX',
      [SchemaOrgOrganizationClaim.IdentifierValue]: 'acme-id',
    } as any)).toBe('urn:org:tax:acme-id');
  });

  it('normalizes legacy fallback ids to the canonical ledger URN', () => {
    expect(resolveLedgerOrganizationId(undefined, 'TAX|legacy-acme'))
      .toBe('urn:org:tax:legacy-acme');
  });
});
