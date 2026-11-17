// Flow contract: tenant lifecycle representative identity matching retains typed legal identifiers and never derives controller authority from an occupation.
import { describe, expect, it } from '@jest/globals';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const helperPath = '../../../utils/tenant-representative-identity';
const loadHelpers = () => import(helperPath);

const identifier = { type: SAFE.organizationIdentifierType, value: SAFE.organizationBusinessNumber };
const credential = { credentialSubject: { memberOf: { identifier: { additionalType: identifier.type, value: identifier.value } } } };

describe('tenant representative legal identifier binding', () => {
  it('routes actual lifecycle binding through the GW owner instead of legacy helpers', () => {
    const source = readFileSync(resolve('src/managers/hosting/HostingLifecycleService.ts'), 'utf8');
    expect(source.includes('sos-data-utils-ts/activation-policy')).toBe(false);
    expect(source).toContain('readRepresentativeOrganizationIdentifier');
    expect(source).toContain('matchesTenantLegalIdentifier');
  });
  it('reads the complete typed memberOf identifier and matches normalized case/whitespace', async () => {
    const { readRepresentativeOrganizationIdentifier, matchesTenantLegalIdentifier } = await loadHelpers();
    expect(readRepresentativeOrganizationIdentifier(credential)).toEqual(identifier);
    expect(matchesTenantLegalIdentifier(readRepresentativeOrganizationIdentifier(credential), { type: ` ${identifier.type.toLowerCase()} `, value: ` ${identifier.value} ` })).toBe(true);
  });
  it('retains taxID/TAXID/TAX_ID compatibility and first credential-subject projection', async () => {
    const { readRepresentativeOrganizationIdentifier, matchesTenantLegalIdentifier } = await loadHelpers();
    const tax = { type: 'TAX', value: identifier.value };
    expect(readRepresentativeOrganizationIdentifier({credentialSubject:[{memberOf:{taxID:identifier.value}},credential.credentialSubject]})).toEqual(tax);
    expect(matchesTenantLegalIdentifier(tax,{type:'tax_id',value:identifier.value})).toBe(true);
    expect(matchesTenantLegalIdentifier(tax,{type:'taxid',value:identifier.value})).toBe(true);
  });
  it('rejects missing bindings, crossed identifier types and values with different punctuation', async () => {
    const { readRepresentativeOrganizationIdentifier, matchesTenantLegalIdentifier } = await loadHelpers();
    expect(readRepresentativeOrganizationIdentifier({credentialSubject:{hasOccupation:{identifier:'RESPRSN'}}})).toBeUndefined();
    expect(matchesTenantLegalIdentifier(undefined,identifier)).toBe(false);
    expect(matchesTenantLegalIdentifier(identifier,{...identifier,type:'TAX'})).toBe(false);
    expect(matchesTenantLegalIdentifier(identifier,{...identifier,value:`${identifier.value}-`})).toBe(false);
  });
});
