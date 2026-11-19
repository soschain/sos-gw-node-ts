// Flow contract: verified evidence and any required host admission decision precede a new licence Offer; existing-tenant re-registration preserves its separate binding path.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { processOrganizationVerificationTransaction } from '../../../managers/hosting/process-organization-verification';

describe('processOrganizationVerificationTransaction legacy re-registration', () => {
  it('uses the existing-tenant controller upsert and does not create a new Offer', async () => {
    const claims = {
      [SchemaOrgOrganizationClaim.AlternateName]: 'VATES-G00000000',
      [SchemaOrgServiceClaim.Category]: 'onehealth-research',
    };
    const representativeCredential = {
      id: 'urn:example:credential:historical-representative',
      issuer: 'did:web:ica.example.test',
      type: ['VerifiableCredential', 'LegalRepresentativeCredential'],
    };
    const createPendingTenantRegistrationFromClaims = jest.fn(async () => {
      throw new Error('must not create a second pending registration');
    });
    const reregisterExistingLegacyRepresentativeController = jest.fn(async (_input: unknown) => ({
      ...claims,
      [SchemaOrgOrganizationClaim.IdentifierReference]: 'urn:example:organization:existing',
    }));

    const response = await processOrganizationVerificationTransaction({
      job: {
        tenantId: 'host',
        jurisdiction: 'es',
        sector: 'network',
        action: '_transaction',
        content: {
          thid: 'transaction-thread-001',
          iss: 'did:web:historical-portal.example.test',
          meta: { jws: { protected: { kid: 'historical-portal-public-key' } } },
          body: { data: [{ resource: { meta: { claims }, verification: { resourceType: 'contract' } } }] },
        },
      } as any,
      issuerDid: 'did:web:gateway.example.test',
      config: { sectorsAllowed: ['onehealth-research'], namespace: 'cds-ES', networkMode: 'network' } as any,
      normalizeClaims: value => value,
      createPendingTenantRegistrationFromClaims,
      createOrganizationIssueClaimsFromClaims: jest.fn() as any,
      forwardOrganizationVerificationTransactionToIca: jest.fn(async () => ({ resourceType: 'Bundle' })),
      extractCredentialResourcesFromIcaPayload: jest.fn(() => [representativeCredential]),
      reregisterExistingLegacyRepresentativeController,
    });

    expect(reregisterExistingLegacyRepresentativeController).toHaveBeenCalledWith(expect.objectContaining({
      claims,
      credentials: [representativeCredential],
    }));
    expect(createPendingTenantRegistrationFromClaims).not.toHaveBeenCalled();
    expect((response.body.data[0].resource as any).next).toBeUndefined();
    expect((response.body.data[0].resource as any).meta.claims[SchemaOrgOrganizationClaim.IdentifierReference])
      .toBe('urn:example:organization:existing');
  });
});

describe('processOrganizationVerificationTransaction host admission', () => {
  it('requires approval before creating an Offer and does not treat verification as approval', async () => {
    const claims = {
      [SchemaOrgOrganizationClaim.AlternateName]: 'VATES-G00000000',
      [SchemaOrgServiceClaim.Category]: 'onehealth-research',
    };
    const evidence = { resourceType: 'Bundle' };
    const authorizeNewOffer = jest.fn(async (_input: unknown) => {
      throw new Error('review required');
    });
    const createPendingTenantRegistrationFromClaims = jest.fn(async () => claims);
    const deps = {
      job: {
        tenantId: 'host',
        jurisdiction: 'es',
        sector: 'network',
        action: '_transaction',
        content: { body: { data: [{ resource: { meta: { claims } } }] } },
      } as any,
      issuerDid: 'did:web:gateway.example.test',
      config: { sectorsAllowed: ['onehealth-research'], namespace: 'cds-ES', networkMode: 'network' } as any,
      normalizeClaims: (value: typeof claims) => value,
      createPendingTenantRegistrationFromClaims,
      createOrganizationIssueClaimsFromClaims: jest.fn() as any,
      forwardOrganizationVerificationTransactionToIca: jest.fn(async () => evidence),
      extractCredentialResourcesFromIcaPayload: jest.fn(() => []),
      authorizeNewOffer,
    };
    await expect(processOrganizationVerificationTransaction(deps as any)).rejects.toThrow('review required');
    expect(authorizeNewOffer).toHaveBeenCalledWith(expect.objectContaining({
      claims, evidence, network: 'network', sector: 'onehealth-research',
    }));
    expect(createPendingTenantRegistrationFromClaims).not.toHaveBeenCalled();
  });
});
