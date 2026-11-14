// Flow contract: independent identity and commerce claim catalogs preserve exact stored keys and authorization boundaries.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgOfferClaim, SchemaOrgOrderClaim, SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import {
  isConfiguredHostLegalPersonTenant,
  processHostOrderEntry,
} from '../../../managers/hosting/process-order-entry';

/** Flow contract: initial host-tenant finalization reuses the configured legal person and never submits a duplicate Fabric organization. */
describe('processHostOrderEntry active offer idempotency', () => {
  it('recognizes only the exact configured host legal identifier', () => {
    const claims = {
      [SchemaOrgOrganizationClaim.IdentifierType]: 'BN',
      [SchemaOrgOrganizationClaim.IdentifierValue]: '704457076',
    };
    expect(isConfiguredHostLegalPersonTenant(claims, {
      idType: 'BN', idValue: '704457076',
    })).toBe(true);
    expect(isConfiguredHostLegalPersonTenant(claims, {
      idType: 'BN', idValue: '000000000',
    })).toBe(false);
  });

  it('keeps the pending Offer authoritative when mandatory ledger registration fails', async () => {
    const offerId = 'urn:cds:CA-BC:v1:animal-care:product:org.schema:Offer:pending';
    const pendingClaims = {
      [SchemaOrgOfferClaim.Identifier]: offerId,
      [SchemaOrgOrganizationClaim.AlternateName]: '704457076',
      [SchemaOrgOrganizationClaim.AddressCountry]: 'US',
      [SchemaOrgOrganizationClaim.IdentifierType]: 'BN',
      [SchemaOrgOrganizationClaim.IdentifierValue]: '704457076',
      [SchemaOrgOrganizationClaim.LegalName]: 'Example Veterinary Organization',
      [SchemaOrgServiceClaim.Category]: 'animal-care',
    };
    const put = jest.fn(async () => true);
    const ledgerFailure = new Error('ledger endorsement timeout');

    await expect(processHostOrderEntry({
      entry: { resource: { resourceType: 'Order', meta: { claims: { [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId } } } } as any,
      vaultRepository: {
        query: jest.fn(async () => [{
          id: 'animal-care_704457076', status: 'pending',
          content: { status: 'pending', claims: pendingClaims, contained: [] },
        }]),
        createNewVault: jest.fn(async () => true),
        put,
      } as any,
      kmsService: {
        unprotectConfidentialData: jest.fn(async (doc: any) => doc.content),
        provisionKeys: jest.fn(async () => undefined),
        protectConfidentialData: jest.fn(async (doc: any) => doc),
      } as any,
      logger: { error: jest.fn() } as any,
      config: {
        namespace: 'gdc', networkMode: 'test-network',
        apiBaseUrl: 'https://host-vet.connecthealth.info', hostExternalDomain: 'host-vet.connecthealth.info',
        host: { jurisdiction: 'CA-BC' }, ledger: {},
      } as any,
      hostRuntime: { hostCollectionName: 'system_host' } as any,
      offerOrderService: { processLicenseOrderEntry: jest.fn() } as any,
      extractResources: jest.fn(() => ({
        organization: { id: 'urn:org:bn:704457076' }, service: { id: 'service-veterinary' },
      })) as any,
      extractContainedService: jest.fn(() => undefined),
      finalizeTenantConfig: jest.fn(async () => ({
        status: 'active', claims: pendingClaims, governanceVc: {}, selfDescriptionVc: {},
        didDocument: { id: 'did:web:host-vet.connecthealth.info:704457076:cds-US:v1:animal-care' },
      })) as any,
      isLedgerRegistrationEnabled: jest.fn(() => true),
      extractServiceEvidence: jest.fn(() => undefined),
      buildControllerEntityConfig: jest.fn() as any,
      storeControllerEntityConfig: jest.fn() as any,
      getCurrentUrnNetwork: jest.fn(() => 'test-network'),
      registerOrganizationOnLedger: jest.fn(async () => { throw ledgerFailure; }),
    })).rejects.toBe(ledgerFailure);

    expect(put).not.toHaveBeenCalled();
  });

  it('does not issue licenses or require another payment when replaying an accepted organization offer', async () => {
    const offerId = 'urn:cds:CA-BC:v1:animal-care:product:org.schema:Offer:existing';
    const response = await processHostOrderEntry({
      entry: { resource: { resourceType: 'Order', meta: { claims: { [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId } } } } as any,
      vaultRepository: {
        query: jest.fn(async () => [{
          status: 'active',
          content: {
            status: 'active',
            claims: {
              [SchemaOrgOfferClaim.Identifier]: offerId,
              [SchemaOrgOrganizationClaim.AlternateName]: '704457076',
              [SchemaOrgServiceClaim.Category]: 'animal-care',
            },
          },
        }]),
        put: jest.fn(),
      } as any,
      kmsService: { unprotectConfidentialData: jest.fn(async (doc: unknown) => (doc as any).content) } as any,
      logger: { error: jest.fn() } as any,
      config: {} as any,
      hostRuntime: { hostCollectionName: 'system_host' } as any,
      offerOrderService: { processLicenseOrderEntry: jest.fn() } as any,
      extractResources: jest.fn() as any,
      extractContainedService: jest.fn() as any,
      finalizeTenantConfig: jest.fn() as any,
      isLedgerRegistrationEnabled: jest.fn() as any,
      extractServiceEvidence: jest.fn() as any,
      buildControllerEntityConfig: jest.fn() as any,
      storeControllerEntityConfig: jest.fn() as any,
      getCurrentUrnNetwork: jest.fn() as any,
    });

    expect(response.response?.status).toBe('200');
    expect(response.resource?.meta?.claims?.[SchemaOrgOrderClaim.AcceptedOfferIdentifier]).toBe(offerId);
  });
});
