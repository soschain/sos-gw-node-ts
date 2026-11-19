// Flow contract: a controller's JSON:API snapshot is visible only after the entire tenant catalogue is validated and written.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { JobRequest } from 'sos-data-utils-ts/confidential-job';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';
import { GatewaySector } from 'sos-data-utils-ts/gateway-sector-contract';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { PublicOfferingCatalogManager } from '../../../managers/PublicOfferingCatalogManager';
import { isRequestValid } from '../../../utils/request-validator';
import { initializeTenantServicesConfig } from '../../../utils/services';

const controller = 'did:web:controller.example';
const offering = {
  id: 'tracker', type: 'Product', attributes: {
    category: 'devices', name: 'Example tracker', description: 'A monitoring device',
    manufacturer: { id: 'designer', name: 'Device designer' },
    offers: [{ id: 'offer-es', seller: { id: 'seller', name: 'Retail seller' }, eligibleRegions: [{ country: 'ES', regions: [] }],
      deliveryCountries: ['ES'], operationCountries: [], supportCountries: [], url: 'https://seller.example/product' }],
  },
};

function job(data: unknown[], tenantId = 'clinic', actor = controller, jurisdiction = 'CA-BC') {
  return { tenantId, jurisdiction, sector: 'animal-care', section: 'organization', format: 'org.schema',
    resourceType: 'Catalog', action: '_publish', content: { thid: 'catalog-thread', iss: actor, body: { data } } } as JobRequest;
}

describe('PublicOfferingCatalogManager', () => {
  it.each([DataspaceSectors.AnimalCare, GatewaySector.ANTIFRAUD])('advertises the Schema.org publication route for %s, and keeps DCAT operations separate', sector => {
    const services = initializeTenantServicesConfig(String(sector) as GatewaySector);
    const request = { sector, section: 'organization', resourceType: 'Catalog', action: '_publish' };
    expect(isRequestValid(services, { ...request, format: 'org.schema' })).toBe(true);
    expect(isRequestValid(services, { ...request, format: 'org.w3.dcat' })).toBe(false);
    expect(isRequestValid(services, { ...request, action: '_upsert', format: 'org.schema' })).toBe(true);
  });

  it('replaces only the admitted tenant snapshot and preserves it when a later update fails validation', async () => {
    const repository = new VaultMemRepository();
    const put = jest.spyOn(repository, 'put');
    const protectConfidentialData = jest.fn(async (doc: ConfidentialStorageDoc) => doc);
    let status = 'active';
    const manager = new PublicOfferingCatalogManager({
      repository, protection: { protectConfidentialData, async unprotectConfidentialData<T>(doc: ConfidentialStorageDoc) { return doc.content as T; } },
      tenantManager: {
        tenantExists: async () => true,
        getTenantJurisdiction: async () => 'CA-BC',
        getCollectionName: async vaultId => `physical-${vaultId}`,
        getTenant: async vaultId => ({ didDocument: { id: `did:web:${vaultId}.example`, controller: [controller] },
          claims: { [SchemaOrgOrganizationClaim.LegalName]: 'Admitted organisation' }, meta: { tenantAuthorization: { status } } }),
      },
    });
    const first = await manager.process(job([offering]));
    expect(first.body).toMatchObject({ total: 1 });
    expect(put).toHaveBeenCalledTimes(1);
    const original = await manager.read('animal-care_clinic');
    expect(original).toEqual([expect.objectContaining({
      id: 'tracker', publisher: { id: 'did:web:animal-care_clinic.example', name: 'Admitted organisation' },
      manufacturer: offering.attributes.manufacturer, offers: offering.attributes.offers, demo: false,
    })]);
    const foreignPublisher = { ...offering, id: 'other', attributes: { ...offering.attributes, publisher: { id: 'foreign', name: 'Foreign' } } };
    await expect(manager.process(job([offering, foreignPublisher]))).rejects.toThrow(/catalogue submission/i);
    await expect(manager.process(job([offering], 'clinic', 'did:web:outsider.example'))).rejects.toThrow(/controller/i);
    await expect(manager.process(job([offering], 'clinic', controller, 'CA-ON'))).rejects.toThrow(/jurisdiction/i);
    expect(put).toHaveBeenCalledTimes(1);
    expect(await manager.read('animal-care_clinic')).toEqual(original);
    expect(await manager.read('animal-care_another')).toEqual([]);

    const replacement = { ...offering, id: 'updated', attributes: { ...offering.attributes, name: 'Updated tracker' } };
    status = 'suspended';
    await expect(manager.process(job([replacement]))).rejects.toThrow(/authorization is suspended/i);
    expect(await manager.read('animal-care_clinic')).toEqual(original);
    status = 'active';
    put.mockResolvedValueOnce(false);
    await expect(manager.process(job([replacement]))).rejects.toThrow(/could not be persisted/i);
    expect(await manager.read('animal-care_clinic')).toEqual(original);
    await manager.process(job([replacement]));
    expect(protectConfidentialData).toHaveBeenCalledTimes(3);
    expect(await manager.read('animal-care_clinic')).toEqual([expect.objectContaining({id: 'updated'})]);

    await expect(manager.process({ ...job([offering, replacement]), action: '_upsert' })).rejects.toThrow(/exactly one/i);
    await Promise.all([manager.process({ ...job([offering]), action: '_upsert' }), manager.process({
      ...job([{ ...replacement, attributes: { ...replacement.attributes, name: 'Edited manually' } }]), action: '_upsert',
    })]);
    expect(await manager.read('animal-care_clinic')).toEqual([
      expect.objectContaining({ id: 'updated', name: 'Edited manually' }), expect.objectContaining({ id: 'tracker' }),
    ]);
  });
});
