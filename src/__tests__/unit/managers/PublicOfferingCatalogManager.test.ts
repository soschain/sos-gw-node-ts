// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Controller edits preserve earlier versions, and withdrawal hides just the selected resource.
import { describe, expect, it, jest } from '@jest/globals';
import { createHash } from 'node:crypto';
import { readPublicOfferingSubmission } from 'antifraud-data-utils-ts/public-offering-catalog';
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
  it.each([DataspaceSectors.AnimalCare, DataspaceSectors.HealthTech, GatewaySector.ANTIFRAUD])('advertises the Schema.org publication route for %s, and keeps DCAT operations separate', sector => {
    const services = initializeTenantServicesConfig(String(sector) as GatewaySector);
    const request = { sector, section: 'organization', resourceType: 'Catalog', action: '_publish' };
    expect(isRequestValid(services, { ...request, format: 'org.schema' })).toBe(true);
    expect(isRequestValid(services, { ...request, format: 'org.w3.dcat' })).toBe(false);
    expect(isRequestValid(services, { ...request, action: '_upsert', format: 'org.schema' })).toBe(true);
    expect(isRequestValid(services, { ...request, action: '_unpublish', format: 'org.schema' })).toBe(true);
    expect(isRequestValid(services, { ...request, action: '_history', format: 'org.schema' })).toBe(true);
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
    expect(await manager.read('animal-care_clinic')).toEqual([expect.objectContaining({id: 'updated'})]);

    const service = {id:'support', type:'Service', attributes:{category:'animal-support', name:'Device support', description:'Device support', offers:offering.attributes.offers}};
    const edited = { ...replacement, attributes: { ...replacement.attributes, name: 'Edited in the review batch' } };
    const update: JobRequest = { ...job([offering, edited]), action: '_upsert' };
    await expect(manager.process({ ...job([offering, service]), action: '_upsert' })).rejects.toThrow(/one offering type/i);
    const writeCount = put.mock.calls.length;
    protectConfidentialData.mockRejectedValueOnce(new Error('Protection failed'));
    await expect(manager.process(update)).rejects.toThrow(/protection failed/i);
    expect(put).toHaveBeenCalledTimes(writeCount);
    expect(await manager.read('animal-care_clinic')).toEqual([expect.objectContaining({id:'updated', name:'Updated tracker'})]);

    expect((await manager.process(update)).body).toMatchObject({total:2});
    expect(put).toHaveBeenCalledTimes(writeCount+1);
    expect(put.mock.lastCall?.[1]).toHaveLength(4);
    expect(await manager.read('animal-care_clinic')).toEqual([
      expect.objectContaining({ id: 'updated', name: 'Edited in the review batch' }), expect.objectContaining({ id: 'tracker' }),
    ]);

    const legacy = readPublicOfferingSubmission({data:[offering,{ ...offering, id:'legacy-only' }]},
      {publisher:{id:'did:web:animal-care_clinic.example', name:'Admitted organisation'},sector:'animal-care',demo:false});
    await repository.put('physical-animal-care_clinic', legacy.map(item => ({
      id: createHash('sha256').update(item.id).digest('hex'), status:'active', sequence:1, content:{offerings:[item]},
    } as ConfidentialStorageDoc)), 'public-offering-entries');
    const overlappingService={...service,id:offering.id};
    const revisedTracker={...offering,attributes:{...offering.attributes,name:'Tracker revision'}};
    await manager.process({...job([overlappingService]),action:'_upsert'});
    await manager.process({...job([revisedTracker]),action:'_upsert'});
    const feed=await manager.read('animal-care_clinic');
    expect(feed.filter(item=>item.id===offering.id)).toEqual(expect.arrayContaining([
      expect.objectContaining({type:'Product',name:'Tracker revision'}),
      expect.objectContaining({type:'Service',name:'Device support'}),
    ]));
    expect(feed).toContainEqual(expect.objectContaining({id:'legacy-only',type:'Product'}));
    expect(feed).toHaveLength(4);
    const reference = { type: offering.type, id: offering.id };
    const historyJob: JobRequest = { ...job([reference]), action: '_history' };
    const before = (await manager.process(historyJob)).body as { versions: { versionId: string; offering?: { name: string } }[] };
    expect(before.versions).toEqual(expect.arrayContaining([
      expect.objectContaining({ versionId: expect.any(String), offering: expect.objectContaining({ name: offering.attributes.name }) }),
      expect.objectContaining({ versionId: expect.any(String), offering: expect.objectContaining({ name: revisedTracker.attributes.name }) }),
    ]));
    const withdrawal: JobRequest = { ...job([reference]), action: '_unpublish' };
    await expect(manager.process({ ...job([reference], 'clinic', 'did:web:outsider.example'), action: '_unpublish' })).rejects.toThrow(/controller/i);
    expect((await manager.process(withdrawal)).body).toEqual({ total: 1 });
    await manager.process(job([offering]));
    expect(await manager.read('animal-care_clinic')).not.toContainEqual(expect.objectContaining(reference));
    expect(await manager.read('animal-care_clinic')).toContainEqual(expect.objectContaining({ type: overlappingService.type, id: offering.id }));
    expect((await manager.process(historyJob)).body).toMatchObject({
      versions: expect.arrayContaining([...before.versions, expect.objectContaining({ status: 'withdrawn' })]),
    });
    await manager.process({ ...job([offering]), action: '_upsert' });
    expect(await manager.read('animal-care_clinic')).toContainEqual(expect.objectContaining(reference));
    const restored = (await manager.process(historyJob)).body as {
      versions: { versionId: string; contentHash: string; offering: { name: string } }[];
    };
    const sameTerms = restored.versions.filter(version => version.offering.name === offering.attributes.name);
    expect(new Set(sameTerms.map(version => version.versionId)).size).toBeGreaterThan(1);
    expect(new Set(sameTerms.map(version => version.contentHash)).size).toBe(1);
  });
});
