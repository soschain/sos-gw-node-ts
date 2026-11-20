import {
  ClaimsHealthDcatCatalogRecord,
  ClaimsHealthDcatDataset,
  ClaimsHealthDcatDataService,
  isHealthDcatCatalogRecordExternallyDiscoverable,
  normalizeHealthDcatResource,
  type HealthDcatCatalogRecordStatus,
  type HealthDcatResource,
} from 'sos-data-utils-ts/health-dcat';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import { EntityLifecycleStatus } from '../gdc-backend-utils-node/models/enums';
import { healthDcatSectionByResource } from '../managers/HealthDcatManager';

/** Projects only the public metadata of current tenant-published HealthDCAT records. */
export async function readPublishedHealthDcat(
  repository: IVaultRepository,
  kms: IKmsService,
  collection: string,
  vaultId: string,
  catalogUrl: string,
  publisherDid: string,
) {
  const status: HealthDcatCatalogRecordStatus = 'published';
  const [publishedStatus] = await kms.protectAttributesNameAndValue(
    [{ name: ClaimsHealthDcatCatalogRecord.status, value: status, type: 'string' }], vaultId,
  );
  const list = (type: HealthDcatResource['resourceType']) =>
    repository.listContainersInSection<ConfidentialStorageDoc>(collection, healthDcatSectionByResource[type]);
  const read = async (document: ConfidentialStorageDoc | undefined, type: HealthDcatResource['resourceType']) => {
    if (document?.status !== EntityLifecycleStatus.Active) return undefined;
    const content = await kms.unprotectConfidentialData<{ resource?: unknown }>(document, vaultId);
    try {
      const resource = normalizeHealthDcatResource(content?.resource);
      return resource.resourceType === type && resource.id === document.id ? resource : undefined;
    } catch {
      return undefined;
    }
  };

  const datasetIds = new Set<string>();
  if (publishedStatus) {
    for (const document of await list('CatalogRecord')) {
      if (!document.indexed?.attributes?.some(item => item.name === publishedStatus.name && item.value === publishedStatus.value)) continue;
      const record = await read(document, 'CatalogRecord');
      if (!record || !isHealthDcatCatalogRecordExternallyDiscoverable(record)) continue;
      const topic = record.meta.claims[ClaimsHealthDcatCatalogRecord.primaryTopic];
      if (typeof topic === 'string' && topic.startsWith('Dataset/')) datasetIds.add(topic.slice('Dataset/'.length));
    }
  }
  const datasets = [];
  const pointers = new Map<string, { '@id': string }>();
  const publisher = { '@id': publisherDid };
  for (const id of [...datasetIds].sort()) {
    const dataset = await read(await repository.get<ConfidentialStorageDoc>(
      collection, id, healthDcatSectionByResource.Dataset,
    ), 'Dataset');
    if (!dataset) continue;
    const claims = dataset.meta.claims;
    if (claims[ClaimsHealthDcatDataset.publisher] !== publisherDid) continue;
    const pointer = { '@id': `${catalogUrl}/datasets/${encodeURIComponent(`research:${id}`)}` };
    pointers.set(id, pointer);
    datasets.push({
      ...pointer, '@type': 'dcat:Dataset', 'dcterms:identifier': id,
      'dcterms:title': claims[ClaimsHealthDcatDataset.title],
      'dcterms:description': claims[ClaimsHealthDcatDataset.description],
      'dcterms:publisher': publisher, 'dcterms:accessRights': claims[ClaimsHealthDcatDataset.accessRights],
    });
  }
  const services = [];
  if (pointers.size) {
    for (const document of await list('DataService')) {
      const service = await read(document, 'DataService');
      if (!service) continue;
      const claims = service.meta.claims;
      if (claims[ClaimsHealthDcatDataService.publisher] !== publisherDid) continue;
      const references = claims[ClaimsHealthDcatDataService.servesDataset];
      const served = (Array.isArray(references) ? references : [references])
        .flatMap(id => pointers.get(String(id)) ?? []);
      const url = URL.parse(String(claims[ClaimsHealthDcatDataService.endpointUrl] ?? ''));
      if (!served.length || url?.protocol !== 'https:' || url.username || url.password) continue;
      services.push({
        '@id': `${catalogUrl}#data-service-${encodeURIComponent(service.id)}`,
        '@type': 'dcat:DataService', 'dcterms:title': claims[ClaimsHealthDcatDataService.title],
        'dcterms:publisher': publisher, 'dcterms:accessRights': claims[ClaimsHealthDcatDataService.accessRights],
        'dcat:endpointURL': url.href, 'dcat:servesDataset': served,
      });
    }
  }
  return { datasets, services };
}
