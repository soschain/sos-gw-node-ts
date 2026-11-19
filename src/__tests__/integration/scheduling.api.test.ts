// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import { resolveHostPhysicalCollectionName } from '../../config/storage-layout';
// Flow contract: an authenticated clinic actor writes and searches claims-first scheduling and public directory resources through the real asynchronous GW VET HTTP boundary.
import { afterEach, expect, it, jest } from '@jest/globals';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import {
  buildCohortCommunicationRequestFlatEntry,
  buildEncounterCareJourneyFlatGraph,
  buildServiceRequestFlatEntry,
  buildServiceRequestTriageTaskFlatEntry,
} from 'fhir-data-utils-ts';
import { HealthcareServiceClaim } from 'fhir-data-utils-ts/claims';
import type { GatewaySector } from 'sos-data-utils-ts/gateway-sector-contract';
import { AppointmentResponseStatuses, buildAppointmentResource, buildAppointmentResponseResource, buildLocationResource, expandAvailability, normalizeSchedulingFlatClaimsResource } from 'sos-data-utils-ts/scheduling';
import { buildOrganizationScopedResourceUrn } from 'sos-data-utils-ts/organization-scoped-resource-identity';
import { REPOSITORY_SAFE_EXAMPLES } from 'sos-data-utils-ts/repository-privacy';
import { buildGatewayDataspaceCatalogArtifactPath, buildGatewayDataspaceCatalogRequestPath, buildGatewayDataspaceOfferingCatalogPath } from 'sos-data-utils-ts/gateway-dataspace-routing';
import { buildDepartmentDirectoryResource, buildPlaceDirectoryResource, buildProductDirectoryResource, buildServiceDirectoryResource, normalizeDirectoryFlatClaimsResource } from 'sos-data-utils-ts/place-service-directory';
import { buildHealthDcatDataService, buildHealthDcatDataset, buildHealthDcatDistribution, buildResearchStudyDatasetPublication, updateHealthDcatCatalogRecordStatus } from 'sos-data-utils-ts/health-dcat';
import { buildPractitionerRoleReferenceFromAssignmentIdentifier, buildResearchStudyProvenanceResource } from 'sos-data-utils-ts/provenance';
import { startServer, resetServerConfig } from '../../server';
import { getEnvSectionId } from '../../utils/section-env';
import { initializeTenantServicesConfig } from '../../utils/services';
import { generateTenantCollectionNameFromClaims, getTenantVaultId } from '../../utils/tenant';
import { testPayloadCreateTenant1 } from '../data/end-to-end.data';
import { PUBLIC_OFFERING_EXAMPLE } from '../data/example-payloads';
import { configureAuthenticatedTestActor } from './helpers/authenticated-test-actor';
import { invokeExpress } from './helpers/invokeExpress';

const tenantId = 'veterinary-clinic';
const sector = 'animal-care';
const jurisdiction = 'CA-BC';

const schedulingClaimsProjection = (resource: Readonly<{ resourceType: string; id: string; meta?: unknown }>) =>
  normalizeSchedulingFlatClaimsResource({ resourceType: resource.resourceType, id: resource.id, meta: resource.meta });

afterEach(() => resetServerConfig());

it('uses the configured HTTPS gateway identity for public catalogue links behind the ingress', async () => {
  const publicOrigin = new URL(REPOSITORY_SAFE_EXAMPLES.httpsBaseUrl).origin;
  const environment = jest.replaceProperty(process, 'env', { ...process.env, HOST_PUBLIC_URL: publicOrigin, HOST_EXTERNAL_DOMAIN: '' });
  try {
    configureEnvironment();
    const authenticatedActor = await configureAuthenticatedTestActor();
    resetServerConfig();
    const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
    try {
      await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
      const scope = { tenantId, jurisdiction, version: 'v1', sector };
      const reply = await invokeExpress(app, { method: 'GET', url: buildGatewayDataspaceCatalogArtifactPath(scope) });
      expect(reply.status).toBe(200);
      expect(new URL(JSON.parse(reply.text)['@id']).origin).toBe(publicOrigin);
    } finally { queueAdapter.stop(); }
  } finally { environment.restore(); }
});

it('publishes a territorial CRM catalogue and individual offerings through the authenticated queue', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor();
  resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const scope = { tenantId, jurisdiction, version: 'v1', sector };
    const feed = buildGatewayDataspaceOfferingCatalogPath(scope);
    const safe = REPOSITORY_SAFE_EXAMPLES;
    const product = PUBLIC_OFFERING_EXAMPLE;
    const publicRead = () => invokeExpress(app, { method: 'GET', url: feed });
    const catalogRead = () => invokeExpress(app, { method: 'GET', url: buildGatewayDataspaceCatalogArtifactPath(scope) });
    const empty = await publicRead();
    expect(empty.status).toBe(200);
    expect(JSON.parse(empty.text)).toEqual([]);
    const unpublishedCatalog = await catalogRead();
    expect(unpublishedCatalog.status).toBe(200);
    expect(unpublishedCatalog.text).not.toContain(feed);
    const published = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid,
      'Catalog', '_publish', 'publish-territorial-catalogue', { jsonapi: { version: '1.1' }, data: [product] }, 'org.schema');
    expect(published).toEqual({ total: 1 });
    const result = await publicRead();
    expect(result.status).toBe(200);
    expect(JSON.parse(result.text)).toEqual([expect.objectContaining({ id: product.id, type: product.type,
      publisher: expect.objectContaining({ id: (await tenantManager.getDidDocument(getTenantVaultId(sector, tenantId)))?.id }),
      offers: product.attributes.offers, demo: false })]);
    const publishedCatalog = await catalogRead();
    expect(publishedCatalog.status).toBe(200);
    const dcat = JSON.parse(publishedCatalog.text);
    expect(dcat['@context']['dcat:endpointURL']).toEqual({ '@type': '@id' });
    const offeringService = dcat['dcat:service'].find((node: Record<string, string>) => node['dcat:endpointURL']?.endsWith(feed));
    expect(offeringService).toMatchObject({ '@type': 'dcat:DataService',
      'dcterms:publisher': { '@id': (await tenantManager.getDidDocument(getTenantVaultId(sector, tenantId)))?.id },
    });
    expect(new URL(offeringService['dcat:endpointURL']).pathname).toBe(feed);
    expect(publishedCatalog.text).not.toContain(product.attributes.name);
    const dcatRequest = (filters: object) => invokeExpress(app, { method: 'POST', url: buildGatewayDataspaceCatalogRequestPath(scope),
      headers: { 'content-type': 'application/json' }, body: { filters } });
    expect(JSON.parse((await dcatRequest({})).text)['dcat:service']).toContainEqual(offeringService);
    const filteredCatalog = await dcatRequest({ sector: 'health-care' });
    expect(filteredCatalog.status).toBe(200);
    expect(filteredCatalog.text).not.toContain(feed);
    const collection = await tenantManager.getCollectionName(getTenantVaultId(sector, tenantId));
    const record = await vaultRepository.get<any>(collection!, 'current', 'public-offering-catalog');
    expect(record?.jwe).toBeDefined();
    expect(record?.content).toBeUndefined();
    const manualProduct = { ...product, id: 'individual-tracker', attributes: { ...product.attributes, name: 'First manual entry' } };
    const publishOne = async (entry: typeof product, thid: string) => submitAndPoll(app, authenticatedActor.authorizationHeader,
      authenticatedActor.actorDid, 'Catalog', '_upsert', thid, { data: entry }, 'org.schema');
    expect(await publishOne(manualProduct, 'publish-individual-tracker')).toEqual({ total: 1 });
    expect(await publishOne({ ...manualProduct, attributes: { ...manualProduct.attributes, name: 'Updated manual entry' } }, 'update-individual-tracker')).toEqual({ total: 1 });
    expect(JSON.parse((await publicRead()).text)).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: product.id }), expect.objectContaining({ id: manualProduct.id, name: 'Updated manual entry' }),
    ]));
    expect(JSON.parse((await publicRead()).text)).toHaveLength(2);
    const plan = { name: 'Preventive care', currency: 'EUR', monthly: '9.95', annually: '99.00', features: ['Consultation'] };
    const service = { id: 'consultation', type: 'Service', attributes: {
      category: 'healthcare-services', name: 'Example consultation', description: 'Preventive care', images: [safe.httpsBaseUrl],
      offers: [{ ...product.attributes.offers[0]!, plans: [plan] }],
    } };
    expect(await publishOne(service, 'publish-individual-service')).toEqual({ total: 1 });
    const replacement = { ...product, id: 'replacement-product' };
    await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid,
      'Catalog', '_publish', 'replace-crm-snapshot', { data: [replacement] }, 'org.schema');
    const combined = JSON.parse((await publicRead()).text);
    expect(combined.map((item: { id: string }) => item.id).sort()).toEqual([manualProduct.id, replacement.id, service.id].sort());
    expect(combined.find((item: { id: string }) => item.id === service.id)).toMatchObject({ type: 'Service',
      images: [safe.httpsBaseUrl], offers: [expect.objectContaining({ plans: [plan] })] });
    const mismatched = await invokeExpress(app, { method: 'GET', url: buildGatewayDataspaceOfferingCatalogPath({ ...scope, jurisdiction: safe.secondaryCountryIso2 }) });
    expect(mismatched.status).toBe(404);
  } finally { queueAdapter.stop(); }
});

it('persists Location and Slot as encrypted flat claims and returns indexed search matches', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor();
  resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    const hostClaims = {
      [SchemaOrgOrganizationClaim.AddressCountry]: process.env.ORG_HOST_JURISDICTION,
      [SchemaOrgOrganizationClaim.IdentifierType]: process.env.ORG_HOST_ID_TYPE,
      [SchemaOrgOrganizationClaim.IdentifierValue]: process.env.ORG_HOST_ID_VALUE,
      [SchemaOrgServiceClaim.Category]: 'system',
    };
    const hostCollection = resolveHostPhysicalCollectionName();
    const tenantClaims = {
      ...(testPayloadCreateTenant1.body.data[0].resource.meta.claims as any),
      [SchemaOrgOrganizationClaim.AlternateName]: tenantId,
      [SchemaOrgOrganizationClaim.AddressCountry]: 'CA',
      [SchemaOrgOrganizationClaim.AddressRegion]: jurisdiction,
      [SchemaOrgServiceClaim.Category]: sector,
    };
    const tenantVaultId = getTenantVaultId(sector, tenantId);
    await kmsService.provisionKeys(tenantVaultId);
    const secureTenant = await kmsService.protectConfidentialData({ id: tenantVaultId, status: 'active', sequence: 0, content: {
      claims: tenantClaims,
      didConfig: { service: initializeTenantServicesConfig(sector as GatewaySector) },
      didDocument: { '@context': 'https://www.w3.org/ns/did/v1', id: 'did:web:veterinary-clinic.example', controller: [authenticatedActor.actorDid] },
    } } as any, 'host');
    await vaultRepository.put(hostCollection, [secureTenant as any], getEnvSectionId('tenants'));
    await tenantManager.getTenant(tenantVaultId);

    const location = normalizeSchedulingFlatClaimsResource(buildLocationResource({
      id: 'clinic-main', organizationReference: 'Organization/veterinary-clinic', name: 'Main room', latitude: 49.2, longitude: -123.1,
    }));
    const organizationResources = REPOSITORY_SAFE_EXAMPLES.organizationScopedResources;
    const departmentUrn = buildOrganizationScopedResourceUrn({
      parentUrn: organizationResources.organizationUrn,
      kind: 'department',
      resourceUuid: organizationResources.departmentUuid,
    });
    const serviceUrn = buildOrganizationScopedResourceUrn({
      parentUrn: departmentUrn,
      kind: 'service',
      resourceUuid: organizationResources.serviceUuid,
    });
    const scheduleUrn = buildOrganizationScopedResourceUrn({
      parentUrn: serviceUrn,
      kind: 'schedule',
      resourceUuid: organizationResources.scheduleUuid,
    });
    const slot = normalizeSchedulingFlatClaimsResource(expandAvailability({
      scheduleUrnsByLocation: { 'Location/clinic-main': scheduleUrn },
      healthcareServiceReference: 'HealthcareService/veterinary-care',
      serviceType: 'http://terminology.hl7.org/CodeSystem/service-type|1',
      resourceActorReferencesByLocation: { 'Location/clinic-main': ['Location/clinic-main'] },
      startDate: '2026-09-18', endDate: '2026-09-18', timeZone: 'UTC', slotMinutes: 30,
      periods: [{ daysOfWeek: [5], startTime: '16:00', endTime: '16:30', locationReferences: ['Location/clinic-main'] }], exceptions: [],
    })[0].resource);
    for (const resource of [location, slot]) {
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, resource.resourceType, '_batch', `write-${resource.resourceType}`, { data: [{ request: { method: 'POST' }, resource }] });
      expect(written.data[0].response.status).toBe('201');
      const searchName = resource.resourceType === 'Location' ? 'Location.status' : 'Slot.status';
      const found = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, resource.resourceType, '_search', `search-${resource.resourceType}`, { data: [{ resource: { resourceType: resource.resourceType, id: 'search', meta: { claims: { [searchName]: resource.meta.claims[searchName] } } } }] });
      expect(found.data[0].resource).toEqual(resource);
    }
    const physicalCollection = generateTenantCollectionNameFromClaims(tenantClaims);
    const records = await vaultRepository.listContainersInSection<any>(physicalCollection, 'slots');
    expect(records[0].jwe).toBeDefined();
    expect(records[0].content).toBeUndefined();
  } finally { queueAdapter.stop(); }
});

it('searches clinic AppointmentResponses inclusively between dates across different user actors', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const inside = schedulingClaimsProjection(buildAppointmentResponseResource({
      id: 'response-inside', appointmentReference: 'Appointment/a-1', actorReference: 'Patient/user-one',
      participantStatus: AppointmentResponseStatuses.Accepted, respondedAt: '2026-09-09T18:00:00.000Z',
    }));
    const outside = schedulingClaimsProjection(buildAppointmentResponseResource({
      id: 'response-outside', appointmentReference: 'Appointment/a-2', actorReference: 'Patient/user-two',
      participantStatus: AppointmentResponseStatuses.Declined, respondedAt: '2026-10-01T00:00:00.000Z',
    }));
    for (const resource of [inside, outside]) {
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'AppointmentResponse', '_batch', `write-${resource.id}`, { data: [{ request: { method: 'POST' }, resource }] });
      expect(written.data[0].response.status).toBe('201');
    }
    const found = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'AppointmentResponse', '_search', 'search-response-period', { data: [{ resource: { resourceType: 'AppointmentResponse', id: 'search', meta: { claims: {
      'AppointmentResponse._lastUpdated': ['ge2026-09-01T00:00:00.000Z', 'le2026-09-30T23:59:59.999Z'],
    } } } }] });
    expect(found.data.map((entry: any) => entry.resource.id)).toEqual(['response-inside']);
  } finally { queueAdapter.stop(); }
});

it('searches imported clinic Appointments by the standard inclusive date parameter', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const appointments = [
      buildAppointmentResource({
        id: 'appointment-inside', status: 'booked', start: '2026-09-18T16:00:00.000Z', end: '2026-09-18T16:30:00.000Z',
        slotReferences: ['Slot/inside'], actorReferences: ['Animal/animal-one'], locationReference: 'Location/clinic-main',
      }),
      buildAppointmentResource({
        id: 'appointment-outside', status: 'booked', start: '2026-10-18T16:00:00.000Z', end: '2026-10-18T16:30:00.000Z',
        slotReferences: ['Slot/outside'], actorReferences: ['Animal/animal-one'], locationReference: 'Location/clinic-main',
      }),
    ].map(schedulingClaimsProjection);
    for (const resource of appointments) {
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Appointment', '_batch', `write-${resource.id}`, { data: [{ request: { method: 'POST' }, resource }] });
      expect(written.data[0].response.status).toBe('201');
    }

    const found = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Appointment', '_search', 'search-appointment-period', { data: [{ resource: { resourceType: 'Appointment', id: 'search', meta: { claims: {
      'Appointment.date': ['ge2026-09-01T00:00:00.000Z', 'le2026-09-30T23:59:59.999Z'],
    } } } }] });

    expect(found.data.map((entry: any) => entry.resource.id)).toEqual(['appointment-inside']);
  } finally { queueAdapter.stop(); }
});

it('persists and searches claims-first Encounter, ServiceRequest, Task and CommunicationRequest through the real HTTP worker boundary', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const encounter = buildEncounterCareJourneyFlatGraph({ parent: {
      entryId: 'encounter-one', identifier: 'urn:uuid:encounter-one', status: 'planned',
      subjectReference: 'Animal/animal-one', appointmentReference: 'Appointment/appointment-one',
      serviceProviderReference: 'Organization/veterinary-clinic', periodStart: '2026-09-26T18:00:00.000Z',
      locationReference: 'Location/admission-one',
    } })[0];
    const serviceRequest = buildServiceRequestFlatEntry({
      entryId: 'service-request-one', identifier: 'urn:uuid:service-request-one', status: 'active', intent: 'order', priority: 'stat',
      code: { system: 'http://snomed.info/sct', code: '225358003' }, subjectReference: 'Animal/animal-one',
      requesterReference: 'RelatedPerson/controller-one', performerReferences: ['HealthcareService/emergency-one'],
      authoredAt: '2026-09-26T18:01:00.000Z',
    });
    const task = buildServiceRequestTriageTaskFlatEntry({
      entryId: 'triage-task-one', identifier: 'urn:uuid:triage-task-one', serviceRequestReference: serviceRequest.reference,
      subjectReference: 'Animal/animal-one', requesterReference: 'RelatedPerson/controller-one', ownerReference: 'Group/dispatch-one',
      authoredAt: '2026-09-26T18:01:00.000Z',
    });
    const communicationRequest = buildCohortCommunicationRequestFlatEntry({
      entryId: 'communication-request-one', identifier: 'urn:uuid:communication-request-one', status: 'active', priority: 'routine',
      category: { system: 'http://terminology.hl7.org/CodeSystem/communication-category', code: 'notification' },
      subjectReference: 'Group/cohort-one', requesterReference: 'Organization/veterinary-clinic',
      authoredAt: '2026-09-26T18:02:00.000Z', reasonReferences: ['ResearchStudy/study-one'],
    });
    for (const entry of [encounter, serviceRequest, task, communicationRequest]) {
      const resource = { resourceType: entry.resourceType, id: entry.entryId, meta: { claims: entry.claims } };
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, entry.resourceType, '_batch', `write-${entry.entryId}`, {
        data: [{ request: { method: 'POST', url: entry.reference }, resource }],
      }, 'org.hl7.fhir.r5');
      expect(written.data[0].response.status).toBe('201');
      const identifierClaim = `${entry.resourceType}.identifier`;
      const found = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, entry.resourceType, '_search', `search-${entry.entryId}`, {
        data: [{ resource: { resourceType: entry.resourceType, id: 'search', meta: { claims: { [identifierClaim]: entry.claims[identifierClaim] } } } }],
      }, 'org.hl7.fhir.r5');
      const versionClaim = `${entry.resourceType}.meta.versionId`;
      expect(found.data[0].resource).toEqual({
        resourceType: entry.resourceType,
        id: entry.entryId,
        meta: { claims: expect.objectContaining({
          [identifierClaim]: [entry.claims[identifierClaim]],
          [versionClaim]: [expect.stringMatching(/^z/)],
        }) },
      });
      if (entry.resourceType === 'Task') {
        const currentVersion = found.data[0].resource.meta.claims[versionClaim][0];
        const acceptedTask = {
          ...found.data[0].resource,
          meta: { claims: {
            ...found.data[0].resource.meta.claims,
            'Task.status': 'accepted',
            'Task.owner': 'PractitionerRole/responder-one',
            'Task.last-modified': '2026-09-26T18:03:00.000Z',
          } },
        };
        const updated = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Task', '_batch', 'update-triage-task', {
          data: [{ request: { method: 'PUT', url: entry.reference, ifMatch: `W/"${currentVersion}"` }, resource: acceptedTask }],
        }, 'org.hl7.fhir.r5');
        expect(updated.data[0].response).toMatchObject({ status: '200', etag: expect.stringMatching(/^W\/"z.+"$/) });
        const stale = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Task', '_batch', 'reject-stale-triage-task', {
          data: [{ request: { method: 'PUT', url: entry.reference, ifMatch: `W/"${currentVersion}"` }, resource: acceptedTask }],
        }, 'org.hl7.fhir.r5');
        expect(stale.data[0].response.status).toBe('412');
      }
    }
  } finally { queueAdapter.stop(); }
});

it('persists and searches the clinic department Organization, Place, offered Service, and insurance Product through schema.org routes', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const department = normalizeDirectoryFlatClaimsResource(buildDepartmentDirectoryResource({
      id: 'companion-animal-care', legalOrganizationIdentifier: 'did:web:veterinary-clinic.example',
      name: 'Companion animal care', placeIdentifiers: ['clinic-main'],
      specialty: { system: 'http://loinc.org', code: 'LP173421-1', display: 'Veterinary medicine' },
      logoUrl: 'https://clinic.example/logo.png',
    }));
    const place = normalizeDirectoryFlatClaimsResource(buildPlaceDirectoryResource({
      id: 'clinic-main', organizationIdentifier: 'did:web:veterinary-clinic.example', name: 'Main clinic',
      address: { addressCountry: 'CA', addressRegion: 'CA-BC', addressLocality: 'Coquitlam', postalCode: 'V3K 3V9', streetAddress: '435 North Road' },
      position: { latitude: 49.2446, longitude: -122.8926 }, photoUrl: 'https://clinic.example/main.webp',
      accessibilityFeatures: ['wheelchair-accessible'], openingHours: [{ daysOfWeek: ['Monday'], opens: '09:00', closes: '17:00' }],
    }));
    const service = normalizeDirectoryFlatClaimsResource(buildServiceDirectoryResource({
      id: 'vaccination', organizationIdentifier: 'companion-animal-care', placeIdentifiers: ['clinic-main'],
      name: 'Vaccination', serviceTypes: ['vaccination'], categories: ['animal-care'], areaServed: ['CA-BC'],
    }));
    const product = normalizeDirectoryFlatClaimsResource(buildProductDirectoryResource({
      id: 'wellness-plan', organizationIdentifier: 'did:web:veterinary-clinic.example', name: 'Animal wellness plan',
      productType: 'insurance-plan', categories: ['animal-insurance'], areaServed: ['CA-BC'],
      insurance: { status: 'active', coverageTypes: ['preventive-care'] },
    }));
    for (const resource of [department, place, service, product]) {
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, resource.resourceType, '_batch', `write-${resource.resourceType}`, { data: [{ request: { method: 'POST' }, resource }] }, 'org.schema');
      expect(written.data[0].response.status).toBe('201');
    }
    const foundPlaces = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Place', '_search', 'search-place-postal', { data: [{ resource: { resourceType: 'Place', id: 'search', meta: { claims: { 'org.schema.Place.address.postalCode': 'V3K 3V9' } } } }] }, 'org.schema');
    const foundDepartments = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Organization', '_search', 'search-department-type', { data: [{ resource: { resourceType: 'Organization', id: 'search', meta: { claims: { 'org.schema.Organization.additionalType': 'http://loinc.org/LP173421-1' } } } }] }, 'org.schema');
    const foundServices = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Service', '_search', 'search-service-type', { data: [{ resource: { resourceType: 'Service', id: 'search', meta: { claims: { 'org.schema.Service.serviceType': 'vaccination' } } } }] }, 'org.schema');
    const foundProducts = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Product', '_search', 'search-product-type', { data: [{ resource: { resourceType: 'Product', id: 'search', meta: { claims: { 'org.schema.Product.additionalType': 'insurance-plan' } } } }] }, 'org.schema');
    expect(foundDepartments.data.map((entry: any) => entry.resource.id)).toEqual(['companion-animal-care']);
    expect(foundPlaces.data.map((entry: any) => entry.resource.id)).toEqual(['clinic-main']);
    expect(foundServices.data.map((entry: any) => entry.resource.id)).toEqual(['vaccination']);
    expect(foundProducts.data.map((entry: any) => entry.resource.id)).toEqual(['wellness-plan']);
  } finally { queueAdapter.stop(); }
});

it('persists and searches one claims-first HealthcareService through the organization FHIR R5 route', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const healthcareService = {
      resourceType: 'HealthcareService', id: 'vaccination', meta: { claims: {
        [HealthcareServiceClaim.Identifier]: ['urn:uuid:vaccination'],
        [HealthcareServiceClaim.Active]: ['true'],
        [HealthcareServiceClaim.Organization]: ['Organization/preventive-care'],
        [HealthcareServiceClaim.Name]: ['Vaccination'],
        [HealthcareServiceClaim.Location]: ['Location/main-clinic'],
      } },
    };
    const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid,
      'HealthcareService', '_batch', 'write-healthcare-service', {
        data: [{ request: { method: 'POST', url: 'HealthcareService/vaccination' }, resource: healthcareService }],
      }, 'org.hl7.fhir.r5');
    expect(written.data[0].response.status).toBe('201');
    const found = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid,
      'HealthcareService', '_search', 'search-healthcare-service', {
        data: [{ resource: { resourceType: 'HealthcareService', id: 'search', meta: { claims: {
          [HealthcareServiceClaim.Identifier]: ['urn:uuid:vaccination'],
        } } } }],
      }, 'org.hl7.fhir.r5');
    expect(found.data[0].resource).toEqual(expect.objectContaining({ resourceType: 'HealthcareService', id: 'vaccination' }));
  } finally { queueAdapter.stop(); }
});

it('publishes and archives a ResearchStudy Dataset without deleting the study or changing data access rights', async () => {
  configureEnvironment();
  const authenticatedActor = await configureAuthenticatedTestActor(); resetServerConfig();
  const { app, queueAdapter, tenantManager, vaultRepository, kmsService } = await startServer({ listen: false });
  try {
    await provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService });
    const authority = { organizationIdentifier: 'did:web:veterinary-clinic.example', controllerIdentifier: authenticatedActor.actorDid, actingControllerIdentifier: authenticatedActor.actorDid };
    const professionalRole = buildPractitionerRoleReferenceFromAssignmentIdentifier('urn:uuid:123e4567-e89b-12d3-a456-426614174000');
    const provenance = buildResearchStudyProvenanceResource({ id: 'study-1-created', researchStudyReference: 'ResearchStudy/study-1', recorded: '2026-09-10T12:00:00.000Z', agents: [{ type: 'author', who: professionalRole }] });
    const writtenProvenance = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Provenance', '_batch', 'publish-study-provenance', { data: [{ request: { method: 'POST' }, resource: provenance }] }, 'org.hl7.fhir.r5');
    expect(writtenProvenance.data[0].response.status).toBe('201');
    const foundProvenance = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Provenance', '_search', 'search-study-provenance', { data: [{ resource: { resourceType: 'Provenance', id: 'search', meta: { claims: { 'Provenance.target': ['ResearchStudy/study-1'], 'Provenance.agent-author-who': [professionalRole] } } } }] }, 'org.hl7.fhir.r5');
    expect(foundProvenance.data[0].resource.id).toBe('study-1-created');
    const distribution = buildHealthDcatDistribution({ ...authority, id: 'distribution-study-1', title: 'Controlled study access', accessUrl: 'https://hdab.example/apply/study-1', format: 'http://publications.europa.eu/resource/authority/file-type/JSON', accessRights: 'NON_PUBLIC', healthDataAccessBodyIdentifier: 'Organization/hdab-1' });
    const dataset = buildHealthDcatDataset({ ...authority, sector: 'animal-research', id: 'dataset-study-1', title: 'Study cohort', description: 'Aggregated veterinary cohort', publisherRole: 'data-holder', dataHolderIdentifier: 'did:web:veterinary-clinic.example', sourceKind: 'spreadsheet-import', sourceReference: 'ResearchStudy/study-1', accessRights: 'NON_PUBLIC', anonymizationStatus: 'pseudonymized', healthCategory: ['animal-health'], healthDataAccessBodyIdentifier: 'Organization/hdab-1', structuredData: true, variableTableGroupIdentifiers: ['Group/study-1-variables'], distributionIdentifiers: [distribution.id], applicableLegislation: ['http://data.europa.eu/eli/reg/2025/327/oj'] });
    const publication = buildResearchStudyDatasetPublication({ ...authority, dataset, researchStudyIdentifier: 'ResearchStudy/study-1', provenanceReference: 'Provenance/study-1-created', catalogRecordIdentifier: 'record-study-1', status: 'published', modifiedAt: '2026-09-10T12:00:00.000Z' });
    const accessUrl = 'https://hdab.example/apply/study-1';
    const service = buildHealthDcatDataService({ ...authority, id: `${dataset.id}-access`, title: 'Controlled study access', endpointUrl: accessUrl, servesDatasetIdentifiers: [dataset.id], accessRights: 'NON_PUBLIC' });
    const scope = { tenantId, jurisdiction, version: 'v1', sector };
    const publicCatalog = async () => {
      const reply = await invokeExpress(app, { method: 'GET', url: buildGatewayDataspaceCatalogArtifactPath(scope) });
      expect(reply.status).toBe(200);
      return JSON.parse(reply.text);
    };
    for (const resource of [distribution, publication.dataset, service, publication.record]) {
      const written = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, resource.resourceType, '_batch', `publish-${resource.resourceType}`, { data: [{ request: { method: 'POST' }, resource }] }, 'org.w3.dcat');
      expect(written.data[0].response.status).toBe('201');
    }
    const published = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'CatalogRecord', '_search', 'search-published-record', { data: [{ resource: { resourceType: 'CatalogRecord', id: 'search', meta: { claims: { 'adms.status': 'published' } } } }] }, 'org.w3.dcat');
    expect(published.data.map((entry: any) => entry.resource.id)).toEqual(['record-study-1']);
    const catalog = await publicCatalog();
    const publicDataset = catalog['dcat:dataset'].find((item: Record<string, unknown>) => item['dcterms:identifier'] === dataset.id);
    expect(publicDataset).toMatchObject({ '@type': 'dcat:Dataset', 'dcterms:accessRights': 'NON_PUBLIC' });
    expect(catalog['dcat:service']).toContainEqual(expect.objectContaining({
      '@type': 'dcat:DataService', 'dcat:endpointURL': accessUrl,
      'dcat:servesDataset': [{ '@id': publicDataset['@id'] }],
    }));
    expect(JSON.stringify(catalog)).not.toContain(provenance.id);
    const publicDatasetPath = new URL(publicDataset['@id']).pathname;
    expect((await invokeExpress(app, { method: 'GET', url: publicDatasetPath })).status).toBe(200);
    const requestedCatalog = await invokeExpress(app, { method: 'POST', url: buildGatewayDataspaceCatalogRequestPath(scope) });
    expect(requestedCatalog.status).toBe(200);
    expect(JSON.parse(requestedCatalog.text)['dcat:dataset']).toContainEqual(publicDataset);
    const archivedRecord = updateHealthDcatCatalogRecordStatus({ ...authority, record: publication.record, status: 'archived', modifiedAt: '2026-09-10T13:00:00.000Z' });
    const archived = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'CatalogRecord', '_batch', 'archive-record', { data: [{ request: { method: 'PUT' }, resource: archivedRecord }] }, 'org.w3.dcat');
    expect(archived.data[0].response.status).toBe('200');
    expect(JSON.stringify(await publicCatalog())).not.toContain(dataset.id);
    expect((await invokeExpress(app, { method: 'GET', url: publicDatasetPath })).status).toBe(404);
    const noLongerPublished = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'CatalogRecord', '_search', 'search-after-archive', { data: [{ resource: { resourceType: 'CatalogRecord', id: 'search', meta: { claims: { 'adms.status': 'published' } } } }] }, 'org.w3.dcat');
    expect(noLongerPublished.data).toHaveLength(0);
    const storedDataset = await submitAndPoll(app, authenticatedActor.authorizationHeader, authenticatedActor.actorDid, 'Dataset', '_search', 'search-dataset-after-archive', { data: [{ resource: { resourceType: 'Dataset', id: 'search', meta: { claims: { 'dct.identifier': 'dataset-study-1' } } } }] }, 'org.w3.dcat');
    expect(storedDataset.data[0].resource.meta.claims['dct.accessRights']).toBe('NON_PUBLIC');
    expect(storedDataset.data[0].resource.meta.claims['prov.wasGeneratedBy']).toBe('ResearchStudy/study-1');
    expect(storedDataset.data[0].resource.meta.claims['dct.provenance']).toBe('Provenance/study-1-created');
  } finally { queueAdapter.stop(); }
});

function configureEnvironment() {
  process.env.NODE_ENV = 'test'; process.env.DB_PROVIDER = 'mem'; process.env.STORAGE_PROVIDER = 'mem'; process.env.QUEUE_PROVIDER = 'mem';
  process.env.SECTORS_ALLOWED = sector; process.env.ORG_HOST_LEGAL_NAME = 'Gateway Host Services'; process.env.ORG_HOST_JURISDICTION = 'CA';
  process.env.ORG_HOST_ID_TYPE = 'BN'; process.env.ORG_HOST_ID_VALUE = '700000001'; process.env.ORG_HOST_ADMIN_EMAIL = 'admin@host.example';
  process.env.ORG_HOST_ADMIN_UID = 'host-admin'; process.env.ORG_HOST_ADMIN_ROLE = 'ISCO-08|1111'; process.env.SECURITY_MODE = 'demo'; process.env.JSON_LEGACY = 'true';
}

async function provisionTenant({ authenticatedActor, tenantManager, vaultRepository, kmsService }: any) {
  const hostClaims = { [SchemaOrgOrganizationClaim.AddressCountry]: process.env.ORG_HOST_JURISDICTION, [SchemaOrgOrganizationClaim.IdentifierType]: process.env.ORG_HOST_ID_TYPE, [SchemaOrgOrganizationClaim.IdentifierValue]: process.env.ORG_HOST_ID_VALUE, [SchemaOrgServiceClaim.Category]: 'system' };
  const hostCollection = resolveHostPhysicalCollectionName();
  const tenantClaims = { ...(testPayloadCreateTenant1.body.data[0].resource.meta.claims as any), [SchemaOrgOrganizationClaim.AlternateName]: tenantId, [SchemaOrgOrganizationClaim.AddressCountry]: 'CA', [SchemaOrgOrganizationClaim.AddressRegion]: jurisdiction, [SchemaOrgServiceClaim.Category]: sector };
  const tenantVaultId = getTenantVaultId(sector, tenantId); await kmsService.provisionKeys(tenantVaultId);
  const secureTenant = await kmsService.protectConfidentialData({ id: tenantVaultId, status: 'active', sequence: 0, content: { claims: tenantClaims, didConfig: { service: initializeTenantServicesConfig(sector as GatewaySector) }, didDocument: { '@context': 'https://www.w3.org/ns/did/v1', id: 'did:web:veterinary-clinic.example', controller: [authenticatedActor.actorDid] } } } as any, 'host');
  await vaultRepository.put(hostCollection, [secureTenant as any], getEnvSectionId('tenants')); await tenantManager.getTenant(tenantVaultId);
}

async function submitAndPoll(app: any, authorization: string, issuer: string, resourceType: string, action: '_batch' | '_search' | '_publish' | '_upsert', thid: string, body: Record<string, unknown>, format = 'org.hl7.fhir.api') {
  const base = `/${tenantId}/cds-${jurisdiction}/v1/${sector}/organization/${format}/${resourceType}`;
  const submitted = await invokeExpress(app, { method: 'POST', url: `${base}/${action}`, headers: { 'content-type': 'application/json', authorization }, body: { thid, iss: issuer, body } });
  expect(submitted.status).toBe(202);
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const polled = await invokeExpress(app, { method: 'POST', url: `${base}/${action}-response`, headers: { 'content-type': 'application/json' }, body: { thid } });
    if (polled.status === 200) return JSON.parse(polled.text);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`${resourceType} async response timed out.`);
}
