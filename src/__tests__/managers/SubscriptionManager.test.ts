// Flow contract: a tenant registers an exact R5 topic/subscription, successful writes enter a durable outbox, and the BFF rest-hook receives notifications without widening scope.
import { SubscriptionManager } from '../../managers/SubscriptionManager';
import { VaultMemRepository } from '../../database/repositories/vault/vault.mem.repository';
import { mockKmsService } from '../mocks/kms.mock';
import { getEnvSectionId } from '../../utils/section-env';
import { getTenantVaultId } from '../../utils/tenant';

describe('SubscriptionManager', () => {
  it('persists an encrypted tenant/BFF FHIR R5 rest-hook Subscription', async () => {
    const vaultRepository = new VaultMemRepository();
    const vaultId = getTenantVaultId('health-care', 'tenant.example');
    await vaultRepository.createNewVault({ id: vaultId });
    const fetchFn = jest.fn(async () => ({ ok: true, status: 200 }));
    const manager = new SubscriptionManager({
      vaultRepository,
      kmsService: mockKmsService,
      tenantsCacheManager: { tenantExists: jest.fn(async () => true) } as any,
      fetchFn,
    });
    await manager.process({
      tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'health-care',
      section: 'entity', format: 'org.hl7.fhir.r5', resourceType: 'SubscriptionTopic', action: '_batch',
      content: { body: { entry: [{ resource: {
        resourceType: 'SubscriptionTopic', id: 'new-data-topic', status: 'active',
        url: 'https://profiles.example/SubscriptionTopic/new-data',
        resourceTrigger: [{ resource: 'Observation' }],
        canFilterBy: [{ resourceType: 'Observation', filterParameter: 'patient', comparator: ['eq'] }],
      } }] } },
    } as any);
    const result = await manager.process({
      tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'health-care',
      section: 'entity', format: 'org.hl7.fhir.r5', resourceType: 'Subscription', action: '_batch',
      content: { body: { resourceType: 'Bundle', type: 'batch', entry: [{ resource: {
        resourceType: 'Subscription', id: 'new-data', status: 'requested',
        topic: 'https://profiles.example/SubscriptionTopic/new-data',
        channelType: { code: 'rest-hook' }, endpoint: 'https://bff.example/fhir/subscriptions',
        filterBy: [{ resourceType: 'Observation', filterParameter: 'patient', value: 'Patient/123' }],
      } }] } },
    } as any);

    expect((result.body as any).data[0].response.status).toBe('201');
    const stored = await vaultRepository.get<any>(vaultId, 'new-data', getEnvSectionId('fhir-r5-subscriptions'));
    expect(stored?.jwe).toBeDefined();
    expect((result.body as any).data[0].resource.status).toBe('active');

    await manager.captureEvents({
      tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'health-care',
      section: 'individual', format: 'org.hl7.fhir.r5', resourceType: 'Observation', action: '_batch',
      content: { body: { entry: [{ resource: {
        resourceType: 'Observation', id: 'obs-1', subject: { reference: 'Patient/123' }, status: 'final',
      } }] } },
    } as any);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    const outbox = await vaultRepository.getContainersInSection<any>(vaultId, getEnvSectionId('fhir-r5-subscription-notifications'));
    expect(outbox).toHaveLength(1);
  });

  it('rejects an individual Subscription without an exact subject filter', async () => {
    const manager = new SubscriptionManager({
      vaultRepository: new VaultMemRepository(), kmsService: mockKmsService,
      tenantsCacheManager: { tenantExists: jest.fn(async () => true) } as any,
    });
    const result = await manager.process({
      tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'health-care',
      section: 'individual', format: 'org.hl7.fhir.r5', resourceType: 'Subscription', action: '_batch',
      content: { body: { entry: [{ resource: {
        resourceType: 'Subscription', id: 'too-broad', status: 'requested',
        topic: 'https://profiles.example/SubscriptionTopic/new-data',
        channelType: { code: 'rest-hook' }, endpoint: 'https://bff.example/events',
      } }] } },
    } as any);
    expect((result.body as any).data[0].response.status).toBe('400');
  });

  it('notifies the BFF when DataConv writes an export-completion Communication', async () => {
    const vaultRepository = new VaultMemRepository();
    const vaultId = getTenantVaultId('onehealth-research', 'tenant.example');
    await vaultRepository.createNewVault({ id: vaultId });
    const fetchFn = jest.fn(async () => ({ ok: true, status: 200 }));
    const manager = new SubscriptionManager({
      vaultRepository, kmsService: mockKmsService,
      tenantsCacheManager: { tenantExists: jest.fn(async () => true) } as any, fetchFn,
    });
    const base = { tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'onehealth-research', section: 'entity', format: 'org.hl7.fhir.r5', action: '_batch' };
    await manager.process({ ...base, resourceType: 'SubscriptionTopic', content: { body: { entry: [{ resource: {
      resourceType: 'SubscriptionTopic', id: 'research-export-ready', status: 'active',
      url: 'https://profiles.example/SubscriptionTopic/research-export-ready',
      resourceTrigger: [{ resource: 'Communication' }],
    } }] } } } as any);
    await manager.process({ ...base, resourceType: 'Subscription', content: { body: { entry: [{ resource: {
      resourceType: 'Subscription', id: 'research-export-ready', status: 'requested',
      topic: 'https://profiles.example/SubscriptionTopic/research-export-ready',
      channelType: { code: 'rest-hook' }, endpoint: 'https://bff.example/fhir/subscriptions',
    } }] } } } as any);

    await manager.captureEvents({ ...base, resourceType: 'Communication', content: { body: { entry: [{ resource: {
      resourceType: 'Communication', id: 'job-terminal-export-1', status: 'completed',
      subject: { reference: 'ResearchStudy/study-one' },
      payload: [{ contentReference: { reference: 'Task/export-1' } }],
    } }] } } } as any);

    expect(fetchFn).toHaveBeenCalledTimes(2);
    const outbox = await vaultRepository.getContainersInSection<any>(vaultId, getEnvSectionId('fhir-r5-subscription-notifications'));
    expect(outbox).toHaveLength(1);
  });
});

describe('SubscriptionManager independent R5 notification boundary', () => {
  async function fixture(topicFilter: Record<string, unknown>) {
    const vaultRepository = new VaultMemRepository();
    const vaultId = getTenantVaultId('health-care', 'tenant.example');
    await vaultRepository.createNewVault({ id: vaultId });
    const fetchFn = jest.fn(async () => ({ ok: true, status: 200 }));
    const manager = new SubscriptionManager({ vaultRepository, kmsService: mockKmsService,
      tenantsCacheManager: { tenantExists: jest.fn(async () => true) } as any, fetchFn });
    const base = { tenantId: 'tenant.example', jurisdiction: 'ES', sector: 'health-care', section: 'entity', format: 'org.hl7.fhir.r5', action: '_batch' };
    const topic = { resourceType: 'SubscriptionTopic', id: 'new-data', url: 'https://profiles.example/SubscriptionTopic/new-data',
      status: 'active', resourceTrigger: [{ resource: 'Communication' }], canFilterBy: [topicFilter] };
    const topicResult = await manager.process({ ...base, resourceType: 'SubscriptionTopic', content: { body: { entry: [{ resource: topic }] } } } as any);
    return { manager, vaultRepository, vaultId, fetchFn, base, topic, topicResult };
  }

  it.each(['legacy', 'canonical'])('projects %s topic filter metadata without rewriting persisted records', async variant => {
    const filter = { ...(variant === 'legacy' ? { resourceType: 'Communication' } : { resource: 'http://hl7.org/fhir/StructureDefinition/Communication' }),
      filterParameter: 'status', comparator: ['eq'] };
    const f = await fixture(filter);
    expect((f.topicResult.body as any).data[0].response.status).toBe('201');
    const subscriptionResult = await f.manager.process({ ...f.base, resourceType: 'Subscription', content: { body: { entry: [{ resource: {
      resourceType: 'Subscription', id: 'new-data', status: 'requested', topic: f.topic.url,
      filterBy: [{ resourceType: 'Communication', filterParameter: 'status', comparator: 'eq', value: 'completed' }],
      channelType: { code: 'rest-hook' }, endpoint: 'https://bff.example/events', content: 'full-resource',
    } }] } } } as any);
    expect((subscriptionResult.body as any).data[0].response.status).toBe('201');
    const resource = { resourceType: 'Communication', id: 'event-1', status: 'completed' };
    await f.manager.captureEvents({ ...f.base, resourceType: 'Communication', content: { body: { entry: [{ resource }] } } } as any);
    expect(f.fetchFn).toHaveBeenCalledTimes(2);
    const handshake = JSON.parse((f.fetchFn.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect(handshake.entry[0].fullUrl).toMatch(/^urn:uuid:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i);
    const notification = JSON.parse((f.fetchFn.mock.calls[1] as unknown as [string, RequestInit])[1].body as string);
    expect(notification.entry).toHaveLength(2);
    for (const entry of notification.entry) expect(entry.fullUrl).toMatch(/^urn:uuid:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i);
    expect(new Set(notification.entry.map((entry: any) => entry.fullUrl)).size).toBe(2);
    const status = notification.entry[0].resource;
    expect(status.eventsSinceSubscriptionStart).toBe('1');
    expect(status.notificationEvent[0].eventNumber).toBe('1');
    expect(status.notificationEvent[0].focus.reference).toBe(`${resource.resourceType}/${resource.id}`);
    expect(notification.entry[1].resource).toEqual(resource);
    const topics = await f.vaultRepository.getContainersInSection<any>(f.vaultId, getEnvSectionId('fhir-r5-subscription-topics'));
    expect(topics).toHaveLength(1);
    const stored = await mockKmsService.unprotectConfidentialData<any>(topics[0], f.vaultId);
    expect(stored.resource.canFilterBy).toEqual([filter]);
    expect(f.topic.canFilterBy).toEqual([filter]);
  });

  it('rejects contradictory legacy and canonical topic resource fields', async () => {
    const f = await fixture({ resource: 'Communication', resourceType: 'Observation', filterParameter: 'status', comparator: ['eq'] });
    expect((f.topicResult.body as any).data[0].response.status).toBe('400');
    const topics = await f.vaultRepository.getContainersInSection<any>(f.vaultId, getEnvSectionId('fhir-r5-subscription-topics'));
    expect(topics).toHaveLength(0);
  });

  it('does not deliver from a contradictory stored topic or silently rewrite it', async () => {
    const f = await fixture({ resourceType: 'Communication', filterParameter: 'status', comparator: ['eq'] });
    await f.manager.process({ ...f.base, resourceType: 'Subscription', content: { body: { entry: [{ resource: {
      resourceType: 'Subscription', id: 'new-data', status: 'requested', topic: f.topic.url,
      filterBy: [{ resourceType: 'Communication', filterParameter: 'status', comparator: 'eq', value: 'completed' }],
      channelType: { code: 'rest-hook' }, endpoint: 'https://bff.example/events', content: 'full-resource',
    } }] } } } as any);
    const section = getEnvSectionId('fhir-r5-subscription-topics');
    const original = (await f.vaultRepository.getContainersInSection<any>(f.vaultId, section))[0];
    const stored = await mockKmsService.unprotectConfidentialData<any>(original, f.vaultId);
    stored.resource.canFilterBy[0].resource = 'Observation';
    const contradictory = await mockKmsService.protectConfidentialData({
      id: original.id, status: original.status, sequence: Number(original.sequence) + 1, content: stored,
    } as any, f.vaultId);
    await f.vaultRepository.put(f.vaultId, [contradictory], section);
    const before = structuredClone(await f.vaultRepository.getContainersInSection<any>(f.vaultId, section));
    await f.manager.captureEvents({ ...f.base, resourceType: 'Communication', content: { body: { entry: [{ resource: {
      resourceType: 'Communication', id: 'event-1', status: 'completed',
    } }] } } } as any);
    expect(f.fetchFn).toHaveBeenCalledTimes(1);
    expect(await f.vaultRepository.getContainersInSection<any>(f.vaultId, section)).toEqual(before);
  });
});
