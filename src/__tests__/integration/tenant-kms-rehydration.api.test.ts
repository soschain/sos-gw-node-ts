// Flow contract: 1. Activate/order the tenant and purchase its seat. 2. Restart KMS over persisted vault records. 3. Read the current controller from that tenant's DID document and authenticate a genuinely signed OIDC principal for it. 4. Retain successful employee readback after restart and provisioning replay without changing the published encryption key. 5. Reject a verified foreign controller and leave the tenant's employee records unchanged. Production admission and custody checks remain enabled.
import { resolveHostPhysicalCollectionName } from '../../config/storage-layout';
/**
 * Flow contract: activate a tenant, purchase a professional seat through the
 * explicit Offer and host Order boundary, restart KMS, then prove that the
 * tenant can still create an employee with authoritative asynchronous readback.
 */
import * as express from 'express';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { AdapterCryptoSdkNode } from '../../gdc-backend-utils-node/adapters/node/crypto';
import { AsyncResponseStoreMem } from '../../adapters/async-response-store.mem';
import { QueueAdapterMem } from '../../adapters/queue-mem';
import { VaultMemRepository } from '../../database/repositories/vault/vault.mem.repository';
import { StorageMemAdapter } from '../../database/storage/mem.storage.adapter';
import { HostingManager } from '../../managers/HostingManager';
import { EmployeeManager } from '../../managers/EmployeeManager';
import { LicenseManager } from '../../managers/LicenseManager';
import { ManagerRegistry } from '../../managers/registry';
import { TenantsCacheManager } from '../../managers/TenantsCacheManager';
import { ConsoleLogger } from '../../loggers/ConsoleLogger';
import { createApiRouter } from '../../routes/api';
import { KmsService } from '../../services/KmsService';
import { InMemoryEnvelopeAdapter } from '../../services/kms-envelope-adapter';
import { VaultWrappedKeyRepository } from '../../services/wrapped-key-repository';
import { Worker } from '../../worker';
import type { IServerConfig } from '../../config';
import { GatewaySector } from 'sos-data-utils-ts/gateway-sector-contract';
import { generateTenantCollectionNameFromClaims } from '../../utils/tenant';
import { SchemaOrgOrganizationClaim, SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { invokeExpress } from './helpers/invokeExpress';
import { buildActivationPayload, pollJsonBody } from './helpers/story-flow';
import { ORGANIZATION_ORDER_REQUEST, EMPLOYEE_REGISTRATION_REQUEST } from '../data/example-payloads';
import { SchemaOrgOfferClaim, SchemaOrgOrderClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { IHostRuntime } from '../../managers/IHostRuntime';
import { testClaimsHostInitialization } from '../data/end-to-end.data';
import { buildLicensePurchaseEntry } from 'gdc-common-utils-ts';
import { HttpRequestMethods } from 'sos-data-utils-ts/bff-wire-contract';
import { getTenantVaultId } from '../../utils/tenant';
import { AppAuthorizationManager } from '../../managers/AppAuthorizationManager';
import type { ITokenVerifier } from '../../auth/ITokenVerifier';
import { generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { REPOSITORY_SAFE_EXAMPLES as safe } from 'sos-data-utils-ts/repository-privacy';
import { getEnvSectionId } from '../../utils/section-env';

const hostBootstrapClaims = testClaimsHostInitialization;

describe('Tenant KMS rehydration after activate route story', () => {
  const hostCollectionName = resolveHostPhysicalCollectionName();
  const vaultRepository = new VaultMemRepository();
  const logger = new ConsoleLogger();
  const cryptographyService = new CryptographyService(new AdapterCryptoSdkNode());

  let initialHarness: Awaited<ReturnType<typeof buildHarness>>;
  let restartedHarness: Awaited<ReturnType<typeof buildHarness>>;
  let tenantId: string;
  let controllerDid: string;
  let controllerAuthorization: string;
  let foreignDid: string;
  let foreignAuthorization: string;
  const originalInsecureBearer = process.env.DEMO_ALLOW_INSECURE_BEARER;

  beforeAll(async () => {
    process.env.DEV_SEED = 'true';
    process.env.NODE_ENV = 'development';
    process.env.SECURITY_MODE = 'demo';
    process.env.JSON_LEGACY = 'true';
    process.env.FHIR_LEGACY = 'true';
    process.env.DIDCOMM_PLAIN = 'true';
    process.env.DEMO_ALLOW_INSECURE_BEARER = 'true';

    const fixtureKeys = await generateKeyPair('ES384');
    const tokenVerifier: ITokenVerifier = {
      async verify(token) {
        try {
          const { payload } = await jwtVerify(token, fixtureKeys.publicKey, {
            issuer: safe.didWeb, audience: safe.httpsBaseUrl, algorithms: ['ES384'],
          });
          return { valid: true, payload };
        } catch {
          return { valid: false, error: 'Signed fixture principal rejected' };
        }
      },
    };
    initialHarness = await buildHarness(vaultRepository, hostCollectionName, cryptographyService, logger, tokenVerifier);
    tenantId = await onboardViaActivateAndOrder(initialHarness.app, initialHarness.queueAdapter);
    await purchaseEmployeeSeat(initialHarness.app, initialHarness.queueAdapter, tenantId);
    await initialHarness.queueAdapter.waitForEmptyQueue();
    initialHarness.queueAdapter.stop();

    process.env.DEMO_ALLOW_INSECURE_BEARER = 'false';
    restartedHarness = await buildHarness(vaultRepository, hostCollectionName, cryptographyService, logger, tokenVerifier);
    const tenantDocument = await restartedHarness.tenantManager.getDidDocument(getTenantVaultId(GatewaySector.HEALTH_CARE, tenantId));
    const controllers = Array.isArray(tenantDocument?.controller) ? tenantDocument.controller : tenantDocument?.controller ? [tenantDocument.controller] : [];
    controllerDid = controllers.find((value): value is string => typeof value === 'string' && value.startsWith('did:')) || '';
    expect(controllerDid).not.toBe('');
    foreignDid = `${safe.didWeb}:foreign-controller`;
    expect(controllers).not.toContain(foreignDid);
    const signPrincipal = (subject: string) => new SignJWT({}).setProtectedHeader({ alg: 'ES384' })
      .setIssuer(safe.didWeb).setAudience(safe.httpsBaseUrl).setSubject(subject)
      .setIssuedAt().setExpirationTime('10m').sign(fixtureKeys.privateKey);
    controllerAuthorization = `Bearer ${await signPrincipal(controllerDid)}`;
    foreignAuthorization = `Bearer ${await signPrincipal(foreignDid)}`;
  });

  afterAll(() => {
    initialHarness?.queueAdapter.stop();
    restartedHarness?.queueAdapter.stop();
    if (originalInsecureBearer === undefined) delete process.env.DEMO_ALLOW_INSECURE_BEARER;
    else process.env.DEMO_ALLOW_INSECURE_BEARER = originalInsecureBearer;
  });

  it('keeps tenant encrypt-to-self plaintext flows working after a KMS restart', async () => {
    const employeeUrl = `/${tenantId}/cds-es/v1/health-care/entity/org.schema/Employee/_batch`;
    const createPayload = structuredClone(EMPLOYEE_REGISTRATION_REQUEST) as any;
    createPayload.thid = 'employee-kms-rehydration-thid';
    createPayload.jti = 'employee-kms-rehydration-jti';
    createPayload.iss = controllerDid;
    createPayload.body.data[0].resource = {
      meta: {
        claims: {
          ...(createPayload.body.data[0].resource?.meta?.claims || {}),
        },
      },
    };
    createPayload.body.data[0].meta = {};
    createPayload.body.data[0].request = { method: 'POST' };

    const submit = await invokeExpress(restartedHarness.app, {
      method: 'POST',
      url: employeeUrl,
      headers: { 'content-type': 'application/json', authorization: controllerAuthorization },
      body: createPayload,
    });

    expect(submit.status).toBe(202);
    await restartedHarness.queueAdapter.waitForEmptyQueue();

    const poll = await pollJsonBody(restartedHarness.app, submit.headers.location, createPayload.thid);
    expect(poll.status).toBe(200);
    expect(poll.body.data[0].response.status).toBe('201');
    expect(String(poll.body.data[0].resource?.id || '')).toBeTruthy();
  });

  it('keeps the published tenant key and employee flow working when provisioning is replayed after restart', async () => {
    const replayEmployeeIdentifier = 'urn:uuid:71f84db2-dd41-4d99-a2d6-31a075319a86';
    const replayEmployeeEmail = 'receptionist-replayed-provisioning@acme.example';
    const tenantVaultId = getTenantVaultId(GatewaySector.HEALTH_CARE, tenantId);
    const publishedDid = await restartedHarness.tenantManager.getDidDocument(tenantVaultId);
    const publishedEncryptionKid = (publishedDid?.verificationMethod || [])
      .find((method) => (method.publicKeyJwk as any)?.use === 'enc')?.publicKeyJwk?.kid;

    const replayedKeys = await restartedHarness.kmsService.provisionKeys(tenantVaultId);

    expect(replayedKeys.keys.find((key) => key.use === 'enc')?.kid).toBe(publishedEncryptionKid);
    const employeeUrl = `/${tenantId}/cds-es/v1/health-care/entity/org.schema/Employee/_batch`;
    const createPayload = structuredClone(EMPLOYEE_REGISTRATION_REQUEST) as any;
    createPayload.thid = 'employee-kms-rehydration-replayed-provisioning-thid';
    createPayload.jti = 'employee-kms-rehydration-replayed-provisioning-jti';
    createPayload.iss = controllerDid;
    createPayload.body.data[0].resource = {
      meta: {
        claims: {
          ...(createPayload.body.data[0].resource?.meta?.claims || {}),
          [SchemaOrgPersonClaim.Identifier]: replayEmployeeIdentifier,
          [SchemaOrgPersonClaim.Email]: replayEmployeeEmail,
        },
      },
    };
    createPayload.body.data[0].meta = {};
    createPayload.body.data[0].request = { method: HttpRequestMethods.Post };

    const submit = await invokeExpress(restartedHarness.app, {
      method: HttpRequestMethods.Post,
      url: employeeUrl,
      headers: { 'content-type': 'application/json', authorization: controllerAuthorization },
      body: createPayload,
    });

    expect(submit.status).toBe(202);
    await restartedHarness.queueAdapter.waitForEmptyQueue();

    const poll = await pollJsonBody(restartedHarness.app, submit.headers.location, createPayload.thid);
    expect(poll.status).toBe(200);
    expect(poll.body.data[0].response.status).toBe('201');
    expect(String(poll.body.data[0].resource?.id || '')).toBeTruthy();
  });

  it('denies a genuinely verified foreign controller after restart without changing employee records', async () => {
    const tenantVaultId = getTenantVaultId(GatewaySector.HEALTH_CARE, tenantId);
    const collection = await restartedHarness.tenantManager.getCollectionName(tenantVaultId);
    if (!collection) throw new Error('Authoritative tenant collection unavailable');
    const before = structuredClone(await vaultRepository.getContainersInSection(collection, getEnvSectionId('employees')) || []);
    const template = structuredClone(EMPLOYEE_REGISTRATION_REQUEST);
    const entry = template.body.data[0];
    const payload = {
      ...template, thid: 'employee-kms-foreign-controller-thread',
      jti: 'employee-kms-foreign-controller-request', iss: foreignDid,
      body: { ...template.body, data: [{
        ...entry, meta: {}, request: { method: HttpRequestMethods.Post },
        resource: { meta: { claims: { ...(entry.resource?.meta?.claims || {}) } } },
      }] },
    };
    const submit = await invokeExpress(restartedHarness.app, {
      method: HttpRequestMethods.Post,
      url: `/${tenantId}/cds-es/v1/health-care/entity/org.schema/Employee/_batch`,
      headers: { 'content-type': 'application/json', authorization: foreignAuthorization },
      body: payload,
    });
    expect(submit.status).toBe(202);
    await restartedHarness.queueAdapter.waitForEmptyQueue();
    const poll = await pollJsonBody(restartedHarness.app, submit.headers.location, payload.thid);
    expect(poll.status).toBe(200);
    expect(poll.body.data[0].response.status).toBe('403');
    expect(await vaultRepository.getContainersInSection(collection, getEnvSectionId('employees')) || []).toEqual(before);
  });
});

async function purchaseEmployeeSeat(
  app: express.Express,
  queueAdapter: QueueAdapterMem,
  tenantId: string,
): Promise<void> {
  const offerPayload = {
    jti: 'employee-kms-seat-offer-jti',
    iss: `did:web:testhost.com:${tenantId}:cds-es:v1:health-care:employee:controller`,
    aud: tenantId,
    type: 'application/didcomm-plain+json',
    thid: 'employee-kms-seat-offer-thid',
    body: {
      resourceType: 'Bundle',
      type: 'batch',
      data: [buildLicensePurchaseEntry({ quantity: 1, userClass: 'employee', type: 'web' })],
    },
  };

  const offerSubmit = await invokeExpress(app, {
    method: 'POST',
    url: `/${tenantId}/cds-es/v1/health-care/entity/org.schema/Offer/_create`,
    headers: { 'content-type': 'application/json' },
    body: offerPayload,
  });
  expect(offerSubmit.status).toBe(202);
  await queueAdapter.waitForEmptyQueue();
  const offerPoll = await pollJsonBody(app, offerSubmit.headers.location, offerPayload.thid);
  const offerId = String(offerPoll.body.data[0].resource?.meta?.claims?.[SchemaOrgOfferClaim.Identifier] || '');
  expect(offerPoll.body.data[0].response.status).toBe('201');
  expect(offerId).toBeTruthy();

  const orderPayload = structuredClone(ORGANIZATION_ORDER_REQUEST) as any;
  orderPayload.thid = 'employee-kms-seat-order-thid';
  orderPayload.jti = 'employee-kms-seat-order-jti';
  orderPayload.body.data[0].meta = {};
  orderPayload.body.data[0].resource = { meta: { claims: {
    [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId,
    [SchemaOrgOrderClaim.PaymentMethod]: 'Stripe',
    [SchemaOrgOrderClaim.PartOfInvoice]: 'employee-kms-seat-invoice',
  } } };
  const orderSubmit = await invokeExpress(app, {
    method: 'POST',
    url: '/host/cds-es/v1/test/registry/org.schema/Order/_batch',
    headers: { 'content-type': 'application/json' },
    body: orderPayload,
  });
  expect(orderSubmit.status).toBe(202);
  await queueAdapter.waitForEmptyQueue();
  const orderPoll = await pollJsonBody(app, orderSubmit.headers.location, orderPayload.thid);
  expect(orderPoll.body.data[0].response.status).toBe('201');
}

async function buildHarness(
  sharedVaultRepository: VaultMemRepository,
  hostCollectionName: string,
  cryptographyService: CryptographyService,
  logger: ConsoleLogger,
  tokenVerifier: ITokenVerifier,
): Promise<{
  app: express.Express;
  queueAdapter: QueueAdapterMem;
  tenantManager: TenantsCacheManager;
  kmsService: KmsService;
}> {
  const asyncResponseStore = new AsyncResponseStoreMem();
  let kmsService: KmsService;
  const tenantManager = new TenantsCacheManager(sharedVaultRepository, () => kmsService, hostCollectionName);
  kmsService = new KmsService(cryptographyService, tenantManager, {
    wrappedKeyRepository: new VaultWrappedKeyRepository(sharedVaultRepository, hostCollectionName),
    envelopeAdapter: new InMemoryEnvelopeAdapter(),
  });
  await kmsService.init();

  const mockConfig: IServerConfig = {
    securityMode: 'demo',
    networkMode: 'test',
    fhirLegacy: true,
    jsonLegacy: true,
    didcommPlainEnabled: true,
    demoAllowInsecureBearer: process.env.DEMO_ALLOW_INSECURE_BEARER === 'true',
    nodeEnv: 'test',
    port: 3000,
    maxHeaderSize: 131072,
    apiHostname: 'testhost',
    hostExternalDomain: 'testhost.com',
    apiBaseUrl: 'http://testhost:3000',
    namespace: 'test-namespace',
    sectorsAllowed: [GatewaySector.HEALTH_CARE, GatewaySector.TEST],
    allowedPaymentMethods: ['Stripe'],
    dbProvider: 'mem',
    queueProvider: 'mem',
    storageProvider: 'mem',
    host: { legalName: 'Test Host', jurisdiction: 'ES', idType: 'TAX', idValue: 'VATES-B00000000' },
    mongo: { dbName: 'test' },
    firebase: {},
  };
  const hostRuntime: IHostRuntime = { hostCollectionName, hostDid: 'did:web:testhost.com' };

  const hostingManager = new HostingManager(
    sharedVaultRepository,
    kmsService,
    tenantManager,
    new StorageMemAdapter(),
    logger,
    mockConfig,
    hostRuntime,
  );
  const hostAlreadyExists = await sharedVaultRepository.vaultExists('host');
  if (!hostAlreadyExists) {
    await hostingManager.bootstrapHost(hostBootstrapClaims as any);
  }
  await tenantManager.loadHost();

  const managerRegistry: ManagerRegistry = {
    hostingManager,
    employeeManager: new EmployeeManager(sharedVaultRepository, kmsService, tenantManager, tenantManager, hostRuntime),
    licenseManager: new LicenseManager(sharedVaultRepository, kmsService),
    tenantManager,
  };

  const worker = new Worker(managerRegistry, mockConfig.apiBaseUrl, kmsService);
  const queueAdapter = new QueueAdapterMem(asyncResponseStore, worker);

  const app = express.default();
  app.use(express.json({ type: ['application/json', 'application/fhir+json'] }));
  app.use(express.urlencoded({ extended: false }));
  const appAuthorization = new AppAuthorizationManager(sharedVaultRepository, tokenVerifier, kmsService, cryptographyService);
  app.use('/', createApiRouter(queueAdapter, tenantManager, kmsService, asyncResponseStore, sharedVaultRepository, cryptographyService, mockConfig.apiBaseUrl, appAuthorization));

  return { app, queueAdapter, tenantManager, kmsService };
}

async function onboardViaActivateAndOrder(app: express.Express, queueAdapter: QueueAdapterMem): Promise<string> {
  const activationPayload = buildActivationPayload() as any;
  const activationSubmit = await invokeExpress(app, {
    method: 'POST',
    url: '/host/cds-es/v1/test/registry/org.schema/Organization/_activate',
    headers: { 'content-type': 'application/json' },
    body: activationPayload,
  });
  expect(activationSubmit.status).toBe(202);
  await queueAdapter.waitForEmptyQueue();

  const activationPoll = await pollJsonBody(app, activationSubmit.headers.location, activationPayload.thid);
  expect(activationPoll.status).toBe(200);

  const activationEntry = activationPoll.body.data[0];
  const offerId = String(activationEntry.resource?.meta?.claims?.[SchemaOrgOfferClaim.Identifier] || '');
  expect(offerId).toBeTruthy();

  const orderPayload = structuredClone(ORGANIZATION_ORDER_REQUEST) as any;
  orderPayload.thid = 'tenant-kms-order-thid';
  orderPayload.jti = 'tenant-kms-order-jti';
  orderPayload.body.data[0].meta = {};
  orderPayload.body.data[0].resource = {
    meta: {
      claims: {
        [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId,
        [SchemaOrgOrderClaim.PaymentMethod]: 'Stripe',
        [SchemaOrgOrderClaim.PartOfInvoice]: 'tenant-kms-order-invoice',
      },
    },
  };

  const orderSubmit = await invokeExpress(app, {
    method: 'POST',
    url: '/host/cds-es/v1/test/registry/org.schema/Order/_batch',
    headers: { 'content-type': 'application/json' },
    body: orderPayload,
  });
  expect(orderSubmit.status).toBe(202);
  await queueAdapter.waitForEmptyQueue();

  const orderPoll = await pollJsonBody(app, orderSubmit.headers.location, orderPayload.thid);
  expect(orderPoll.status).toBe(200);

  return String(activationEntry.resource?.meta?.claims?.[SchemaOrgOrganizationClaim.AlternateName] || '');
}
