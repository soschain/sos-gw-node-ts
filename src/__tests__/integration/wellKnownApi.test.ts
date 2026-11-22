// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// src/__tests__/integration/wellKnownApi.test.ts
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.
// Always create JSDoc, do not use strings inline in keys nor values, use types instead, and reuse the data test examples.

import { jest } from '@jest/globals';
import express from 'express';
import { createHash } from 'node:crypto';
import { compactVerify, CompactSign, exportJWK, generateKeyPair } from 'jose';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { AdapterCryptoSdkNode } from '../../gdc-backend-utils-node/adapters/node/crypto';
import { createDiscoveryRouter } from '../../routes/discovery';
import { DiscoveryService } from '../../services/DiscoveryService';
import type { TenantsCacheManager } from '../../managers/TenantsCacheManager';
import { testClaimsRegisterTenantExpanded, testHostDomain, testHostIdValue, testTenant1AlternateName, testTenant1DidWebHosted, testTenant1IdentifierUrn, testTenant1VaultId } from '../data/organization.data';
import { DidDocument } from '../../gdc-backend-utils-node/models/did';
import { IKmsService } from '../../gdc-backend-utils-node/models/IKmsService';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import { parseTenantUrn } from '../../utils/urn';
import { ILogger } from '../../loggers/ILogger';
import type { IVaultRepository } from '../../database/repositories/vault/vault.repository';
import { invokeExpress } from './helpers/invokeExpress';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { HostNetworkTypes } from 'sos-data-utils-ts/gateway-profile-values';
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';
import { ServiceCapability } from 'sos-data-utils-ts/service-capabilities';
import { serializeServiceCapabilityTokens } from 'sos-data-utils-ts/service-capabilities';
import {
  buildExampleHostedTenantBaseUrl,
  EXAMPLE_COVERAGE_SCOPE_EU,
  EXAMPLE_GATEWAY_PUBLIC_ORIGIN,
  EXAMPLE_HOSTING_OPERATOR_DID,
  EXAMPLE_HOST_PUBLIC_HOSTNAME,
  EXAMPLE_PROVIDER_LEGAL_NAME,
  EXAMPLE_SECONDARY_PROVIDER_ALTERNATE_NAME,
  EXAMPLE_SECONDARY_PROVIDER_LEGAL_NAME,
  EXAMPLE_SECONDARY_TENANT_SERVICE_DID,
  EXAMPLE_SIGNED_TERMS_PDF_URL,
} from 'sos-data-utils-ts/gateway-flow-examples';
import { buildGatewayDataspaceBasePath, buildGatewayDataspaceCatalogArtifactPath, buildGatewayDataspaceVersionPath } from 'sos-data-utils-ts/gateway-dataspace-routing';
import { NativeFhirFormats } from '../../constants/fhir-discovery';
import { SUBJECT_SECTION_DIGITAL_TWIN } from '../../constants/domain';
import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';
import { ContinuityServiceCapability } from 'sos-data-utils-ts/continuity-service-capabilities';
import { PublicAlertOperationalClaim } from 'sos-data-utils-ts/public-notifications';
import { CommunicationRequestClaim, DocumentReferenceClaim } from 'fhir-data-utils-ts/claims';

const EXAMPLE_SIGNED_TERMS_PDF_HASH = createHash('sha256')
  .update(EXAMPLE_SIGNED_TERMS_PDF_URL)
  .digest('hex');
const mockTenantsCacheManager = {
  getDidDocument: jest.fn(),
  getEmployeeDidDocument: jest.fn(),
  getTenant: jest.fn(),
  isTenantOperational: jest.fn(async () => true),
  getTenantDomainUrl: jest.fn(async () => `https://${testHostDomain}`),
  getTenantOperationalUrl: jest.fn(),
  getTenantJurisdiction: jest.fn(async () => 'CA-BC'),
  getTenantSector: jest.fn(async () => 'health-care'),
  getDidServiceConfig: jest.fn(),
  listAutodiscoverableTenants: jest.fn(),
  listRegisteredTenants: jest.fn(),
  getCollectionName: jest.fn(async () => testTenant1VaultId),
} as unknown as jest.Mocked<TenantsCacheManager>;

const mockVaultRepository = {
  getContainersInSection: jest.fn(async () => []),
  listContainersInSection: jest.fn(async () => []),
} as unknown as jest.Mocked<IVaultRepository>;

// Create a fully typed mock of the IKmsService to satisfy the interface
const mockKmsService: jest.Mocked<IKmsService> = {
  init: jest.fn(),
  provisionKeys: jest.fn(),
  getPublicJwks: jest.fn(),
  getPublicVerificationKey: jest.fn(),
  getPublicEncryptionKey: jest.fn(),
  getHostPublicJwkSet: jest.fn(),
  decodeRequest: jest.fn(),
  signWithManagedKey: jest.fn(),
  signWithReconstructedKey: jest.fn(),
  createDetachedJws: jest.fn(),
  createCompactJws: jest.fn(),
  encodeResponse: jest.fn(),
  protectConfidentialData: jest.fn(),
  unprotectConfidentialData: jest.fn(async (doc: ConfidentialStorageDoc) => doc.content as any),
  getHmacBase64Url: jest.fn(),
  protectAttributesNameAndValue: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
} as jest.Mocked<ILogger>;

const app = express();
const discoveryService = new DiscoveryService(mockTenantsCacheManager);
// Pass the mocked kmsService and logger to the router
const discoveryRouter = createDiscoveryRouter(
  mockTenantsCacheManager,
  discoveryService,
  mockKmsService,
  mockLogger,
  mockVaultRepository,
  new CryptographyService(new AdapterCryptoSdkNode()),
);
app.use('/', discoveryRouter);

describe('Well-Known DID Discovery API', () => {

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should return the correct DID Document for a hosted tenant via the cds-style path', async () => {
    // --- Arrange ---
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;

    // Construct the exact URL the gateway is expected to handle for a hosted DID.
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/did.json`;
    
    const expectedDidDoc: DidDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: testTenant1IdentifierUrn,
      alsoKnownAs: [testTenant1DidWebHosted],
      service: [{ // This is the new assertion
        id: '#legal-participant-credential',
        type: 'gx:LegalParticipant',
        serviceEndpoint: `${testTenant1DidWebHosted}/.well-known/legal-participant.vc.json`
      }]
    };

    // Configure the mock: The `resolveTenant` middleware will call `getDidDocument` to find the tenant.
    // The final route handler will then call it again via the discoveryService to get the document.
    mockTenantsCacheManager.getDidDocument.mockResolvedValue(expectedDidDoc);

    // --- Act ---
    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });

    // --- Assert ---
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(JSON.parse(response.text)).toEqual(expectedDidDoc);
    
    // Verify the middleware and the service handler used the correctly constructed vaultId to find the tenant.
    expect(mockTenantsCacheManager.getDidDocument).toHaveBeenCalledWith(testTenant1VaultId);
    // It's called twice: once in the middleware to check existence, once in the handler to get the data.
    expect(mockTenantsCacheManager.getDidDocument).toHaveBeenCalledTimes(2);
  });

  it('returns the same tenant DID document at the did:web path and the legacy well-known alias', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantPath = `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}`;
    const legacyKid = `${testTenant1DidWebHosted}#legacy-es384`;
    const expectedDidDoc = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: testTenant1DidWebHosted,
      verificationMethod: [{
        id: legacyKid,
        controller: testTenant1DidWebHosted,
        type: 'JsonWebKey2020',
        publicKeyJwk: { kid: 'legacy-es384', kty: 'EC', crv: 'P-384', alg: 'ES384', use: 'sig' },
      }],
      authentication: [legacyKid],
      assertionMethod: [legacyKid],
    } as DidDocument;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue(expectedDidDoc);

    const standardResponse = await invokeExpress(app, { method: 'GET', url: `${tenantPath}/did.json` });
    const compatibilityResponse = await invokeExpress(app, {
      method: 'GET',
      url: `${tenantPath}/.well-known/did.json`,
    });

    expect(standardResponse.status).toBe(200);
    expect(compatibilityResponse.status).toBe(200);
    expect(JSON.parse(standardResponse.text)).toEqual(expectedDidDoc);
    expect(JSON.parse(compatibilityResponse.text)).toEqual(expectedDidDoc);
    expect(JSON.parse(standardResponse.text)).toEqual(JSON.parse(compatibilityResponse.text));
    const publishedDid = JSON.parse(standardResponse.text) as DidDocument;
    const es384Method = publishedDid.verificationMethod?.find(
      (method) => (method.publicKeyJwk as any)?.alg === 'ES384',
    );
    expect(publishedDid.authentication).toContain(es384Method?.id);
    expect(publishedDid.assertionMethod).toContain(es384Method?.id);
    expect((es384Method?.publicKeyJwk as any)?.purpose).toBeUndefined();
  });

  it('resolves a lowercase hosted VAT DID path against the canonical tenant', async () => {
    const canonicalTenantId = 'VATES-G02793479';
    const canonicalVaultId = `${DataspaceSectors.OneHealthResearch}_${canonicalTenantId}`;
    const expectedDid = `did:web:gateway.example:${canonicalTenantId}:cds-ES:v1:${DataspaceSectors.OneHealthResearch}`;
    const expectedDidDoc = { id: expectedDid } as DidDocument;
    mockTenantsCacheManager.getDidDocument.mockImplementation(async (vaultId: string) => (
      vaultId === canonicalVaultId ? expectedDidDoc : undefined
    ));

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/vates-g02793479/cds-es/v1/${DataspaceSectors.OneHealthResearch}/.well-known/did.json`,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(expectedDidDoc);
    expect(mockTenantsCacheManager.getDidDocument).toHaveBeenCalledWith(canonicalVaultId);
  });

  it('publishes safe authoritative tenant status separately from the DID document', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantDid = `did:web:gateway.example:${testTenant1AlternateName}:cds-${urnParts.jurisdiction}:${urnParts.version}:${urnParts.sector}`;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: tenantDid } as DidDocument);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      status: 'active',
      didDocument: { id: tenantDid, controller: null },
      collectionName: testTenant1VaultId,
    });

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/tenant-status.json`,
    });

    expect(response.status).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(JSON.parse(response.text)).toEqual(expect.objectContaining({
      resourceType: 'OrganizationTenantStatus',
      tenant: expect.objectContaining({ did: tenantDid, controllerBindingStatus: 'required' }),
      controllers: [],
    }));
    expect(response.text).not.toContain('email');
    expect(response.text).not.toContain('activationCode');
    expect(response.text).not.toContain('privateKeyJwk');
  });

  it('resolves the public multikey controller did:web document separately from the tenant DID', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantDid = `did:web:gateway.example:${testTenant1AlternateName}:cds-${urnParts.jurisdiction}:${urnParts.version}:${urnParts.sector}`;
    const memberId = 'zControllerEmailHash';
    const role = 'RESPRSN';
    const controllerDid = `${tenantDid}:employee:${memberId}:${role}`;
    const controllerDidDocument: DidDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: controllerDid,
      verificationMethod: [
        { id: `${controllerDid}#es384`, type: 'JsonWebKey2020', controller: controllerDid, publicKeyJwk: { kid: 'es384', kty: 'EC', crv: 'P-384', x: 'x', y: 'y', alg: 'ES384' } },
        { id: `${controllerDid}#pontus`, type: 'JsonWebKey2020', controller: controllerDid, publicKeyJwk: { kid: 'pontus', kty: 'EC', crv: 'secp256k1', x: 'x', y: 'y', alg: 'ES256K' } },
        { id: `${controllerDid}#pqc`, type: 'JsonWebKey2020', controller: controllerDid, publicKeyJwk: { kid: 'pqc', kty: 'AKP', alg: 'ML-DSA-65', pub: 'public' } },
      ],
    };
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: tenantDid, controller: [controllerDid] },
    } as any);
    mockVaultRepository.getContainersInSection.mockResolvedValueOnce([{
      id: 'historical-controller-record',
      content: { id: controllerDid, didDocument: controllerDidDocument },
    }] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/employee/${memberId}/${role}/did.json`,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(controllerDidDocument);
    expect(mockVaultRepository.getContainersInSection).toHaveBeenCalled();
  });

  it('resolves an existing professional DID without adding the employee as a tenant controller', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantDid = `did:web:gateway.example:${testTenant1AlternateName}:cds-${urnParts.jurisdiction}:${urnParts.version}:${urnParts.sector}`;
    const memberId = 'zVeterinarianEmailHash';
    const role = '2250';
    const professionalDid = `${tenantDid}:employee:${memberId}:${role}`;
    const professionalDidDocument: DidDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: professionalDid,
      alsoKnownAs: [`urn:cds-${urnParts.jurisdiction}:${urnParts.version}:organization:vates:${testTenant1AlternateName}:member:${memberId}:${role}`],
      verificationMethod: [],
    };
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: tenantDid, controller: [] },
    } as any);
    mockVaultRepository.getContainersInSection.mockResolvedValueOnce([{
      id: 'governed-veterinarian-record',
      content: { id: professionalDid, didDocument: professionalDidDocument },
    }] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/employee/${memberId}/${role}/did.json`,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(professionalDidDocument);
  });

  it('publishes human-health capabilities at the exact section and format FHIR base', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const operationalUrl = `https://gateway.example/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}`;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1DidWebHosted } as any);
    mockTenantsCacheManager.getTenantOperationalUrl.mockResolvedValue(operationalUrl);
    mockTenantsCacheManager.getDidServiceConfig.mockResolvedValue([{
      selector: { section: SUBJECT_SECTION_DIGITAL_TWIN, format: NativeFhirFormats.R4 },
      serviceEndpoint: ResourceTypesFhirR4.ResearchSubject,
      actions: ['_search'],
    }] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/${SUBJECT_SECTION_DIGITAL_TWIN}/${NativeFhirFormats.R4}/metadata`,
    });
    const statement = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(statement.implementation.url).toBe(`${operationalUrl}/${SUBJECT_SECTION_DIGITAL_TWIN}/${NativeFhirFormats.R4}`);
    expect(statement.rest[0].resource.map((resource: any) => resource.type)).toEqual([
      ResourceTypesFhirR4.ResearchSubject,
    ]);
  });

  it('publishes veterinary capabilities at the exact section and format FHIR base', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const operationalUrl = `https://gateway.example/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}`;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1DidWebHosted } as any);
    mockTenantsCacheManager.getTenantOperationalUrl.mockResolvedValue(operationalUrl);
    mockTenantsCacheManager.getDidServiceConfig.mockResolvedValue([{
      selector: { section: SUBJECT_SECTION_DIGITAL_TWIN, format: NativeFhirFormats.R4 },
      serviceEndpoint: `${ResourceTypesFhirR4.ResearchSubject},ResearchStudy`,
      actions: ['_search'],
    }] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/${SUBJECT_SECTION_DIGITAL_TWIN}/${NativeFhirFormats.R4}/metadata`,
    });
    const statement = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(statement.implementation.url).toBe(`${operationalUrl}/${SUBJECT_SECTION_DIGITAL_TWIN}/${NativeFhirFormats.R4}`);
    expect(statement.rest[0].resource.map((resource: any) => resource.type)).toEqual([
      ResourceTypesFhirR4.ResearchSubject,
      'ResearchStudy',
    ]);
  });
});

describe('Well-Known JWKS Discovery API', () => {
  // Flow contract: the root host DID advertises /jwks.json, so that exact
  // public URL must expose the host keys without requiring CDS route context.

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('returns the host JWK Set at the exact URL advertised by the root host DID', async () => {
    const expectedJwks = { keys: [{ kid: 'root-host-key-1', kty: 'AKP' }] };
    mockKmsService.getPublicJwks.mockResolvedValue(expectedJwks);

    const response = await invokeExpress(app, { method: 'GET', url: '/jwks.json' });

    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(JSON.parse(response.text)).toEqual(expectedJwks);
    expect(mockKmsService.getPublicJwks).toHaveBeenCalledWith('host');
  });

  it('should return the JWKSet for the host', async () => {
    // --- Arrange ---
    const expectedJwks = { keys: [{ kid: 'host-key-1', kty: 'AKP' }] };
    const expectedUrl = `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known/jwks.json`;

    // Mock the KMS service directly
    mockKmsService.getPublicJwks.mockResolvedValue(expectedJwks);
    
    // The middleware still needs to resolve the host.
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: 'did:web:host' } as any);

    // --- Act ---
    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });

    // --- Assert ---
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(JSON.parse(response.text)).toEqual(expectedJwks);
    expect(mockKmsService.getPublicJwks).toHaveBeenCalledWith('host');
  });

  it('should return the JWKSet for a hosted tenant', async () => {
    // --- Arrange ---
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/jwks.json`;
    const expectedJwks = { keys: [{ kid: 'tenant-key-1', kty: 'AKP' }] };

    mockKmsService.getPublicJwks.mockResolvedValue(expectedJwks);
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1IdentifierUrn } as any);

    // --- Act ---
    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });

    // --- Assert ---
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(expectedJwks);
    expect(mockKmsService.getPublicJwks).toHaveBeenCalledWith(testTenant1VaultId);
  });

  it('does not expose private KMS purpose labels in the public JWK Set', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const expectedUrl = `/${testTenant1AlternateName}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/jwks.json`;
    mockKmsService.getPublicJwks.mockResolvedValue({
      keys: [
        { kid: 'comm-ml', kty: 'AKP', alg: 'ML-DSA-44', use: 'sig', purpose: 'comm_sig' },
        { kid: 'vc-ml', kty: 'AKP', alg: 'ML-DSA-44', use: 'sig', purpose: 'vc_sign' },
      ],
    } as any);
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1IdentifierUrn } as any);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.keys).toEqual([
      { kid: 'comm-ml', kty: 'AKP', alg: 'ML-DSA-44', use: 'sig' },
      { kid: 'vc-ml', kty: 'AKP', alg: 'ML-DSA-44', use: 'sig' },
    ]);
  });
});

describe('Well-Known Ping API', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should return the host ping response via the host-scoped CDS path', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: 'did:web:host' } as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/host/cds-eu/v1/${HostNetworkTypes.Test}/.well-known/ping`,
    });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.type).toBe('batch-response');
    expect(parsed.data?.[0]?.issue?.[0]?.diagnostics).toBe('Ping successful');
    expect(mockTenantsCacheManager.getDidDocument).toHaveBeenCalledWith('host');
  });
});

describe('Well-Known Tenant Artifacts API', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('publishes the same participant-signed Gaia-X statement in JSON and in a JWT container', async () => {
    const urn = parseTenantUrn(testTenant1IdentifierUrn)!;
    const base = `/${testTenant1AlternateName}/cds-${urn.jurisdiction}/${urn.version}/${urn.sector}/.well-known`;
    const did = testTenant1DidWebHosted;
    const statement = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'LegalPerson'],
      issuer: did,
      credentialSubject: { id: did, type: 'gx:LegalPerson' },
    };
    const signed = { ...statement, proof: { verificationMethod: `${did}#tenant-gaia-x`, jws: 'header..signature' } };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: did } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({ didDocument: { id: did }, selfDescriptionVc: signed } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [
      { kid: 'tenant-vc-sign', use: 'sig', purpose: 'vc_sign', alg: 'ML-DSA-65' },
      { kid: 'tenant-gaia-x', use: 'sig', kty: 'EC', alg: 'ES256' },
    ] } as any);
    mockKmsService.createDetachedJws.mockResolvedValue('header..signature');
    mockKmsService.createCompactJws.mockResolvedValue('header.payload.signature');

    const json = await invokeExpress(app, { method: 'GET', url: base + '/vc.json' });
    expect(JSON.parse(json.text)).toMatchObject({
      ...statement,
      proof: [{ verificationMethod: `${did}#tenant-gaia-x` }, { verificationMethod: `${did}#tenant-vc-sign` }],
    });
    const jwt = await invokeExpress(app, { method: 'GET', url: base + '/legal-participant.vc.json' });
    expect(JSON.parse(jwt.text)).toEqual({
      '@context': 'https://www.w3.org/ns/credentials/v2',
      type: 'EnvelopedVerifiableCredential',
      id: 'data:application/vc+jwt,header.payload.signature',
    });
    expect(mockKmsService.createCompactJws).toHaveBeenCalledWith(
      { ...statement, '@context': [...statement['@context'], 'https://w3id.org/gaia-x/development#'] },
      'tenant-gaia-x', testTenant1VaultId, 'vc_sign', expect.any(Object),
    );
  });

  it('serves only the original ICA organization credential at organization.json', async () => {
    const urn = parseTenantUrn(testTenant1IdentifierUrn)!;
    const base = `/${testTenant1AlternateName}/cds-${urn.jurisdiction}/${urn.version}/${urn.sector}/.well-known`;
    const organization = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
      type: ['VerifiableCredential', 'OrganizationCredential'],
      issuer: testTenant1IdentifierUrn,
      credentialSubject: { id: testTenant1DidWebHosted, '@type': 'Organization' },
      proof: { verificationMethod: `${testTenant1IdentifierUrn}#test-key`, jws: 'header..signature' },
    };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1DidWebHosted } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({ governanceVc: organization } as any);

    const response = await invokeExpress(app, { method: 'GET', url: base + '/organization.json' });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(organization);
    expect(mockKmsService.createCompactJws).not.toHaveBeenCalled();
    expect(mockKmsService.createDetachedJws).not.toHaveBeenCalled();

    const hostBase = `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known`;
    const hostDid = testTenant1DidWebHosted;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: hostDid } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: hostDid },
      organizationCredential: organization,
      governanceVc: { issuer: hostDid, type: ['VerifiableCredential', 'LegalPerson'], credentialSubject: { id: hostDid, type: 'gx:LegalPerson' } },
    } as any);
    const host = await invokeExpress(app, { method: 'GET', url: hostBase + '/organization.json' });
    expect(host.status).toBe(200);
    expect(JSON.parse(host.text)).toEqual(organization);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'host-vc-sign', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createDetachedJws.mockResolvedValue('header..signature');
    const legacy = await invokeExpress(app, { method: 'GET', url: hostBase + '/vc.json' });
    expect(JSON.parse(legacy.text).type).toContain('LegalPerson');

    mockTenantsCacheManager.getTenant.mockResolvedValue({ governanceVc: { ...organization, issuer: hostDid } } as any);
    const missing = await invokeExpress(app, { method: 'GET', url: hostBase + '/organization.json' });
    expect(missing.status).toBe(404);
  });

  it.each(['host', 'tenant'])('signs the published ICA evidence link only for a matching %s', async (target) => {
    const cryptography = new CryptographyService(new AdapterCryptoSdkNode());
    const { publicJWKey, secretKeyBytes } = await cryptography.generateKeyPairMlDsa(undefined, 'ML-DSA-65');
    const { kid, alg } = publicJWKey;
    const compatible = await generateKeyPair('ES256');
    const compatibleKid = 'compatible-signature';
    const compatiblePublicJwk = { ...await exportJWK(compatible.publicKey), alg: 'ES256', use: 'sig', kid: compatibleKid };
    const icaKeys = await cryptography.generateKeyPairMlDsa();
    const urn = parseTenantUrn(testTenant1IdentifierUrn)!;
    const base = target === 'host'
      ? `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known`
      : `/${testTenant1AlternateName}/cds-${urn.jurisdiction}/${urn.version}/${urn.sector}/.well-known`;
    const did = target === 'host' ? `did:web:${testHostDomain}` : testTenant1DidWebHosted;
    const organizationClaims = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
      type: ['VerifiableCredential', 'OrganizationCredential'],
      issuer: EXAMPLE_HOSTING_OPERATOR_DID,
      credentialSubject: { id: did, '@type': 'Organization', taxID: testHostIdValue },
      evidence: [{ type: 'document' }],
    };
    const icaSignature = await cryptography.signDataJws(organizationClaims, {
      kid: icaKeys.publicJWKey.kid,
      alg: icaKeys.publicJWKey.alg,
    }, icaKeys.secretKeyBytes);
    const organization = {
      ...organizationClaims,
      proof: {
        verificationMethod: `${EXAMPLE_HOSTING_OPERATOR_DID}#${icaKeys.publicJWKey.kid}`,
        jws: `${icaSignature.protected}..${icaSignature.signature}`,
      },
    };
    const declaration = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'LegalPerson'],
      issuer: did,
      credentialSubject: {
        id: did,
        type: 'gx:LegalPerson',
        'gx:legalRegistrationNumber': { id: `${did}#ica-legal-registration-evidence` },
      },
      proof: [{ verificationMethod: `${did}#test-key`, jws: 'header..signature' }],
    };
    const entity = {
      didDocument: { id: did }, selfDescriptionVc: declaration, organizationCredential: organization,
      claims: target === 'host'
        ? { [SchemaOrgOrganizationClaim.IdentifierValue]: testHostIdValue }
        : { ...testClaimsRegisterTenantExpanded, [SchemaOrgOrganizationClaim.TaxId]: testHostIdValue },
    };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: did } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue(entity as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [compatiblePublicJwk, { ...publicJWKey, use: 'sig', purpose: 'vc_sign' }] } as any);
    const signCompatible = (payload: object, header = {}) =>
      new CompactSign(Buffer.from(JSON.stringify(payload)))
        .setProtectedHeader({ alg: 'ES256', kid: compatibleKid, ...header })
        .sign(compatible.privateKey);
    mockKmsService.createDetachedJws.mockImplementation(async (payload, signingKid) => {
      if (signingKid === compatibleKid) {
        const [protectedHeader, , signature] = (await signCompatible(payload)).split('.');
        return `${protectedHeader}..${signature}`;
      }
      const signature = await cryptography.signDataJws(payload, { kid, alg }, secretKeyBytes);
      return `${signature.protected}..${signature.signature}`;
    });
    mockKmsService.createCompactJws.mockImplementation(async (payload, _kid, _vaultId, _purpose, header) =>
      signCompatible(payload, header));
    const original = await invokeExpress(app, { method: 'GET', url: `${base}/organization.json` });
    const json = await invokeExpress(app, { method: 'GET', url: `${base}/vc.json` });
    const jwt = await invokeExpress(app, { method: 'GET', url: `${base}/legal-participant.vc.json` });
    const { proof: publishedIcaProof, ...publishedIcaClaims } = JSON.parse(original.text);
    expect({ ...publishedIcaClaims, proof: publishedIcaProof }).toEqual(organization);
    const [icaHeader, , icaDetachedSignature] = publishedIcaProof.jws.split('.');
    const icaCompact = `${icaHeader}.${Buffer.from(JSON.stringify(publishedIcaClaims)).toString('base64url')}.${icaDetachedSignature}`;
    expect(await cryptography.verifyJws(icaCompact, icaKeys.publicJWKey)).toBe(true);
    expect(jwt.status).toBe(200);
    const { proof, ...statement } = JSON.parse(json.text);
    expect(statement.relatedResource).toEqual([{
      id: `https://${testHostDomain}${base}/organization.json`,
      digestSRI: `sha256-${createHash('sha256').update(original.text).digest('base64')}`,
    }]);
    expect(statement.credentialSubject['https://schema.org/taxID']).toBe(testHostIdValue);
    expect(statement.credentialSubject['gx:legalRegistrationNumber']).toBeUndefined();
    expect(proof.map((entry: { verificationMethod: string }) => entry.verificationMethod))
      .toEqual([`${did}#${compatibleKid}`, `${did}#${kid}`]);
    const detached = (entry: { jws: string }) => {
      const [header, , signature] = entry.jws.split('.');
      return `${header}.${Buffer.from(JSON.stringify(statement)).toString('base64url')}.${signature}`;
    };
    expect((await compactVerify(detached(proof[0]), compatible.publicKey)).protectedHeader.alg).toBe('ES256');
    expect(await cryptography.verifyJws(detached(proof[1]), publicJWKey)).toBe(true);
    const compact = JSON.parse(jwt.text).id.split(',')[1];
    const verified = await compactVerify(compact, compatible.publicKey);
    expect(verified.protectedHeader).toMatchObject({ typ: 'vc+jwt', cty: 'vc', kid: `${did}#${compatibleKid}`, iss: did });
    expect(JSON.parse(Buffer.from(verified.payload).toString())).toEqual(statement);
    const vaultId = target === 'host' ? 'host' : testTenant1VaultId;
    expect(mockKmsService.createDetachedJws).toHaveBeenCalledWith(statement, kid, vaultId, 'vc_sign');
    expect(mockKmsService.createCompactJws).toHaveBeenCalledWith(statement, compatibleKid, vaultId, 'vc_sign', expect.any(Object));

    mockTenantsCacheManager.getTenant.mockResolvedValue({
      ...entity,
      claims: testClaimsRegisterTenantExpanded,
    } as any);
    const mismatch = await invokeExpress(app, { method: 'GET', url: `${base}/vc.json` });
    expect(JSON.parse(mismatch.text).relatedResource).toBeUndefined();
  });

  it('preserves the original host organization statement and its endorsements', async () => {
    const urn = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantBase = `/${testTenant1AlternateName}/cds-${urn.jurisdiction}/${urn.version}/${urn.sector}/.well-known`;
    const hostBase = `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known`;
    const did = testTenant1DidWebHosted;
    const organization = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
      type: ['VerifiableCredential', 'OrganizationCredential'],
      issuer: did,
      credentialSubject: { id: did, '@type': 'Organization', taxID: testHostIdValue },
      evidence: [{ type: 'document' }],
      proof: [did, EXAMPLE_HOSTING_OPERATOR_DID].map(signer => ({
        verificationMethod: `${signer}#test-key`, jws: 'header..signature',
      })),
    };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: did } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: did }, organizationCredential: organization, claims: testClaimsRegisterTenantExpanded,
    } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'test-key', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createDetachedJws.mockResolvedValue('header..signature');
    const response = await invokeExpress(app, { method: 'GET', url: `${hostBase}/organization.json` });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toMatchObject({
      ...organization,
      proof: [expect.objectContaining({ verificationMethod: organization.proof[0].verificationMethod }), organization.proof[1]],
    });
    const tenant = await invokeExpress(app, { method: 'GET', url: `${tenantBase}/organization.json` });
    expect(tenant.status).toBe(404);
  });

  it('publishes a provisional host organization statement without issuing one for tenants', async () => {
    const urn = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantBase = `/${testTenant1AlternateName}/cds-${urn.jurisdiction}/${urn.version}/${urn.sector}/.well-known`;
    const hostBase = `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known`;
    const did = testTenant1DidWebHosted;
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: did } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: did }, claims: testClaimsRegisterTenantExpanded,
    } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'test-key', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createDetachedJws.mockResolvedValue('header..signature');
    const host = await invokeExpress(app, { method: 'GET', url: `${hostBase}/organization.json` });
    expect(host.status).toBe(200);
    const { proof, ...statement } = JSON.parse(host.text);
    expect(statement.issuer).toBe(did);
    expect(statement.type).toContain('OrganizationCredential');
    expect(statement.credentialSubject).toMatchObject({ id: did, '@type': 'Organization', taxID: testTenant1AlternateName });
    expect(statement.evidence).toBeUndefined();
    expect(proof[0].verificationMethod).toBe(`${did}#test-key`);
    expect(mockKmsService.createDetachedJws).toHaveBeenCalledWith(statement, 'test-key', 'host', 'vc_sign');
    const tenant = await invokeExpress(app, { method: 'GET', url: `${tenantBase}/organization.json` });
    expect(tenant.status).toBe(404);
  });

  it('should return the stored self-description (self-description.json) for a hosted tenant', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/self-description.json`;

    const expectedSelfDesc = { type: ['VerifiableCredential'], credentialSubject: { id: testTenant1IdentifierUrn } };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1IdentifierUrn } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({ selfDescriptionVc: expectedSelfDesc } as any);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual(expectedSelfDesc);
    expect(mockTenantsCacheManager.getTenant).toHaveBeenCalledWith(testTenant1VaultId);
  });

  it('publishes a host-signed hosting offer in the host catalogue without tenant capabilities', async () => {
    const scope = {
      participantId: 'host',
      jurisdiction: EXAMPLE_COVERAGE_SCOPE_EU,
      version: 'v1',
      hostNetwork: HostNetworkTypes.Test,
    } as const;
    const base = buildGatewayDataspaceBasePath(scope).replace(/\/dsp$/, '');
    // Check the exact public artifact filenames a catalogue reader can follow.
    const offerPath = `${base}/.well-known/service-offering-hosting.json`;
    const providerPath = `${base}/.well-known/legal-participant.vc.json`;
    const origin = EXAMPLE_GATEWAY_PUBLIC_ORIGIN;
    const headers = { host: EXAMPLE_HOST_PUBLIC_HOSTNAME };
    const hostDid = { id: EXAMPLE_HOSTING_OPERATOR_DID };
    const hostClaims = {
      [SchemaOrgServiceClaim.TermsOfService]: EXAMPLE_SIGNED_TERMS_PDF_URL,
      [`${SchemaOrgServiceClaim.TermsOfService}#hash`]: EXAMPLE_SIGNED_TERMS_PDF_HASH,
    };
    mockTenantsCacheManager.getDidDocument.mockResolvedValue(hostDid as any);
    mockTenantsCacheManager.listAutodiscoverableTenants.mockResolvedValue([]);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: hostDid,
      claims: hostClaims,
      governanceVc: { type: ['VerifiableCredential', 'LegalPerson'] },
    } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'host-vc-sign', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createCompactJws.mockResolvedValue('header.payload.signature');

    const offer = await invokeExpress(app, { method: 'GET', url: offerPath, headers });
    expect(offer.status).toBe(200);
    expect(JSON.parse(offer.text)).toMatchObject({
      issuer: hostDid.id,
      credentialSubject: {
        type: 'gx:ServiceOffering',
        'gx:providedBy': { id: origin + providerPath },
      },
    });
    expect(mockKmsService.createCompactJws).toHaveBeenCalledWith(
      expect.objectContaining({ issuer: hostDid.id }), 'host-vc-sign', 'host', 'vc_sign', expect.any(Object),
    );

    const cataloguePath = buildGatewayDataspaceCatalogArtifactPath(scope);
    const catalogue = await invokeExpress(app, { method: 'GET', url: cataloguePath, headers });
    expect(catalogue.status).toBe(200);
    expect(JSON.parse(catalogue.text)['dcat:service']).toEqual([
      expect.objectContaining({ '@id': origin + offerPath, 'dcterms:publisher': { '@id': hostDid.id } }),
    ]);

    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: hostDid,
      claims: { [SchemaOrgServiceClaim.TermsOfService]: EXAMPLE_SIGNED_TERMS_PDF_URL },
      governanceVc: { type: ['VerifiableCredential', 'LegalPerson'] },
    } as any);
    const unavailable = await invokeExpress(app, { method: 'GET', url: offerPath, headers });
    expect(unavailable.status).toBe(404);
    const catalogueWithoutOffer = await invokeExpress(app, { method: 'GET', url: cataloguePath, headers });
    expect(JSON.parse(catalogueWithoutOffer.text)['dcat:service']).toEqual([]);
  });

  it('should return the index service offering artifact for a hosted tenant when indexing is enabled', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/service-offering-index.json`;

    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1DidWebHosted } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'tenant-vc-sign', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createCompactJws.mockResolvedValue('header.payload.signature');
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: testTenant1DidWebHosted },
      claims: {
        [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
        [SchemaOrgOrganizationClaim.AlternateName]: tenantId,
        [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
        [SchemaOrgServiceClaim.Category]: urnParts.sector,
        [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
          alternateName: tenantId,
          jurisdiction: urnParts.jurisdiction,
          version: urnParts.version,
          sector: urnParts.sector,
        }),
        [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
          ServiceCapability.IndexProvider,
          ServiceCapability.IndexReader,
        ]),
        [SchemaOrgServiceClaim.TermsOfService]: EXAMPLE_SIGNED_TERMS_PDF_URL,
        [`${SchemaOrgServiceClaim.TermsOfService}#hash`]: EXAMPLE_SIGNED_TERMS_PDF_HASH,
      },
    } as any);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.type).toEqual(['VerifiableCredential', 'ServiceOffering']);
    expect(parsed.credentialSubject.type).toBe('gx:ServiceOffering');
    expect(parsed.credentialSubject['gx:endpoint']).toEqual([{ 'gx:endpointURL': buildExampleHostedTenantBaseUrl({
      alternateName: tenantId,
      jurisdiction: urnParts.jurisdiction,
      version: urnParts.version,
      sector: urnParts.sector,
    }) }]);
    expect(parsed.proof).toEqual({
      type: 'EnvelopedVerifiableCredential',
      id: 'data:application/vc+jwt,header.payload.signature',
    });
    expect(mockKmsService.createCompactJws).toHaveBeenCalledWith(
      expect.objectContaining({ type: ['VerifiableCredential', 'ServiceOffering'] }),
      'tenant-vc-sign',
      testTenant1VaultId,
      'vc_sign',
      expect.objectContaining({ typ: 'vc+jwt', cty: 'vc' }),
    );
  });

  it('should return 404 for the research service offering artifact when digital twin is not enabled', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction}/${urnParts.version}/${urnParts.sector}/.well-known/service-offering-research.json`;

    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1IdentifierUrn } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: testTenant1IdentifierUrn },
      claims: {
        [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
        [SchemaOrgOrganizationClaim.AlternateName]: tenantId,
        [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
        [SchemaOrgServiceClaim.Category]: urnParts.sector,
        [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
          alternateName: tenantId,
          jurisdiction: urnParts.jurisdiction,
          version: urnParts.version,
          sector: urnParts.sector,
        }),
        [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
          ServiceCapability.IndexProvider,
          ServiceCapability.IndexReader,
        ]),
      },
    } as any);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });

    expect(response.status).toBe(404);
  });

  it('should return an independently selectable personal-backup service offering artifact', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = `/${tenantId}/cds-${urnParts.jurisdiction.toLowerCase()}/${urnParts.version}/${urnParts.sector}/.well-known/service-offering-personal-backup.json`;

    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1DidWebHosted } as any);
    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'tenant-vc-sign', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createCompactJws.mockResolvedValue('header.payload.signature');
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: testTenant1DidWebHosted },
      claims: {
        [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
        [SchemaOrgOrganizationClaim.AlternateName]: tenantId,
        [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
        [SchemaOrgServiceClaim.Category]: urnParts.sector,
        [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
          alternateName: tenantId,
          jurisdiction: urnParts.jurisdiction,
          version: urnParts.version,
          sector: urnParts.sector,
        }),
        [SchemaOrgServiceClaim.ServiceType]: ContinuityServiceCapability.DocumentBackupProvider,
        [SchemaOrgServiceClaim.TermsOfService]: EXAMPLE_SIGNED_TERMS_PDF_URL,
        [`${SchemaOrgServiceClaim.TermsOfService}#hash`]: EXAMPLE_SIGNED_TERMS_PDF_HASH,
      },
    } as any);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.id).toContain(expectedUrl);
    expect(parsed.credentialSubject['gx:name']).toContain('Personal Backup');
    expect(parsed.proof).toEqual({
      type: 'EnvelopedVerifiableCredential',
      id: 'data:application/vc+jwt,header.payload.signature',
    });
    expect(mockKmsService.createCompactJws).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialSubject: expect.objectContaining({
          'gx:name': expect.stringContaining('Personal Backup'),
        }),
      }),
      'tenant-vc-sign',
      testTenant1VaultId,
      'vc_sign',
      expect.objectContaining({ typ: 'vc+jwt', cty: 'vc' }),
    );
  });

  it('should hide tenant dataspace publication endpoints when the tenant is disabled', async () => {
    const urnParts = parseTenantUrn(testTenant1IdentifierUrn)!;
    const tenantId = testTenant1AlternateName;
    const expectedUrl = buildGatewayDataspaceVersionPath({
      tenantId,
      jurisdiction: urnParts.jurisdiction,
      version: urnParts.version,
      sector: urnParts.sector,
    });

    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: testTenant1IdentifierUrn } as any);
    mockTenantsCacheManager.isTenantOperational.mockResolvedValue(false);

    const response = await invokeExpress(app, { method: 'GET', url: expectedUrl });
    expect(response.status).toBe(404);
  });
});

describe('Well-Known Legal Participant VC API', () => {

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should return the stored Legal Participant VC for the host', async () => {
    const hostDidDoc = { id: 'did:web:host' };
    const hostEntityConfig = {
      didDocument: hostDidDoc,
      governanceVc: { id: 'urn:uuid:host-legal-participant', issuer: hostDidDoc.id, credentialSubject: { id: hostDidDoc.id, type: 'gx:LegalPerson' } },
    };

    mockKmsService.getPublicJwks.mockResolvedValue({ keys: [{ kid: 'host-vc-sign', use: 'sig', kty: 'EC', alg: 'ES256' }] } as any);
    mockKmsService.createCompactJws.mockResolvedValue('header.payload.signature');
    mockTenantsCacheManager.getTenant.mockResolvedValue(hostEntityConfig);
    mockTenantsCacheManager.getDidDocument.mockResolvedValue(hostDidDoc as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: `/host/cds-${EXAMPLE_COVERAGE_SCOPE_EU}/v1/${HostNetworkTypes.Test}/.well-known/legal-participant.vc.json`,
    });

    expect(response.status).toBe(200);
    const parsed = JSON.parse(response.text);
    expect(parsed).toEqual({
      '@context': 'https://www.w3.org/ns/credentials/v2',
      type: 'EnvelopedVerifiableCredential',
      id: 'data:application/vc+jwt,header.payload.signature',
    });
    expect(mockTenantsCacheManager.getTenant).toHaveBeenCalledWith('host');
  });
});

describe('DSP Discovery API', () => {
  beforeEach(() => {
    mockTenantsCacheManager.isTenantOperational.mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should return host DSP version metadata for a sector-scoped host catalog', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: 'did:web:host' } as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: buildGatewayDataspaceVersionPath({
        participantId: 'host',
        jurisdiction: 'eu',
        version: 'v1',
        hostNetwork: HostNetworkTypes.Test,
      }),
      headers: { host: EXAMPLE_HOST_PUBLIC_HOSTNAME },
    });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.protocolVersions).toEqual([
      {
        version: '2025-1',
        path: `/host/cds-eu/v1/${HostNetworkTypes.Test}/dsp`,
      },
    ]);
  });

  it('should return a sector-scoped host catalog artifact with dcat:service entries derived from serviceType capabilities', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: 'did:web:host' } as any);
    mockTenantsCacheManager.listAutodiscoverableTenants.mockResolvedValue([
      {
        didDocument: { id: testTenant1DidWebHosted },
        claims: {
          [SchemaOrgOrganizationClaim.AlternateName]: testTenant1AlternateName,
          [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
          [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
          [SchemaOrgOrganizationClaim.AddressRegion]: 'ES-MD',
          [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
          [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
            alternateName: testTenant1AlternateName,
            jurisdiction: 'ES',
            version: 'v1',
            sector: DataspaceSectors.HealthResearch,
          }),
          [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
            ServiceCapability.IndexProvider,
            ServiceCapability.DigitalTwinProvider,
            ContinuityServiceCapability.DocumentBackupProvider,
            ContinuityServiceCapability.ImagingStudyProvider,
            ContinuityServiceCapability.BinaryObjectProvider,
          ]),
        },
      },
      {
        didDocument: { id: EXAMPLE_SECONDARY_TENANT_SERVICE_DID },
        claims: {
          [SchemaOrgOrganizationClaim.AlternateName]: EXAMPLE_SECONDARY_PROVIDER_ALTERNATE_NAME,
          [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_SECONDARY_PROVIDER_LEGAL_NAME,
          [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
          [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
          [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
            alternateName: EXAMPLE_SECONDARY_PROVIDER_ALTERNATE_NAME,
            jurisdiction: 'ES',
            version: 'v1',
            sector: DataspaceSectors.HealthResearch,
          }),
          [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
            ServiceCapability.IndexReader,
            ServiceCapability.DigitalTwinReader,
          ]),
        },
      },
    ] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: buildGatewayDataspaceCatalogArtifactPath({
        participantId: 'host',
        jurisdiction: 'eu',
        version: 'v1',
        hostNetwork: HostNetworkTypes.Test,
      }),
      headers: { host: EXAMPLE_HOST_PUBLIC_HOSTNAME },
    });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed['@type']).toBe('dcat:Catalog');
    expect(parsed['dcat:catalog']).toEqual([{
      '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}${buildGatewayDataspaceCatalogArtifactPath({
        tenantId: testTenant1AlternateName, jurisdiction: 'es-md', version: 'v1', sector: DataspaceSectors.HealthResearch,
      })}`,
    }]);
    expect(Array.isArray(parsed['dcat:service'])).toBe(true);
    expect(parsed['dcat:service']).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-index.json`,
          '@type': 'dcat:DataService',
        }),
        expect.objectContaining({
          '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-research.json`,
          '@type': 'dcat:DataService',
        }),
        expect.objectContaining({
          '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-personal-backup.json`,
          '@type': 'dcat:DataService',
          'dcat:keyword': [
            ContinuityServiceCapability.DocumentBackupProvider,
            ContinuityServiceCapability.ImagingStudyProvider,
            ContinuityServiceCapability.BinaryObjectProvider,
          ],
        }),
      ]),
    );
    expect(parsed['dcat:dataset'][0]['dcat:service']).toEqual(
      expect.arrayContaining([
        { '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-index.json` },
        { '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-research.json` },
        { '@id': `http://${EXAMPLE_HOST_PUBLIC_HOSTNAME}/${testTenant1AlternateName}/cds-es/v1/${DataspaceSectors.HealthResearch}/.well-known/service-offering-personal-backup.json` },
      ]),
    );
    // The published access URL follows the registered publisher, independently of the request Host header.
    expect(parsed['dcat:dataset'][0]['dcat:distribution'][0]['dcat:accessURL']).toBe(
      `https://${testHostDomain}/.well-known/did.json`,
    );
    expect(parsed['dcat:dataset']).toHaveLength(1);
    expect(mockTenantsCacheManager.listAutodiscoverableTenants).toHaveBeenCalledTimes(1);
  });

  it('should publish provider datasets when service claims are stored under provider.service', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: 'did:web:host' } as any);
    mockTenantsCacheManager.listAutodiscoverableTenants.mockResolvedValue([
      {
        didDocument: { id: testTenant1DidWebHosted },
        claims: {
          [SchemaOrgOrganizationClaim.AlternateName]: testTenant1AlternateName,
          [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
          [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
        },
        provider: {
          service: {
            [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
            [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
              alternateName: testTenant1AlternateName,
              jurisdiction: 'ES',
              version: 'v1',
              sector: DataspaceSectors.HealthResearch,
            }),
            [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
              ServiceCapability.IndexProvider,
            ]),
          },
        },
      },
    ] as any);

    const response = await invokeExpress(app, {
      method: 'GET',
      url: buildGatewayDataspaceCatalogArtifactPath({
        participantId: 'host',
        jurisdiction: 'eu',
        version: 'v1',
        hostNetwork: HostNetworkTypes.Test,
      }),
      headers: { host: EXAMPLE_HOST_PUBLIC_HOSTNAME },
    });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed['dcat:dataset']).toHaveLength(1);
    expect(parsed['dcat:service']).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          '@type': 'dcat:DataService',
          'dcat:keyword': [ServiceCapability.IndexProvider],
        }),
      ]),
    );
  });

  it('should return normalized published-provider discovery DTOs for backend consumers', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: EXAMPLE_HOSTING_OPERATOR_DID } as any);
    mockTenantsCacheManager.getTenant.mockResolvedValue({
      didDocument: { id: EXAMPLE_HOSTING_OPERATOR_DID },
      claims: {
        [SchemaOrgOrganizationClaim.LegalName]: 'Host Operator Example',
        [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
        [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
        [SchemaOrgServiceClaim.AreaServed]: `ES,${EXAMPLE_COVERAGE_SCOPE_EU}`,
      },
    } as any);
    mockTenantsCacheManager.listAutodiscoverableTenants.mockResolvedValue([
      {
        didDocument: { id: testTenant1DidWebHosted },
        claims: {
          [SchemaOrgOrganizationClaim.AlternateName]: testTenant1AlternateName,
          [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_PROVIDER_LEGAL_NAME,
          [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
          [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
          [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
            alternateName: testTenant1AlternateName,
            jurisdiction: 'ES',
            version: 'v1',
            sector: DataspaceSectors.HealthResearch,
          }),
          [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
            ServiceCapability.IndexProvider,
            ServiceCapability.DigitalTwinProvider,
          ]),
        },
      },
      {
        didDocument: { id: EXAMPLE_SECONDARY_TENANT_SERVICE_DID },
        claims: {
          [SchemaOrgOrganizationClaim.AlternateName]: EXAMPLE_SECONDARY_PROVIDER_ALTERNATE_NAME,
          [SchemaOrgOrganizationClaim.LegalName]: EXAMPLE_SECONDARY_PROVIDER_LEGAL_NAME,
          [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
          [SchemaOrgServiceClaim.Category]: DataspaceSectors.HealthResearch,
          [SchemaOrgServiceClaim.Url]: buildExampleHostedTenantBaseUrl({
            alternateName: EXAMPLE_SECONDARY_PROVIDER_ALTERNATE_NAME,
            jurisdiction: 'ES',
            version: 'v1',
            sector: DataspaceSectors.HealthResearch,
          }),
          [SchemaOrgServiceClaim.ServiceType]: serializeServiceCapabilityTokens([
            ServiceCapability.IndexReader,
            ServiceCapability.DigitalTwinReader,
          ]),
        },
      },
    ] as any);

    const response = await invokeExpress(app, {
      method: 'POST',
      url: '/api/dataspace-discovery/providers',
      headers: { host: EXAMPLE_HOST_PUBLIC_HOSTNAME, 'content-type': 'application/json' },
      body: {
        sector: DataspaceSectors.HealthResearch,
        providerCapability: ServiceCapability.IndexProvider,
        jurisdiction: 'ES',
        coverageScope: EXAMPLE_COVERAGE_SCOPE_EU,
      },
    });

    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(Array.isArray(parsed.providers)).toBe(true);
    expect(parsed.providers).toHaveLength(1);
    expect(parsed.providers[0]).toEqual(
      expect.objectContaining({
        providerDid: testTenant1DidWebHosted,
        hostingOperatorDid: EXAMPLE_HOSTING_OPERATOR_DID,
        title: EXAMPLE_PROVIDER_LEGAL_NAME,
      }),
    );
    expect(parsed.providers[0].record).toEqual(
      expect.objectContaining({
        providerDid: testTenant1DidWebHosted,
        serviceType: ServiceCapability.IndexProvider,
        category: DataspaceSectors.HealthResearch,
        areaServed: 'ES',
      }),
    );
    expect(parsed.hostingOperators).toEqual([
      expect.objectContaining({
        operatorDid: EXAMPLE_HOSTING_OPERATOR_DID,
        matchedCapabilities: [ServiceCapability.IndexProvider],
      }),
    ]);
    expect(parsed.hostingOperators[0].record).toEqual(
      expect.objectContaining({
        subjectId: EXAMPLE_HOSTING_OPERATOR_DID,
        coverageScope: EXAMPLE_COVERAGE_SCOPE_EU,
      }),
    );
  });

  it('returns active public notification projections without attachment bytes or subscriber data', async () => {
    mockTenantsCacheManager.getDidDocument.mockResolvedValue({ id: EXAMPLE_HOSTING_OPERATOR_DID } as any);
    mockTenantsCacheManager.listAutodiscoverableTenants.mockResolvedValue([{
      didDocument: { id: 'did:web:clinic.example' },
      collectionName: 'clinic-collection',
      claims: {
        [SchemaOrgOrganizationClaim.AlternateName]: 'clinic',
        [SchemaOrgOrganizationClaim.Name]: 'Example clinic',
        [SchemaOrgOrganizationClaim.AddressCountry]: 'CA-BC',
        [SchemaOrgServiceClaim.Category]: 'animal-care',
      },
    }] as any);
    mockVaultRepository.listContainersInSection.mockImplementation(async (_collection: string, section: string) => section === 'care-communication-requests'
      ? [{ id: 'notice-1', content: { claims: {
        [CommunicationRequestClaim.Status]: ['active'],
        [CommunicationRequestClaim.InformationProvider]: ['Organization/clinic'],
        [CommunicationRequestClaim.Note]: ['Dog blood needed'],
        [CommunicationRequestClaim.PayloadReference]: ['DocumentReference/content-1'],
        [CommunicationRequestClaim.About]: ['DocumentReference/instructions-1'],
        [CommunicationRequestClaim.AuthoredOn]: ['2026-10-20T00:00:00.000Z'],
        [CommunicationRequestClaim.OccurrencePeriodEnd]: ['2099-10-21T00:00:00.000Z'],
        [PublicAlertOperationalClaim.DatasetName]: ['ca-bc_animal-care_public_blood-donation_dog_alert'],
      } } }]
      : section === 'organization-document-references'
        ? [{ id: 'content-1', content: { claims: {
          [DocumentReferenceClaim.ContentType]: ['text/markdown'],
          [DocumentReferenceClaim.ContentData]: [Buffer.from('Call before travelling.').toString('base64')],
        } } }]
        : [] as any);
    mockKmsService.unprotectConfidentialData.mockImplementation(async (record: any) => record.content);

    const response = await invokeExpress(app, {
      method: 'POST', url: '/api/public-notifications/search',
      headers: { host: EXAMPLE_HOST_PUBLIC_HOSTNAME, 'content-type': 'application/json' },
      body: { datasetNames: ['ca-bc_animal-care_public_blood-donation_dog_alert'] },
    });
    const parsed = JSON.parse(response.text);

    expect(response.status).toBe(200);
    expect(parsed.notifications).toEqual([expect.objectContaining({ notificationId: 'notice-1', subject: 'Dog blood needed' })]);
    expect(JSON.stringify(parsed)).not.toMatch(/contentData|subscriber|recipient/i);
  });
});
