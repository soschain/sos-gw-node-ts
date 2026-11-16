// Flow contract: real individual registration admits a verified self/controller or an exact licensed, DCR-bound practitioner with active organization Subject registration Consent; all other creators are denied before document or vault writes.
import { describe, expect, it, jest } from '@jest/globals';
import { mock } from 'jest-mock-extended';
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { SchemaOrgOfferClaim, SchemaOrgOrderClaim, SchemaOrgOrganizationClaim, SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { ClaimConsent, ConsentDecisions, ConsentStatuses, HealthcareConsentPurposes } from 'fhir-data-utils-ts';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { JobStatus, type JobRequest } from 'sos-data-utils-ts/confidential-job';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { FamilyManager } from '../../../managers/FamilyManager';
import { buildGroupMemberProjectionId, buildGroupMemberSectionId } from '../../../managers/GroupManager';
import type { IVaultRepository } from '../../../database/repositories/vault/vault.repository';
import type { IStorageAdapter } from '../../../database/storage/IStorageAdapter';
import type { ILogger } from '../../../loggers/ILogger';
import { getClinicalCreatorBindingsSectionId } from '../../../utils/clinical-creator-binding';
import { getEnvSectionId } from '../../../utils/section-env';
import { GatewayClaim } from '../../../shared/gateway-claim-contract';
import { QueueAdapterMem } from '../../../adapters/queue-mem';
import { AsyncResponseStoreMem } from '../../../adapters/async-response-store.mem';
import { Worker } from '../../../worker';
import { createJobName } from '../../../utils/naming';
import { createHash } from 'node:crypto';
import { buildOrganizationAuthorizationUrnCds } from 'sos-data-utils-ts/organization-authorization-urn';
import { createOrganizationUrn } from '../../../utils/urn';

const fixture = Object.freeze({
  tenantId: SAFE.tenantId,
  sector: 'health-care',
  collection: 'isolated-registration-vault',
  roleId: SAFE.resourceUuid,
  actorId: SAFE.demoOrganizationUuids.publicHealth,
  subjectId: SAFE.demoOrganizationUuids.healthCare,
  clientId: 'registered-dentist-client',
  groupId: 'subject-registration-group',
  consentId: 'subject-registration-consent',
  creatorEmail: SAFE.firstContactEmail,
  controllerEmail: SAFE.individualEmail,
});
const organizationReference = `Organization/${fixture.tenantId}`;
const practitionerReference = `PractitionerRole/${fixture.roleId}`;
const vaultId = `${fixture.sector}_${fixture.tenantId}`;
const providerDid = `did:web:${SAFE.domain}:${fixture.tenantId}:cds-es-md:v1:${fixture.sector}`;
const stableCreator = buildStableActorIdentifier({ contactKind: 'email', contact: fixture.creatorEmail });
const professionalDid = `${providerDid}:employee:${stableCreator.replace('urn:multibase:', '')}:${encodeURIComponent(HealthcareActorRoles.Dentist)}`;
const publicSigningKey = Object.freeze({ kty: 'EC', crv: 'P-384', x: 'synthetic-x', y: 'synthetic-y' });
const signingKeyThumbprint = createHash('sha256')
  .update('{"crv":"P-384","kty":"EC","x":"synthetic-x","y":"synthetic-y"}').digest('base64url');
const tenantLegalIdentity = Object.freeze({
  jurisdiction: 'ES-MD', version: 'v1', identifierType: 'taxid', identifierValue: SAFE.organizationBusinessNumber,
});
const organizationOwnerUrn = buildOrganizationAuthorizationUrnCds(tenantLegalIdentity);
const tenantIdentifierUrn = createOrganizationUrn({
  namespace: 'cds', network: 'test-network', jurisdiction: tenantLegalIdentity.jurisdiction,
  version: tenantLegalIdentity.version, sector: fixture.sector,
  idType: tenantLegalIdentity.identifierType, idValue: tenantLegalIdentity.identifierValue,
});

type Variant = 'allowed' | 'missing-binding' | 'foreign-binding' | 'missing-dcr' | 'foreign-client'
  | 'inactive-client' | 'missing-group' | 'foreign-group' | 'missing-member' | 'missing-consent'
  | 'revoked-consent' | 'foreign-consent' | 'unlicensed' | 'inactive-employee'
  | 'self' | 'unverified-owner' | 'unrelated-owner' | 'foreign-sector' | 'foreign-provider' | 'foreign-role' | 'foreign-member'
  | 'missing-transport' | 'forged-meta-transport' | 'foreign-device-key' | 'jwks-key-only' | 'same-kid-foreign-material'
  | 'legal-owner' | 'legal-owner-public-provider';

/** Seeds authoritative adapter records; the manager and admission logic are real. */
function harness(variant: Variant = 'allowed') {
  const repository = mock<IVaultRepository>();
  const storage = mock<IStorageAdapter>();
  const logger = mock<ILogger>();
  const configuredProviderDid = variant === 'legal-owner-public-provider'
    ? `did:web:${SAFE.domain}:${fixture.sector}:organization:taxid:${SAFE.organizationBusinessNumber}` : providerDid;
  const actorDid = variant === 'foreign-sector' ? professionalDid.replace(':health-care:', ':animal-care:')
    : variant === 'foreign-provider' ? professionalDid.replace(SAFE.domain, 'another.example.invalid')
    : variant === 'legal-owner-public-provider' ? professionalDid.replace(providerDid, configuredProviderDid) : professionalDid;
  const binding = {
    id: `urn:uuid:${fixture.roleId}`, kind: 'professional',
    actorIdentifier: `urn:uuid:${fixture.actorId}`, authorIdentifier: `urn:uuid:${fixture.roleId}`,
    ownerIdentifier: variant === 'foreign-binding'
      ? buildOrganizationAuthorizationUrnCds({ ...tenantLegalIdentity, identifierValue: 'another-organization' }) : organizationOwnerUrn,
    role: variant === 'foreign-role' ? HealthcareActorRoles.Veterinarian : HealthcareActorRoles.Dentist, actorDids: [actorDid],
    dcrClientIds: variant === 'missing-dcr' ? [] : [fixture.clientId],
  };
  const consentClaims = {
    [ClaimConsent.status]: [variant === 'revoked-consent' ? ConsentStatuses.Inactive : ConsentStatuses.Active],
    [ClaimConsent.decision]: [ConsentDecisions.Permit],
    [ClaimConsent.purpose]: [HealthcareConsentPurposes.Operations],
    [ClaimConsent.subject]: [organizationReference],
    [ClaimConsent.grantor]: [organizationReference],
    [ClaimConsent.manager]: [organizationReference],
    [ClaimConsent.controller]: [organizationReference],
    [ClaimConsent.grantee]: [practitionerReference],
    [ClaimConsent.actorIdentifier]: [practitionerReference],
    [ClaimConsent.actorRole]: [HealthcareActorRoles.Dentist],
    [ClaimConsent.sourceReference]: [`Group/${fixture.groupId}`],
    [ClaimConsent.action]: [`organization/Subject.c?organization=${variant === 'foreign-consent' ? 'Organization/another-tenant' : organizationReference}`],
    [ClaimConsent.identifier]: [`urn:uuid:${fixture.consentId}`],
  };
  const document = (id: string, content: unknown) => ({ id, sequence: 0, status: 'active', content });
  repository.query.mockResolvedValue([]);
  repository.put.mockResolvedValue(true);
  repository.get.mockImplementation(async (_collection, id, section) => {
    if (section === getEnvSectionId('device-profiles') && id === fixture.clientId) {
      return { ...document(id, {
        type: 'DeviceProfile', clientId: fixture.clientId,
        subjectId: `urn:uuid:${fixture.actorId}`, stableActorIdentifier: stableCreator,
        verificationMethodIds: variant === 'jwks-key-only' ? undefined
          : [`${SAFE.didWeb}:employee:${fixture.actorId}#${variant === 'foreign-device-key' ? 'another-device-signing-key' : 'registered-dentist-signing-key'}`],
        jwks: { keys: [{ ...publicSigningKey,
          x: variant === 'same-kid-foreign-material' ? 'another-device-x' : publicSigningKey.x,
          kid: variant === 'foreign-device-key' ? 'another-device-signing-key' : 'registered-dentist-signing-key',
        }] },
      }), status: variant === 'inactive-client' ? 'inactive' : 'active' } as any;
    }
    if (section === 'research-groups' && id === fixture.groupId && variant !== 'missing-group') {
      return document(id, { claims: {
        'Group.type': ['practitioner'], 'Group.membership': ['enumerated'],
        'Group.managing-entity': [variant === 'foreign-group' ? 'Organization/another-tenant' : organizationReference],
      } }) as any;
    }
    if (section === buildGroupMemberSectionId(fixture.groupId)
      && id === buildGroupMemberProjectionId(fixture.groupId, practitionerReference) && variant !== 'missing-member') {
      return document(id, { claims: { 'Group.member': [variant === 'foreign-member' ? `PractitionerRole/${fixture.subjectId}` : practitionerReference] } }) as any;
    }
    return undefined;
  });
  repository.listContainersInSection.mockImplementation(async (_collection, section) => {
    if (section === getClinicalCreatorBindingsSectionId()) return variant === 'missing-binding' ? [] : [binding] as any;
    if (section === 'organization-workflow-consents') return variant === 'missing-consent' ? [] : [document(fixture.consentId, { claims: consentClaims })] as any;
    return [];
  });
  repository.getContainersInSection.mockImplementation(async (_collection, section) => {
    if (section === getEnvSectionId('employees')) return [document('employee', {
      status: variant === 'inactive-employee' ? 'inactive' : 'active',
      claims: { [SchemaOrgPersonClaim.Email]: fixture.creatorEmail, [SchemaOrgPersonClaim.HasOccupation]: HealthcareActorRoles.Dentist },
    })] as any;
    if (section === getEnvSectionId('device-licenses')) return variant === 'unlicensed' ? [] : [document('licence', {
      status: 'active', issuedToEmail: fixture.creatorEmail,
      issuedToRole: HealthcareActorRoles.Dentist, activatedBy: stableCreator,
    })] as any;
    return [];
  });
  const protect = jest.fn(async (record: any) => record);
  const kms = {
    unprotectConfidentialData: jest.fn(async (record: any) => record.content),
    protectConfidentialData: protect,
    protectAttributesNameAndValue: jest.fn(async (attributes: any[]) => attributes),
  };
  const manager = new FamilyManager(repository, kms as any, {
    isTenantOperational: jest.fn(async () => true),
    getCollectionName: jest.fn(async () => fixture.collection),
    getTenantDid: jest.fn(async () => configuredProviderDid),
    getTenantIdentifierUrn: jest.fn(async () => tenantIdentifierUrn),
  } as any, storage, logger, { allowedPaymentMethods: [] } as any);
  const selfLike = ['self', 'unverified-owner', 'unrelated-owner'].includes(variant);
  const job = {
    id: SAFE.resourceUuid, status: JobStatus.DRAFT, sequence: 0, createdAtTimestamp: Date.now(),
    tenantId: fixture.tenantId, jurisdiction: 'ES-MD', sector: fixture.sector,
    section: 'individual', format: 'org.schema', action: '_batch', resourceType: 'Organization',
    content: {
      jti: SAFE.resourceUuid, thid: SAFE.resourceUuid, iss: selfLike ? `${SAFE.didWeb}:individual` : actorDid,
      aud: SAFE.didWeb, type: 'application/api+json',
      client_id: variant === 'foreign-client' ? 'another-client' : fixture.clientId,
      meta: { bearer: { jwt: { payload: {
        sub: 'verified-account', email_verified: variant !== 'unverified-owner',
        email: variant === 'self' || variant === 'unverified-owner' ? fixture.controllerEmail : fixture.creatorEmail,
      } } } },
      body: { data: [{ type: 'Family-registration-form-v1.0', resource: {
        resourceType: 'Organization', meta: { claims: {
          [SchemaOrgOrganizationClaim.IdentifierValue]: fixture.subjectId,
          [SchemaOrgOrganizationClaim.AlternateName]: SAFE.individualGivenName,
          [SchemaOrgOrganizationClaim.OwnerEmail]: fixture.controllerEmail,
          [SchemaOrgPersonClaim.BirthDate]: '2022',
          [SchemaOrgServiceClaim.Category]: fixture.sector,
          [SchemaOrgServiceClaim.TermsOfService]: SAFE.httpsBaseUrl,
        } },
      } }] },
    },
  } as unknown as JobRequest;
  if (variant !== 'missing-transport' && variant !== 'forged-meta-transport') {
    (job as any).authenticatedTransport = {
      kind: 'registered-didcomm', actorDid, signingKeyId: 'registered-dentist-signing-key',
      signedClientId: (job.content as any).client_id, signingKeyThumbprint,
    };
  }
  if (variant === 'forged-meta-transport') {
    (job.content as any).meta.authenticatedTransport = {
      kind: 'registered-didcomm', actorDid, signingKeyId: 'registered-dentist-signing-key',
      signedClientId: fixture.clientId, signingKeyThumbprint,
    };
  }
  return { manager, job, repository, protect, storage, vaultId };
}

/** Keeps section writes readable for a real Offer -> Order lifecycle, including issued seats. */
async function pendingOrderHarness(verifiedRecipient: boolean) {
  const state = harness('self');
  const sections = new Map<string, Map<string, any>>();
  const section = (collection: string, sectionId?: string) => {
    const key = JSON.stringify([collection, sectionId]);
    if (!sections.has(key)) sections.set(key, new Map());
    return sections.get(key)!;
  };
  const readRows = (collection: string, sectionId: string) =>
    [...section(collection, sectionId).values()].map(row => structuredClone(row));
  state.repository.put.mockImplementation(async (collection, rows, sectionId) => {
    for (const row of rows) section(collection, sectionId).set(row.id, structuredClone(row));
    return true;
  });
  state.repository.get.mockImplementation(async (collection, id, sectionId) => {
    const row = section(collection, sectionId).get(id);
    return row ? structuredClone(row) : undefined;
  });
  state.repository.getContainersInSection.mockImplementation(async (collection, sectionId) => readRows(collection, sectionId));
  state.repository.listContainersInSection.mockImplementation(async (collection, sectionId) => readRows(collection, sectionId));
  state.repository.query.mockImplementation(async (collection, query) => readRows(collection, query.sectionId!).filter(row =>
    ((query as any).where || []).every((condition: any) => row.content?.claims?.[condition.name] === condition.value
      || row.indexed?.attributes?.some((attribute: any) => attribute.name === condition.name && attribute.value === condition.value))));
  const registration = await state.manager.process(state.job);
  const receipt = (registration.body as any).data[0];
  expect(receipt.response.status).toBe('201');
  const offerId = receipt.resource.meta.claims[SchemaOrgOfferClaim.Identifier];
  expect(offerId).toEqual(expect.any(String));
  const order = structuredClone(state.job);
  order.resourceType = 'Order';
  if (!verifiedRecipient) (order.content as any).iss = professionalDid;
  (order.content as any).meta.bearer.jwt.payload = {
    sub: verifiedRecipient ? 'verified-controller-account' : 'verified-unrelated-account',
    email: verifiedRecipient ? fixture.controllerEmail : fixture.creatorEmail, email_verified: true,
  };
  (order.content as any).body.data = [{ type: 'Family-order-request-v1.0', resource: {
    resourceType: 'Order', meta: { claims: { [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId } },
  } }];
  state.repository.put.mockClear();
  state.protect.mockClear();
  return { ...state, order, readRows, receipt };
}

describe('FamilyManager professional registration admission', () => {
  it.each(['legal-owner', 'legal-owner-public-provider'] as const)('admits the actual EmployeeManager owner URN profile with %s', async (variant) => {
    const state = harness(variant);
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect(state.repository.put).toHaveBeenCalledTimes(1);
  });

  it('binds a contact declared by existing KYC metadata to the verified controller before completing missing claims', async () => {
    const state = harness('self');
    const entry = (state.job.content as any).body.data[0];
    delete entry.resource.meta.claims[SchemaOrgOrganizationClaim.OwnerEmail];
    entry.meta = { kyc: {
      controllerEmail: fixture.controllerEmail, individualAlternateName: SAFE.individualGivenName,
      profile: { first_name: SAFE.individualGivenName, last_name: SAFE.personFamilyName, kyc_verified_at: '2026-11-01T12:00:00.000Z' },
    } };
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect((response.body as any).data[0].resource.meta.claims[SchemaOrgOrganizationClaim.OwnerEmail]).toBe(fixture.controllerEmail);
    expect(state.repository.put).toHaveBeenCalledTimes(1);
  });

  it('denies a forged proposed KYC controller before retrieving its proof attachment', async () => {
    const state = harness('self');
    const entry = (state.job.content as any).body.data[0];
    delete entry.resource.meta.claims[SchemaOrgOrganizationClaim.OwnerEmail];
    entry.meta = { kyc: { controllerEmail: fixture.creatorEmail } };
    (state.job.content as any).attachments = [{ id: 'proof', media_type: 'application/pdf', data: { links: [`${SAFE.httpsBaseUrl}/proof.pdf`] } }];
    const download = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unauthorized proof must not be retrieved.'));
    try {
      const response = await state.manager.process(state.job);
      expect((response.body as any).data[0].response.status).toBe('403');
      expect(download).not.toHaveBeenCalled();
      expect(state.repository.put).not.toHaveBeenCalled();
    } finally {
      download.mockRestore();
    }
  });

  it('rechecks controller binding after KYC metadata attempts to replace an admitted owner', async () => {
    const state = harness('self');
    (state.job.content as any).body.data[0].meta = { kyc: {
      controllerEmail: fixture.creatorEmail, individualAlternateName: SAFE.individualGivenName,
      profile: { first_name: SAFE.firstContactGivenName, last_name: SAFE.personFamilyName, kyc_verified_at: '2026-11-01T12:00:00.000Z' },
    } };
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('403');
    expect(state.protect).not.toHaveBeenCalled();
    expect(state.repository.put).not.toHaveBeenCalled();
  });

  it('requires the actual proposed controller to confirm a pending Offer before the first activation write', async () => {
    const state = await pendingOrderHarness(false);
    const response = await state.manager.process(state.order);
    expect((response.body as any).data[0].response.status).toBe('403');
    expect(state.protect).not.toHaveBeenCalled();
    expect(state.repository.put).not.toHaveBeenCalled();
  });

  it('allows the verified proposed controller to confirm and persists its distinct responsibility assignment', async () => {
    const state = await pendingOrderHarness(true);
    const response = await state.manager.process(state.order);
    const entries = (response.body as any).data;
    expect(entries[0].response.status).toBe('201');
    expect(entries).toEqual(expect.arrayContaining([expect.objectContaining({
      resource: expect.objectContaining({ resourceType: 'RelatedPerson' }), response: { status: '201' },
    })]));
    const individual = state.readRows(fixture.collection, getEnvSectionId('individual'))[0];
    expect(individual.content.status).toBe('active');
    expect(state.readRows(vaultId, getEnvSectionId('device-licenses'))).toEqual(expect.arrayContaining([
      expect.objectContaining({ content: expect.objectContaining({ issuedToEmail: fixture.controllerEmail, status: 'issued' }) }),
    ]));
  });

  it.each([true, false])('keeps active Order replay bound to the same verified controller=%s', async (verifiedRecipient) => {
    const state = await pendingOrderHarness(true);
    const confirmation = await state.manager.process(state.order);
    expect((confirmation.body as any).data[0].response.status).toBe('201');
    const assignmentId = (confirmation.body as any).data[1].resource.id;
    state.repository.put.mockClear();
    state.protect.mockClear();
    if (!verifiedRecipient) {
      (state.order.content as any).iss = professionalDid;
      (state.order.content as any).meta.bearer.jwt.payload.email = fixture.creatorEmail;
    }
    const replay = await state.manager.process(state.order);
    expect((replay.body as any).data[0].response.status).toBe(verifiedRecipient ? '200' : '403');
    if (verifiedRecipient) expect((replay.body as any).data[1].resource.id).toBe(assignmentId);
    expect(state.repository.put).not.toHaveBeenCalled();
    expect(state.protect).not.toHaveBeenCalled();
  });

  it.each(['allowed', 'missing-transport'] as const)('preserves %s provenance through JSON, the real memory queue and worker into registration admission', async (variant) => {
    const state = harness(variant);
    const request = JSON.parse(JSON.stringify(state.job)) as JobRequest;
    const responseStore = new AsyncResponseStoreMem();
    // Isolate response cryptography I/O; manager authorization and queue/worker execution remain real.
    const encodeResponse = jest.fn(async (_payload: any) => 'protected-worker-response');
    const worker = new Worker({ familyManager: state.manager } as any, SAFE.httpsBaseUrl, {
      getPublicEncryptionKey: jest.fn(async () => ({ kty: 'EC', kid: 'synthetic-response-key' })),
      encodeResponse,
    } as any);
    const queue = new QueueAdapterMem(responseStore, worker);
    try {
      await queue.addJob(createJobName(vaultId, 'Organization', '_batch'), request);
      await queue.waitForEmptyQueue();
      const response = encodeResponse.mock.calls[0][0];
      expect(response.body.data[0].response.status).toBe(variant === 'allowed' ? '201' : '403');
      expect(state.repository.put).toHaveBeenCalledTimes(variant === 'allowed' ? 1 : 0);
      expect(await responseStore.get(request.content!.thid)).toMatchObject({ status: 'COMPLETED', result: 'protected-worker-response' });
    } finally {
      queue.stop();
    }
  });

  it('allows the licensed dentist only with exact organization Group and active registration Consent', async () => {
    const state = harness();
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect(state.repository.put).toHaveBeenCalledTimes(1);
    expect(state.repository.put).toHaveBeenCalledWith(fixture.collection, expect.any(Array), getEnvSectionId('individual'));
  });

  it('preserves the existing JWKS key lookup when a registered profile has no method ID projection', async () => {
    const state = harness('jwks-key-only');
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect(state.repository.put).toHaveBeenCalledTimes(1);
  });

  it.each<Variant>([
    'missing-binding', 'foreign-binding', 'missing-dcr', 'foreign-client', 'inactive-client',
    'missing-group', 'foreign-group', 'missing-member', 'missing-consent', 'revoked-consent',
    'foreign-consent', 'unlicensed', 'inactive-employee', 'unverified-owner', 'unrelated-owner',
    'foreign-sector', 'foreign-provider', 'foreign-role', 'foreign-member',
    'missing-transport', 'forged-meta-transport',
    'foreign-device-key',
    'same-kid-foreign-material',
  ])('denies %s before the first protected write', async (variant) => {
    const state = harness(variant);
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('403');
    expect(state.protect).not.toHaveBeenCalled();
    expect(state.repository.put).not.toHaveBeenCalled();
    expect(state.storage.upload).not.toHaveBeenCalled();
  });

  it('preserves a separately verified proposed controller self-registration without employment', async () => {
    const state = harness('self');
    state.repository.listContainersInSection.mockResolvedValue([]);
    state.repository.getContainersInSection.mockResolvedValue([]);
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect(state.repository.put).toHaveBeenCalledTimes(1);
  });

  it('rejects an unauthorized creator before resolving a remote proof document', async () => {
    const state = harness('missing-consent');
    (state.job.content as any).attachments = [{
      id: 'subject-proof', media_type: 'application/pdf',
      data: { links: [`${SAFE.httpsBaseUrl}/proof.pdf`] },
    }];
    const download = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Document I/O must not start before admission.'));
    try {
      const response = await state.manager.process(state.job);
      expect((response.body as any).data[0].response.status).toBe('403');
      expect(download).not.toHaveBeenCalled();
      expect(state.repository.put).not.toHaveBeenCalled();
    } finally {
      download.mockRestore();
    }
  });

  it('returns the server-derived canonical Organization DID independently of a caller-selected public alias', async () => {
    const baseline = harness('self');
    const first = await baseline.manager.process(baseline.job);
    const canonical = (first.body as any).data[0].resource.meta.claims[SchemaOrgOrganizationClaim.SameAs];
    expect(canonical).toMatch(/^did:web:/);
    const state = harness('self');
    const claims = (state.job.content as any).body.data[0].resource.meta.claims;
    const alias = `${SAFE.didWeb}:public-card-alias`;
    claims[SchemaOrgOrganizationClaim.SameAs] = alias;
    claims[GatewayClaim.OrganizationDid] = `${SAFE.didWeb}:forged-subject`;
    const response = await state.manager.process(state.job);
    const returned = (response.body as any).data[0].resource.meta.claims;
    expect(returned[GatewayClaim.OrganizationDid]).toBe(canonical);
    expect(returned[SchemaOrgOrganizationClaim.SameAs]).toBe(alias);
    const stored = (state.repository.put.mock.calls[0][1][0] as any).content.claims;
    expect(stored[GatewayClaim.OrganizationDid]).toBe(canonical);
  });

  it.each([
    ['pending', 'id'], ['active', 'id'], ['pending', 'email'], ['active', 'email'], ['pending', 'phone'], ['active', 'phone'],
  ])('replaces forged canonical DID on %s replay found by %s using the actual stored row', async (status, lookup) => {
    const baseline = harness('self');
    const first = await baseline.manager.process(baseline.job);
    const expected = (first.body as any).data[0].resource.meta.claims[GatewayClaim.OrganizationDid];
    expect(expected).toMatch(/^did:web:/);
    const stored = baseline.repository.put.mock.calls[0][1][0] as any;
    stored.content.status = status;
    stored.content.claims[GatewayClaim.OrganizationDid] = `${SAFE.didWeb}:historic-forgery`;
    const state = harness('self');
    const originalGet = state.repository.get.getMockImplementation()!;
    state.repository.get.mockImplementation(async (collection, id, section) => {
      if (section === getEnvSectionId('individual') && id === stored.id) return stored;
      return originalGet(collection, id, section);
    });
    const incoming = (state.job.content as any).body.data[0].resource.meta.claims;
    incoming[GatewayClaim.OrganizationDid] = `${SAFE.didWeb}:incoming-forgery`;
    if (lookup !== 'id') {
      delete incoming[SchemaOrgOrganizationClaim.IdentifierValue];
      state.repository.query.mockResolvedValue([stored]);
    }
    if (lookup === 'phone') {
      incoming[SchemaOrgOrganizationClaim.OwnerTelephone] = SAFE.phoneE164;
      stored.content.claims[SchemaOrgOrganizationClaim.OwnerTelephone] = SAFE.phoneE164;
    }
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0]).toMatchObject({ response: { status: '200' } });
    expect((response.body as any).data[0].resource.meta.claims[GatewayClaim.OrganizationDid]).toBe(expected);
    if (status === 'pending' && lookup === 'id') {
      expect((state.repository.put.mock.calls[0][1][0] as any).content.claims[GatewayClaim.OrganizationDid]).toBe(expected);
    }
  });
});
