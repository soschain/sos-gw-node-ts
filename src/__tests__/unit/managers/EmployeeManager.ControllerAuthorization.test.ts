// Flow contract: only the current tenant controller may mutate staff; a licensed professional, foreign controller, forged issuer or body role cannot create keys, consume seats or purge employees.
import { describe, expect, it, jest } from '@jest/globals';
import { mock } from 'jest-mock-extended';
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { JobStatus, type JobRequest } from 'sos-data-utils-ts/confidential-job';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { EmployeeManager } from '../../../managers/EmployeeManager';
import type { IVaultRepository } from '../../../database/repositories/vault/vault.repository';
import { createOrganizationUrn } from '../../../utils/urn';
import { hasActiveProfessionalIdentityAndLicense } from '../../../utils/professional-license';

const providerDid = `${SAFE.didWeb}:cds-es-md:v1:health-care`;
const tenantUrn = createOrganizationUrn({ namespace: 'cds', network: 'test-network', jurisdiction: 'ES-MD',
  sector: 'health-care', idType: 'taxid', idValue: SAFE.organizationBusinessNumber });
const actorDid = (contact: string, kind: 'email' | 'phone', role: string) =>
  `${providerDid}:employee:${buildStableActorIdentifier({ contactKind: kind, contact }).replace('urn:multibase:', '')}:${encodeURIComponent(role)}`;
const doctorDid = actorDid(SAFE.individualEmail, 'email', HealthcareActorRoles.Dentist);
const controllerDid = actorDid(SAFE.firstContactEmail, 'email', HealthcareActorRoles.Controller);
const phoneControllerDid = actorDid(SAFE.phoneE164, 'phone', HealthcareActorRoles.Controller);

type Scenario = 'email-controller' | 'phone-controller' | 'professional' | 'foreign-controller'
  | 'missing-controller' | 'spoofed-controller';

/** Real manager and persistence boundary; only storage/key I/O is isolated. */
function createHarness(scenario: Scenario, mutation: 'create' | 'purge' = 'create') {
  const repository = mock<IVaultRepository>();
  const protect = jest.fn(async (document: any) => document);
  const provisionKeys = jest.fn();
  const kms = { protectConfidentialData: protect, provisionKeys,
    unprotectConfidentialData: jest.fn(async (document: any) => document.content),
    protectAttributesNameAndValue: jest.fn(async (attributes: any[]) => attributes),
  };
  repository.query.mockResolvedValue([]);
  repository.put.mockResolvedValue(true);
  repository.getContainersInSection.mockImplementation(async (_collection, section) => section.includes('employees') ? [{
    id: SAFE.demoOrganizationUuids.publicHealth, sequence: 0, content: { status: 'active', claims: {
      [SchemaOrgPersonClaim.Email]: SAFE.individualEmail, [SchemaOrgPersonClaim.HasOccupation]: HealthcareActorRoles.Dentist,
    } },
  }] as any : [{ id: 'available-staff-seat', sequence: 0, content: {
    id: 'available-staff-seat', status: 'available', userClass: 'employee',
  } }, { id: 'active-dentist-licence', sequence: 0, content: {
    status: 'active', userClass: 'employee', exp: Math.floor(Date.now() / 1000) + 3600,
    issuedToEmail: SAFE.individualEmail, issuedToRole: HealthcareActorRoles.Dentist,
    activatedBy: buildStableActorIdentifier({ contactKind: 'email', contact: SAFE.individualEmail }),
  } }] as any);
  const claims = { [SchemaOrgPersonClaim.Email]: SAFE.individualEmail, [SchemaOrgPersonClaim.HasOccupation]: HealthcareActorRoles.Dentist };
  repository.get.mockResolvedValue({ id: SAFE.resourceUuid, sequence: 0, status: 'inactive', content: {
    id: SAFE.resourceUuid, type: 'Person', status: 'inactive', claims,
  } } as any);
  const sender = scenario === 'email-controller' || scenario === 'missing-controller' || scenario === 'spoofed-controller' ? controllerDid
    : scenario === 'phone-controller' ? phoneControllerDid
      : scenario === 'foreign-controller' ? controllerDid.replace(SAFE.tenantId, 'another-tenant') : doctorDid;
  const verifiedPrincipal = scenario === 'phone-controller'
    ? { sub: 'verified-phone-controller', phone_number: SAFE.phoneE164, phone_number_verified: true }
    : { sub: 'verified-email-account', email_verified: true,
      email: scenario === 'professional' || scenario === 'spoofed-controller' ? SAFE.individualEmail : SAFE.firstContactEmail };
  const job = {
    id: SAFE.resourceUuid, status: JobStatus.DRAFT, sequence: 0, createdAtTimestamp: Date.now(),
    tenantId: SAFE.tenantId, sector: 'health-care', jurisdiction: 'ES-MD',
    section: 'entity', format: 'org.schema', resourceType: 'Employee', action: mutation === 'purge' ? '_purge' : '_batch',
    contentType: 'application/x-www-form-urlencoded',
    content: { iss: sender, aud: providerDid, jti: SAFE.resourceUuid, thid: SAFE.resourceUuid, type: 'application/api+json', client_id: 'registered-controller-client',
      meta: { bearer: { jwt: { payload: verifiedPrincipal } },
        jws: { protected: { kid: 'registered-signing-key', jwk: { kty: 'EC', crv: 'P-384', x: 'synthetic-x', y: 'synthetic-y', kid: 'registered-signing-key' } } },
        jwe: { header: { jwk: { kty: 'OKP', crv: 'ML-KEM-768', x: 'synthetic-enc', kid: 'registered-encryption-key' } } },
      },
      body: { data: [{ type: 'Employee-form-v1.0', request: { method: 'POST' }, resource: {
        resourceType: 'Employee', id: SAFE.resourceUuid, meta: { claims },
      } }] },
    },
  } as unknown as JobRequest;
  const tenantManager = {
    getTenantIdentifierUrn: jest.fn(async () => tenantUrn), getCollectionName: jest.fn(async () => 'isolated-staff-vault'),
    getDidDocument: jest.fn(async () => scenario === 'missing-controller' ? undefined
      : { id: providerDid, controller: [scenario === 'phone-controller' ? phoneControllerDid : controllerDid] }),
  };
  const manager = new EmployeeManager(repository, kms as any, tenantManager as any,
    { addVerificationMethodToTenant: jest.fn() } as any, { hostCollectionName: 'isolated-host-vault', hostDid: SAFE.didWeb });
  return { manager, job, repository, protect, provisionKeys, kms };
}

describe('EmployeeManager controller-only staff mutations', () => {
  it.each(['email-controller', 'phone-controller'] as const)('allows the current %s to create a staff member', async scenario => {
    const state = createHarness(scenario);
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('201');
    expect(response.aud).toBe(state.job.content!.iss);
    expect(state.repository.put).toHaveBeenCalled();
  });

  it.each(['professional', 'foreign-controller', 'missing-controller', 'spoofed-controller'] as const)(
    'denies %s before staff identity or seat writes', async scenario => {
      const state = createHarness(scenario);
      if (scenario === 'professional') await expect(hasActiveProfessionalIdentityAndLicense({
        tenantVaultId: `health-care_${SAFE.tenantId}`, employeeCollectionName: 'isolated-staff-vault',
        identity: { stableActorIdentifier: buildStableActorIdentifier({ contactKind: 'email', contact: SAFE.individualEmail }), role: HealthcareActorRoles.Dentist },
        vaultRepository: state.repository, kmsService: state.kms as any,
      })).resolves.toBe(true);
      const response = await state.manager.process(state.job);
      expect((response.body as any).data[0].response.status).toBe('403');
      expect(state.protect).not.toHaveBeenCalled();
      expect(state.provisionKeys).not.toHaveBeenCalled();
      expect(state.repository.put).not.toHaveBeenCalled();
    },
  );

  it('does not let a professional purge staff by knowing a private record UUID', async () => {
    const state = createHarness('professional', 'purge');
    const response = await state.manager.process(state.job);
    expect((response.body as any).data[0].response.status).toBe('403');
    expect(state.repository.put).not.toHaveBeenCalled();
  });
});
