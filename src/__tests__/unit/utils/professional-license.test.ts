// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { ClaimConsent } from "fhir-data-utils-ts/claims";
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { LICENSE_STATUS_ACTIVE } from '../../../constants/domain';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { hasActiveProfessionalIdentityAndLicense } from '../../../utils/professional-license';
import {
  RESEARCH_STUDY_ACCESS_FIXTURE as fixture,
  RESEARCH_STUDY_REVIEWER_EMAIL,
  buildResearchStudyAccessClaims,
} from '../../data/research-study-access.data';

const reviewerRole = buildResearchStudyAccessClaims()[ClaimConsent.actorRole][0];
const reviewerStableIdentifier = buildStableActorIdentifier({
  contactKind: 'email',
  contact: RESEARCH_STUDY_REVIEWER_EMAIL,
});
const phoneStableIdentifier = buildStableActorIdentifier({ contactKind: 'phone', contact: SAFE.phoneE164 });

describe('active professional identity and protected licence verification', () => {
  it('recognizes an active phone-only professional and its explicitly phone-bound licence', async () => {
    const harness = createHarness({}, undefined, true);
    await expect(hasActiveProfessionalIdentityAndLicense(harness.input)).resolves.toBe(true);
  });

  it.each([
    ['inactive', { status: 'inactive' }],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 1 }],
    ['foreign role', { issuedToRole: 'ISCO-08|2261' }],
    ['foreign phone', { issuedToPhone: SAFE.firstContactPhoneE164 }],
    ['foreign contact-kind binding', { activatedBy: reviewerStableIdentifier }],
    ['missing stable binding', { activatedBy: undefined }],
    ['email-only licence', { issuedToPhone: undefined, issuedToEmail: RESEARCH_STUDY_REVIEWER_EMAIL }],
  ])('denies a phone-only professional licence with %s', async (_caseName, overrides) => {
    const harness = createHarness(overrides, undefined, true);
    await expect(hasActiveProfessionalIdentityAndLicense(harness.input)).resolves.toBe(false);
  });

  it('denies a phone-only professional whose Employee identity is inactive', async () => {
    const harness = createHarness({}, undefined, true, 'inactive');
    await expect(hasActiveProfessionalIdentityAndLicense(harness.input)).resolves.toBe(false);
  });

  it('decrypts every licence with the tenant vault id and skips an unreadable document before a valid match', async () => {
    const corruptLicenseDocument = { id: 'corrupt-license', jwe: { ciphertext: 'corrupt' } };
    const validLicenseDocument = { id: 'valid-license', jwe: { ciphertext: 'valid' } };
    const harness = createHarness({}, [corruptLicenseDocument, validLicenseDocument]);

    await expect(hasActiveProfessionalIdentityAndLicense(harness.input)).resolves.toBe(true);

    expect(harness.unprotectConfidentialData).toHaveBeenCalledWith(corruptLicenseDocument, fixture.vaultId);
    expect(harness.unprotectConfidentialData).toHaveBeenCalledWith(validLicenseDocument, fixture.vaultId);
  });

  it.each([
    ['inactive status', { status: 'inactive' }],
    ['expired timestamp', { exp: Math.floor(Date.now() / 1000) - 1 }],
    ['different role', { issuedToRole: 'ISCO-08|2211' }],
    ['different email', { issuedToEmail: 'another@example.test' }],
    ['different stable binding', { activatedBy: 'urn:multibase:different' }],
  ])('fails closed for a protected licence with %s', async (_caseName, licenseOverrides) => {
    const harness = createHarness(licenseOverrides);

    await expect(hasActiveProfessionalIdentityAndLicense(harness.input)).resolves.toBe(false);
  });
});

function createHarness(
  licenseOverrides: Record<string, unknown> = {},
  licenseDocuments: any[] = [{ id: 'valid-license', jwe: { ciphertext: 'valid' } }],
  phoneOnly = false,
  employeeStatus: string = LICENSE_STATUS_ACTIVE,
) {
  const employeeDocument = { id: 'active-employee', jwe: { ciphertext: 'employee' } };
  const validLicense = {
    status: LICENSE_STATUS_ACTIVE,
    exp: Math.floor(Date.now() / 1000) + 3600,
    issuedToRole: reviewerRole,
    ...(phoneOnly ? { issuedToPhone: SAFE.phoneE164 } : { issuedToEmail: RESEARCH_STUDY_REVIEWER_EMAIL }),
    activatedBy: phoneOnly ? phoneStableIdentifier : reviewerStableIdentifier,
    ...licenseOverrides,
  };
  const unprotectConfidentialData = jest.fn(async (document: any, tenantVaultId: string) => {
    expect(tenantVaultId).toBe(fixture.vaultId);
    if (document === employeeDocument) return {
      status: employeeStatus,
      claims: {
        ...(phoneOnly ? { [SchemaOrgPersonClaim.Telephone]: SAFE.phoneE164 }
          : { [SchemaOrgPersonClaim.Email]: RESEARCH_STUDY_REVIEWER_EMAIL }),
        [SchemaOrgPersonClaim.HasOccupation]: reviewerRole,
      },
    };
    if (document?.jwe?.ciphertext === 'corrupt') throw new Error('licence cannot be decrypted');
    return validLicense;
  });
  const getContainersInSection = jest.fn(async (_collection: string, section: string) => (
    section.includes('employees') ? [employeeDocument] : licenseDocuments
  ));
  return {
    input: {
      tenantVaultId: fixture.vaultId,
      employeeCollectionName: fixture.collectionName,
      identity: { stableActorIdentifier: phoneOnly ? phoneStableIdentifier : reviewerStableIdentifier, role: reviewerRole },
      vaultRepository: { getContainersInSection } as any,
      kmsService: { unprotectConfidentialData } as any,
    },
    unprotectConfidentialData,
  };
}
