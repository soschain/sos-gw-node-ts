// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.
import { normalizeUuid, buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { ClaimConsent, ConsentDecisions, ConsentStatuses } from 'fhir-data-utils-ts';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import type { ClinicalCreatorBinding } from 'sos-data-utils-ts/clinical-creator-contract';
import type { JobRequest } from 'sos-data-utils-ts/confidential-job';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import type { ITenantsManager } from '../managers/ITenantsManager';
import { buildGroupMemberProjectionId, buildGroupMemberSectionId } from '../managers/GroupManager';
import { canonicalPractitionerRoleFromAuthor, ORGANIZATION_WORKFLOW_CONSENT_SECTION } from '../managers/ResearchStudyConsentManager';
import { getAuthenticatedJobActorIdentifiers, isVerifiedBearerBoundToActorDid } from './authenticated-job-actor';
import { getClinicalCreatorBindingsSectionId } from './clinical-creator-binding';
import { readClaimsOnlyContent, type FlatClaims } from './fhir-flat-claims';
import { splitIndexedEmails, splitIndexedPhones } from './indexed-contact';
import { normalizeCodeSystemAndValue } from './normalize-codeAndSystem';
import { parseProfessionalDidIdentity } from './professional-did-identity';
import { hasActiveProfessionalIdentityAndLicense } from './professional-license';
import { getEnvSectionId } from './section-env';
import { getTenantVaultId } from './tenant';
import { computeJwkThumbprint, toBaseJwk } from '../gdc-backend-utils-node/jwk-thumbprint';
import type { PublicJwk } from 'antifraud-data-utils-ts/cryptography';
import { buildOrganizationAuthorizationUrnCds } from 'sos-data-utils-ts/organization-authorization-urn';
import { parseTenantUrn } from './urn';

/** Internal queued provenance, authored only by API registered-key verification. */
export type RegisteredDidcommTransportEvidence = Readonly<{
  kind: 'registered-didcomm';
  actorDid: string;
  signingKeyId: string;
  signingKeyThumbprint: string;
  /** A signed selector; current registration is checked independently below. */
  signedClientId: string;
}>;

export type IndividualRegistrationAdmission = Readonly<{
  sector: string;
  /** Self registration is bound again after document-derived claims are merged. */
  verifiedControllerIdentifiers?: readonly string[];
  /** Server-derived creation provenance; never a controller grant or a clinical consent. */
  professionalCreator?: Readonly<{
    actorDid: string;
    clientId: string;
    authorIdentifier: string;
    ownerIdentifier: string;
    role: string;
  }>;
}>;

function deny(): never {
  throw new ManagerError('Individual registration requires a verified controller or an authorized licensed professional.', IssueType.Forbidden);
}

function proposedControllerIdentifiers(claims: Record<string, unknown>): string[] {
  return [
    ...splitIndexedEmails(claims[SchemaOrgOrganizationClaim.OwnerEmail]).map(contact =>
      buildStableActorIdentifier({ contactKind: 'email', contact })),
    ...splitIndexedPhones(claims[SchemaOrgOrganizationClaim.OwnerTelephone]).map(contact =>
      buildStableActorIdentifier({ contactKind: 'phone', contact })),
  ];
}

/** Rechecks merged PDF/KYC claims so later inputs cannot replace the admitted controller or tenant. */
export function assertAdmittedIndividualRegistrationClaims(
  admission: IndividualRegistrationAdmission,
  claims: Record<string, unknown>,
): void {
  if (claims[SchemaOrgServiceClaim.Category] !== admission.sector) deny();
  if (admission.verifiedControllerIdentifiers
    && !proposedControllerIdentifiers(claims).some(value => admission.verifiedControllerIdentifiers!.includes(value))) deny();
}

/**
 * Authorizes the real queued creator before attachment retrieval or persistence.
 * Request owner contacts identify the proposed controller; they never establish
 * professional authority. OIDC verification and DIDComm signature verification
 * remain API responsibilities; this manager boundary rechecks current records.
 */
export async function admitIndividualRegistration(input: {
  job: JobRequest;
  claims: Record<string, unknown>;
  vaultRepository: IVaultRepository;
  kmsService: IKmsService;
  tenantManager: ITenantsManager;
}): Promise<IndividualRegistrationAdmission> {
  const { job, claims, vaultRepository: repository, kmsService: kms } = input;
  const sector = String(job.sector || '').trim();
  const tenantId = String(job.tenantId || '').trim();
  if (!sector || !tenantId || (claims[SchemaOrgServiceClaim.Category] && claims[SchemaOrgServiceClaim.Category] !== sector)) deny();
  const identifiers = getAuthenticatedJobActorIdentifiers(job).filter(value => !value.startsWith('did:web:'));
  if (proposedControllerIdentifiers(claims).some(value => identifiers.includes(value))) {
    return { sector, verifiedControllerIdentifiers: identifiers };
  }

  const actorDid = String(job.content?.iss || '').trim();
  const transport = (job as JobRequest & { authenticatedTransport?: RegisteredDidcommTransportEvidence }).authenticatedTransport;
  const signedClientId = String((job.content as any)?.client_id || '').trim();
  if (transport?.kind !== 'registered-didcomm' || transport.actorDid !== actorDid
    || !transport.signingKeyId || !transport.signingKeyThumbprint
    || !signedClientId || transport.signedClientId !== signedClientId) deny();
  const bearer = (job.content as any)?.meta?.bearer?.jwt?.payload;
  if (!isVerifiedBearerBoundToActorDid(bearer, actorDid)) deny();
  const identity = parseProfessionalDidIdentity(actorDid);
  if (!identity || identity.membershipMarker !== 'employee') deny();
  const tenantVaultId = getTenantVaultId(sector, tenantId);
  const tenantProviderDid = await input.tenantManager.getTenantDid(tenantVaultId);
  if (!tenantProviderDid || identity.organizationDid !== tenantProviderDid) deny();
  const tenantIdentity = parseTenantUrn(await input.tenantManager.getTenantIdentifierUrn(tenantVaultId) || '');
  if (!tenantIdentity || tenantIdentity.sector !== sector) deny();
  let expectedOrganizationOwner: string;
  try {
    expectedOrganizationOwner = buildOrganizationAuthorizationUrnCds({
      jurisdiction: tenantIdentity.jurisdiction, version: tenantIdentity.version,
      identifierType: tenantIdentity.idType, identifierValue: tenantIdentity.idValue,
    });
  } catch {
    return deny();
  }
  const collectionName = await input.tenantManager.getCollectionName(tenantVaultId);
  if (!collectionName) deny();
  const records = await repository.listContainersInSection<ClinicalCreatorBinding & { id: string }>(tenantVaultId, getClinicalCreatorBindingsSectionId());
  const bindings = records.filter(binding => binding?.kind === 'professional'
    && binding.ownerIdentifier === expectedOrganizationOwner && binding.actorDids?.includes(actorDid)
    && normalizeCodeSystemAndValue(binding.role) === normalizeCodeSystemAndValue(identity.role));
  if (bindings.length !== 1) deny();
  const binding = bindings[0];
  const clientId = String((job.content as any)?.client_id || '').trim();
  if (!clientId || !binding.dcrClientIds?.includes(clientId)) deny();
  const profileDocument = await repository.get<any>(tenantVaultId, clientId, getEnvSectionId('device-profiles'));
  if (profileDocument?.status !== 'active') deny();
  const profile = await kms.unprotectConfidentialData<any>(profileDocument, tenantVaultId);
  if (profile?.clientId !== clientId || profile.stableActorIdentifier !== identity.stableActorIdentifier
    || !normalizeUuid(binding.actorIdentifier)
    || normalizeUuid(profile.subjectId) !== normalizeUuid(binding.actorIdentifier)) deny();
  const methodIds = Array.isArray(profile.verificationMethodIds) ? profile.verificationMethodIds : [];
  if (methodIds.length > 0 && !methodIds.some((id: unknown) => typeof id === 'string'
    && id.endsWith(`#${transport.signingKeyId}`))) deny();
  const profileKeys: unknown[] = Array.isArray(profile.jwks?.keys) ? profile.jwks.keys : [];
  let matchedDeviceKey = false;
  for (const [index, candidate] of profileKeys.entries()) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) continue;
    const key = candidate as PublicJwk;
    // Preserve DeviceRegistrationManager's persisted kid/default-index profile.
    const registeredKid = String(key.kid || `device-key-${index + 1}`).trim();
    if (registeredKid !== transport.signingKeyId) continue;
    try {
      if (await computeJwkThumbprint(toBaseJwk(key)) === transport.signingKeyThumbprint) matchedDeviceKey = true;
    } catch {
      // A malformed historical key cannot supply active DCR authority.
    }
  }
  if (!matchedDeviceKey) deny();
  if (!(await hasActiveProfessionalIdentityAndLicense({
    tenantVaultId, employeeCollectionName: collectionName, identity,
    vaultRepository: repository, kmsService: kms,
  }))) deny();

  const practitioner = canonicalPractitionerRoleFromAuthor(binding.authorIdentifier);
  if (!practitioner) deny();
  const organization = `Organization/${tenantId}`;
  const consentDocuments = await repository.listContainersInSection<any>(collectionName, ORGANIZATION_WORKFLOW_CONSENT_SECTION);
  const readClaims = async (document: any): Promise<FlatClaims | undefined> => readClaimsOnlyContent(await kms.unprotectConfidentialData<unknown>(document, tenantVaultId));
  for (const document of consentDocuments) {
    const consent = await readClaims(document);
    if (!consent) continue;
    const one = (name: string) => consent[name]?.length === 1 ? consent[name][0] : undefined;
    if (one(ClaimConsent.status) !== ConsentStatuses.Active || one(ClaimConsent.decision) !== ConsentDecisions.Permit
      || one(ClaimConsent.subject) !== organization || one(ClaimConsent.grantor) !== organization
      || one(ClaimConsent.manager) !== organization || one(ClaimConsent.controller) !== organization
      || one(ClaimConsent.actorIdentifier) !== practitioner || one(ClaimConsent.grantee) !== practitioner
      || normalizeCodeSystemAndValue(one(ClaimConsent.actorRole)) !== normalizeCodeSystemAndValue(identity.role)
      || one(ClaimConsent.action) !== `organization/Subject.c?organization=${organization}`) continue;
    const start = one(ClaimConsent.periodStart);
    const end = one(ClaimConsent.periodEnd);
    if ((start && (!Number.isFinite(Date.parse(start)) || Date.parse(start) > Date.now()))
      || (end && (!Number.isFinite(Date.parse(end)) || Date.parse(end) <= Date.now()))) continue;
    const groupReference = one(ClaimConsent.sourceReference);
    if (!groupReference?.startsWith('Group/') || groupReference.slice(6).includes('/')) continue;
    const groupId = groupReference.slice(6);
    if (!groupId) continue;
    const groupDocument = await repository.get<any>(collectionName, groupId, 'research-groups');
    const group = groupDocument ? await readClaims(groupDocument) : undefined;
    if (group?.['Group.type']?.[0] !== 'practitioner' || group['Group.membership']?.[0] !== 'enumerated'
      || group['Group.managing-entity']?.[0] !== organization) continue;
    const memberDocument: any = await repository.get<any>(collectionName, buildGroupMemberProjectionId(groupId, practitioner), buildGroupMemberSectionId(groupId));
    const member: FlatClaims | undefined = memberDocument ? await readClaims(memberDocument) : undefined;
    if (member?.['Group.member']?.[0] === practitioner) return {
      sector,
      professionalCreator: {
        actorDid, clientId, authorIdentifier: binding.authorIdentifier,
        ownerIdentifier: expectedOrganizationOwner,
        role: normalizeCodeSystemAndValue(identity.role),
      },
    };
  }
  return deny();
}
