import type { IncludedResource } from 'sos-data-utils-ts/bundle-contract';
import type { PublicJwk } from 'antifraud-data-utils-ts/cryptography';
import type { GatewayDidDocument as DidDocument } from 'sos-data-utils-ts/gateway-did-profile';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { GatewayParameterData } from 'sos-data-utils-ts/gateway-parameter-contract';
import type { JwkSet } from 'antifraud-data-utils-ts/cryptography';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { buildOrganizationEmployeeDidWeb, buildStableActorIdentifier, normalizeActorContact, type ActorContactInput } from 'antifraud-data-utils-ts/organization-identity';
import { normalizeControllerAlias } from 'antifraud-data-utils-ts/public-aliases';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import { EntityLifecycleStatus, EntityType } from '../../gdc-backend-utils-node/models/enums';
import type { EntityConfig } from '../../gdc-backend-utils-node/models/entity';
import type { IKmsService } from '../../gdc-backend-utils-node/models/IKmsService';
import type { IVaultRepository } from '../../database/repositories/vault/vault.repository';
import { normalizeCodeSystemAndValue } from '../../utils/normalize-codeAndSystem';
import { getPersonOccupationClaim } from '../../utils/occupation';
import { normalizeIndexedEmail, normalizeIndexedPhone } from '../../utils/indexed-contact';
import { getEnvSectionId } from '../../utils/section-env';
import { createEmployeeUrn, createEmployeeUrnFromStableActorIdentifier, createOrganizationUrn, parseTenantUrn } from '../../utils/urn';
import { populateDidDocumentFromJwks } from '../../utils/did-backend';

export type ActivationParticipantMaterialLike = Readonly<{
  did?: string;
  sameAs?: string;
  publicKeyJwk?: PublicJwk;
  jwks?: JwkSet;
}>;

export type ControllerRegistrationKeys = Readonly<{
  signerJwk?: PublicJwk;
  encrypterJwk?: PublicJwk;
}>;

type BuildControllerEntityConfigDeps = Readonly<{
  legalRep: IncludedResource;
  tenantUrn: string;
  hostedTenantDid: string;
  kmsService: IKmsService;
  mergeActivationJwks: (keys: Array<PublicJwk | undefined>, jwks?: JwkSet) => JwkSet;
  findJwkByUse: (jwks: JwkSet | undefined, use: 'sig' | 'enc') => PublicJwk | undefined;
  isSignatureJwk: (key: PublicJwk) => boolean;
  isEncryptionJwk: (key: PublicJwk) => boolean;
  registrationKeys?: ControllerRegistrationKeys;
  explicitBinding?: ActivationParticipantMaterialLike;
}>;

type StoreControllerEntityConfigDeps = Readonly<{
  controllerConfig: EntityConfig;
  tenantCollectionName: string;
  vaultId: string;
  kmsService: IKmsService;
  vaultRepository: IVaultRepository;
  bootstrapLifecycleRole: string;
}>;

/** Preserve the existing primary-email selection; telephone-only identities
 * use a separate typed channel rather than an email-shaped placeholder. */
export function readBootstrapControllerContact(claims: Readonly<Record<string, unknown>> | undefined): ActorContactInput | undefined {
  const email = normalizeIndexedEmail(claims?.[SchemaOrgPersonClaim.Email]);
  if (email) return { contactKind: 'email', contact: email };
  const telephone = claims?.[SchemaOrgPersonClaim.Telephone];
  if (typeof telephone !== 'string' || !telephone.trim()) return undefined;
  try {
    return { contactKind: 'phone', contact: normalizeActorContact({ contactKind: 'phone', contact: telephone }) };
  } catch {
    throw new ManagerError('Controller telephone must use E.164.', IssueType.Value);
  }
}

/**
 * Builds the synthetic bootstrap controller employee used during tenant
 * onboarding.
 *
 * Legacy identity contract: `legalRep` is the actor that registered the
 * organization and owns the supplied JWK. A different technical controller
 * merely designated in signed organization evidence is not built here and
 * must later bind its own JWK through the sector `_issue` and DCR flow.
 *
 * Required input claims on `legalRep.meta.claims`:
 * - `Person.email` or `Person.telephone`
 * - `Person.hasOccupation`
 */
export async function buildControllerEntityConfig(
  deps: BuildControllerEntityConfigDeps,
): Promise<EntityConfig> {
  const contact = readBootstrapControllerContact(deps.legalRep.meta?.claims);
  const roleCode = getPersonOccupationClaim(deps.legalRep.meta?.claims as Record<string, any> | undefined);
  if (!contact || !roleCode) {
    throw new ManagerError('Missing required admin Person claims (email or telephone, hasOccupation).', IssueType.Required);
  }

  const parsedTenantUrn = parseTenantUrn(deps.tenantUrn);
  if (!parsedTenantUrn) {
    throw new ManagerError(`Invalid tenant URN format: '${deps.tenantUrn}'`, IssueType.Value);
  }
  if (!deps.hostedTenantDid.startsWith('did:web:')) {
    throw new ManagerError(`Invalid hosted tenant DID: '${deps.hostedTenantDid}'`, IssueType.Value);
  }

  const organizationUrnParams = {
    namespace: parsedTenantUrn.namespace,
    network: parsedTenantUrn.network,
    jurisdiction: parsedTenantUrn.jurisdiction,
    version: parsedTenantUrn.version,
    sector: parsedTenantUrn.sector,
    idType: parsedTenantUrn.idType,
    idValue: parsedTenantUrn.idValue,
  };
  const employeeUrn = contact.contactKind === 'email'
    ? createEmployeeUrn({ ...organizationUrnParams, email: contact.contact, role: roleCode })
    : createEmployeeUrnFromStableActorIdentifier({
      organizationUrn: createOrganizationUrn(organizationUrnParams),
      stableActorIdentifier: buildStableActorIdentifier(contact), role: roleCode,
    });

  let signerJwk = deps.explicitBinding?.publicKeyJwk
    || deps.findJwkByUse(deps.explicitBinding?.jwks, 'sig')
    || deps.registrationKeys?.signerJwk;
  let encrypterJwk = deps.findJwkByUse(deps.explicitBinding?.jwks, 'enc')
    || deps.registrationKeys?.encrypterJwk;
  if (!signerJwk || !encrypterJwk) {
    const provisioned = await deps.kmsService.provisionKeys(employeeUrn);
    signerJwk = signerJwk || provisioned.keys.find((key) => (key as any).kty === 'AKP') as PublicJwk | undefined;
    encrypterJwk = encrypterJwk || provisioned.keys.find((key) => (key as any).kty === 'OKP') as PublicJwk | undefined;
  }
  if (!signerJwk?.kid || !encrypterJwk?.kid) {
    throw new ManagerError('Admin keys are missing "kid" properties.', IssueType.Required);
  }

  // The URN above is an internal storage/continuity alias. Public controllers
  // are always real did:web identifiers built with the shared SDK algorithm.
  // Portal-specific card/profile DIDs are aliases. They must not replace the
  // operational controller DID published and verified by this GW.
  const didId = buildOrganizationEmployeeDidWeb({
    organizationDidWeb: deps.hostedTenantDid,
    ...contact,
    role: HealthcareActorRoles.Controller,
  });
  const presentedDid = String(deps.explicitBinding?.did || '').trim();
  if (presentedDid && !presentedDid.startsWith('did:web:')) {
    throw new ManagerError('Presented controller alias must use a did:web identifier.', IssueType.Value);
  }
  const actorSameAs = normalizeControllerAlias(deps.explicitBinding?.sameAs || contact.contact);
  const alsoKnownAs = Array.from(new Set([
    employeeUrn,
    presentedDid && presentedDid !== didId ? presentedDid : undefined,
    actorSameAs,
  ].filter((value): value is string => Boolean(value))));

  const mergedJwks = deps.mergeActivationJwks([signerJwk, encrypterJwk], deps.explicitBinding?.jwks);
  const didDocument: DidDocument = populateDidDocumentFromJwks(
    {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: didId,
      ...(alsoKnownAs.length ? { alsoKnownAs } : {}),
      service: [],
    },
    mergedJwks,
  );

  const verificationMethods = didDocument.verificationMethod || [];
  const signerMethodId = verificationMethods.find((method) => (method.publicKeyJwk as any)?.kid === signerJwk?.kid)?.id;

  return {
    id: didId,
    type: EntityType.Person,
    status: EntityLifecycleStatus.Active,
    claims: {
      ...(deps.legalRep.meta?.claims || {}),
      [SchemaOrgPersonClaim.Identifier]: didId,
      [SchemaOrgPersonClaim.AdditionalType]: HealthcareActorRoles.Controller,
      [SchemaOrgPersonClaim.SameAs]: actorSameAs,
    },
    didDocument: {
      ...didDocument,
      authentication: signerMethodId ? [signerMethodId] : didDocument.authentication,
    },
    didConfig: { service: [] },
    meta: { lastUpdated: new Date().toISOString() },
  };
}

/**
 * Persists the synthetic bootstrap controller employee created to initialize a
 * hosted tenant.
 */
export async function storeControllerEntityConfig(
  deps: StoreControllerEntityConfigDeps,
): Promise<void> {
  const verificationMethods = deps.controllerConfig.didDocument?.verificationMethod || [];
  const contact = readBootstrapControllerContact(deps.controllerConfig.claims);
  const roleCode = getPersonOccupationClaim(deps.controllerConfig.claims as Record<string, any> | undefined);

  const attributesToIndex: GatewayParameterData[] = [
    ...(contact ? [{ name: contact.contactKind,
      value: contact.contactKind === 'phone' ? normalizeIndexedPhone(contact.contact) : contact.contact,
      unique: true, type: 'string' }] : []),
    ...(roleCode ? [{ name: 'role', value: normalizeCodeSystemAndValue(roleCode), unique: false, type: 'token' } as GatewayParameterData] : []),
    { name: 'lifecycleRole', value: deps.bootstrapLifecycleRole, unique: false, type: 'string' } as GatewayParameterData,
    ...verificationMethods
      .map((vm) => (vm.publicKeyJwk as PublicJwk | undefined)?.kid)
      .filter((kid): kid is string => Boolean(kid))
      .map((kid) => ({ name: 'kid', value: kid, unique: false, type: 'string' } as GatewayParameterData)),
  ];
  const protectedAttributes = await deps.kmsService.protectAttributesNameAndValue(attributesToIndex, deps.vaultId);

  const employeeDoc: ConfidentialStorageDoc = {
    id: deps.controllerConfig.id,
    status: deps.controllerConfig.status,
    sequence: 0,
    content: deps.controllerConfig,
    indexed: { attributes: protectedAttributes },
    public: {
      role: deps.bootstrapLifecycleRole,
    },
  };
  const secureEmployeeDoc = await deps.kmsService.protectConfidentialData(employeeDoc, deps.vaultId);
  await deps.vaultRepository.put(deps.tenantCollectionName, [secureEmployeeDoc], getEnvSectionId('employees'));
}
