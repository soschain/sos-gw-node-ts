import type { DeviceLicense } from 'sos-data-utils-ts/device-license-contract';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import {SchemaOrgOrganizationClaim,SchemaOrgPersonClaim,SchemaOrgServiceClaim} from 'antifraud-data-utils-ts/schema-org-claims';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import type { EntityConfig } from '../gdc-backend-utils-node/models/entity';
import { generateTenantCollectionNameFromClaims, getTenantVaultId, getIdentifierUrnFromClaims,resolveOrganizationRouteJurisdiction } from './tenant';
import { getEnvSectionId } from './section-env';
import { normalizeIndexedEmail,normalizeIndexedPhone } from './indexed-contact';
import { normalizeCodeSystemAndValue } from './normalize-codeAndSystem';
import { getPersonOccupationClaim } from './occupation';
import { getEmployeeRoleFromUrn, getTenantIdentifierUrnPrefix, parseTenantUrn, resolveRoleBearingEmployeeUrn, createEmployeeUrnFromStableActorIdentifier, normalizeEmployeeRole } from './urn';
import { resolveHostPhysicalCollectionName } from '../config/storage-layout';
import {normalizeControllerAlias,normalizeTelephoneAlias} from 'antifraud-data-utils-ts/public-aliases';
import {isStableActorIdentifier,buildStableActorIdentifier,type ActorContactInput} from 'antifraud-data-utils-ts/organization-identity';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { LICENSE_USER_CLASS_EMPLOYEE, LICENSE_STATUS_ACTIVE, LICENSE_STATUS_ISSUED } from '../constants/domain';
import { EntityLifecycleStatus } from '../gdc-backend-utils-node/models/enums';

type LegacyControllerLicenseInput = Readonly<{
  tenantVaultId: string;
  license: DeviceLicense & Record<string, any>;
  vaultRepository: IVaultRepository;
  kmsService?: IKmsService;
}>;

export type LegacyControllerLicenseBinding = Readonly<{ subjectId: string; employeeUrn: string }>;

/** Resolves a seat from protected current designation and contact; it neither changes keys nor grants a role. */
export async function resolveLegacyControllerLicenseBinding(input: LegacyControllerLicenseInput): Promise<LegacyControllerLicenseBinding> {
  const {license, tenantVaultId, vaultRepository, kmsService} = input;
  const deny = (): never => { throw new ManagerError('Controller licence has no unambiguous current tenant binding.', IssueType.Forbidden); };
  if (!kmsService || license.userClass !== LICENSE_USER_CLASS_EMPLOYEE
    || ![LICENSE_STATUS_ISSUED, LICENSE_STATUS_ACTIVE].includes(license.status as typeof LICENSE_STATUS_ISSUED | typeof LICENSE_STATUS_ACTIVE)
    || (license.exp && Number(license.exp) <= Math.floor(Date.now() / 1000))) return deny();
  const email = normalizeIndexedEmail(license.issuedToEmail || '');
  const phone = normalizeIndexedPhone(license.issuedToPhone || '');
  const contact:ActorContactInput|undefined=email?{contactKind:'email',contact:email}:phone?{contactKind:'phone',contact:phone}:undefined;
  const role = normalizeCodeSystemAndValue(license.issuedToRole || '');
  if(!contact||!role)return deny();
  let actorIdentifier:string;
  try{actorIdentifier=buildStableActorIdentifier(contact);}catch{return deny();}
  if(isStableActorIdentifier(license.activatedBy)&&license.activatedBy!==actorIdentifier)return deny();
  const tenantRecord = await vaultRepository.get<ConfidentialStorageDoc>(resolveHostPhysicalCollectionName(), tenantVaultId, getEnvSectionId('tenants'));
  if (!tenantRecord || tenantRecord.id !== tenantVaultId
    || (tenantRecord.status !== undefined && tenantRecord.status !== EntityLifecycleStatus.Active)) return deny();
  const tenant = await kmsService.unprotectConfidentialData<EntityConfig>(tenantRecord, 'host');
  const claims = tenant?.claims;
  if (tenant?.status !== EntityLifecycleStatus.Active || !claims
    || getTenantVaultId(String(claims[SchemaOrgServiceClaim.Category] || ''), String(claims[SchemaOrgOrganizationClaim.AlternateName] || '')) !== tenantVaultId) return deny();
  const collectionName = generateTenantCollectionNameFromClaims(claims);
  const designation = tenant.didDocument?.controller;
  const controllers = [...new Set(typeof designation === 'string' ? [designation] : designation || [])];
  const tenantUrn = getIdentifierUrnFromClaims(claims);
  const declaredScope = tenantUrn ? parseTenantUrn(tenantUrn) : undefined;
  const candidates: LegacyControllerLicenseBinding[] = [];
  for (const controller of controllers) {
    const storedSubjectId = String(license.subjectId || '').trim() || controller;
    const document = await vaultRepository.get<ConfidentialStorageDoc>(collectionName, storedSubjectId, getEnvSectionId('employees'));
    if (!document || document.status === 'inactive' || document.status === 'revoked') continue;
    const employee = await kmsService.unprotectConfidentialData<EntityConfig>(document, tenantVaultId);
    if (employee?.status !== EntityLifecycleStatus.Active || employee.id !== document.id || employee.didDocument?.id !== controller
      || employee.claims?.[SchemaOrgPersonClaim.AdditionalType] !== HealthcareActorRoles.Controller) continue;
    const employeeEmail=normalizeIndexedEmail(String(employee.claims?.[SchemaOrgPersonClaim.Email]||''));
    const employeeTelephone=String(employee.claims?.[SchemaOrgPersonClaim.Telephone]||'').trim();
    const employeeSameAs=String(employee.claims?.[SchemaOrgPersonClaim.SameAs]||'').trim();
    const relevantContact=contact.contactKind==='email'?employeeEmail:employeeTelephone;
    if((!relevantContact&&!employeeSameAs)
      ||(contact.contactKind==='email'&&employeeEmail&&employeeEmail!==email)
      ||(contact.contactKind==='phone'&&employeeTelephone&&normalizeTelephoneAlias(employeeTelephone)!==actorIdentifier)
      ||(employeeSameAs&&normalizeControllerAlias(employeeSameAs)!==actorIdentifier))continue;
    const licensedRole = String(license.issuedToRole || '');
    const controllerLicence = normalizeEmployeeRole(licensedRole) === normalizeEmployeeRole(HealthcareActorRoles.Controller);
    if (!controllerLicence && normalizeCodeSystemAndValue(getPersonOccupationClaim(employee.claims) || '') !== role) continue;
    let employeeUrn = resolveRoleBearingEmployeeUrn(employee.didDocument, licensedRole);
    if (!employeeUrn && controllerLicence && tenantUrn && declaredScope) {
      employeeUrn = createEmployeeUrnFromStableActorIdentifier({ organizationUrn: tenantUrn, stableActorIdentifier: actorIdentifier, role: licensedRole });
    }
    const scope = employeeUrn && parseTenantUrn(getTenantIdentifierUrnPrefix(employeeUrn));
    if (!employeeUrn || !scope || normalizeCodeSystemAndValue(getEmployeeRoleFromUrn(employeeUrn) || '') !== role
      || scope.sector !== String(claims[SchemaOrgServiceClaim.Category])
      || scope.jurisdiction.toUpperCase() !== resolveOrganizationRouteJurisdiction(claims).toUpperCase()
      || scope.idType.toLowerCase() !== String(claims[SchemaOrgOrganizationClaim.IdentifierType]).toLowerCase()
      || scope.idValue !== String(claims[SchemaOrgOrganizationClaim.IdentifierValue])
      || (declaredScope && (scope.namespace !== declaredScope.namespace || scope.network !== declaredScope.network || scope.version !== declaredScope.version))) continue;
    candidates.push({subjectId:document.id,employeeUrn});
  }
  if (candidates.length !== 1 || (license.subjectId && license.subjectId !== candidates[0].subjectId)) return deny();
  return candidates[0];
}

export async function resolveLegacyControllerLicenseSubject(input: LegacyControllerLicenseInput): Promise<string> {
  return (await resolveLegacyControllerLicenseBinding(input)).subjectId;
}
