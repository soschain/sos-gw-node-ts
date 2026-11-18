import {DEFAULT_LICENSE_DEVICE_ALLOWANCE} from '../constants/domain';
import { isIsco08CodingSystem } from 'antifraud-data-utils-ts/isco-08';
import { HL7_CODING_SYSTEM_V3_ROLE_CODE } from 'fhir-data-utils-ts';

/** Pool selection only: none of these descriptions authenticates a role or grants professional authority. */
export const LicenseRoleKinds = Object.freeze({
  IndividualMember: 'individual-member',
  Professional: 'professional',
  Unsupported: 'unsupported',
} as const);
export type LicenseRoleKind = typeof LicenseRoleKinds[keyof typeof LicenseRoleKinds];

/** Retain the existing relationship/occupation compatibility profiles without owning their clinical catalogs. */
export function classifyLicenseRole(role: string): LicenseRoleKind {
  const normalized = String(role || '').trim().toLowerCase();
  if (!normalized) return LicenseRoleKinds.Unsupported;
  const system = normalized.includes('|') ? normalized.split('|', 1)[0] : normalized;
  if (system === 'isco' || isIsco08CodingSystem(system) || system.endsWith('/isco-08')) {
    return LicenseRoleKinds.Professional;
  }
  if (system === HL7_CODING_SYSTEM_V3_ROLE_CODE.toLowerCase()
    || system === 'v3-rolecode' || system === 'org.hl7.v3.rolecode'
    || system.endsWith('/v3-rolecode')) {
    return LicenseRoleKinds.IndividualMember;
  }
  return LicenseRoleKinds.Unsupported;
}

/** The receipt and registration capacity share the same canonical default. */
export function resolveIssuedSeatDeviceAllowance(maxDevices: unknown): number {
  const value = Number(maxDevices);
  return Number.isInteger(value) && value > 0 ? value : DEFAULT_LICENSE_DEVICE_ALLOWANCE;
}
