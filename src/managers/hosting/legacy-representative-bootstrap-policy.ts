import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';

function parseEnabled(raw: string | boolean | undefined): boolean {
  if (typeof raw === 'boolean') return raw;
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return false;
  if (['true', '1', 'yes', 'on'].includes(value)) return true;
  if (['false', '0', 'no', 'off'].includes(value)) return false;
  throw new ManagerError(
    'HOST_LEGACY_REPRESENTATIVE_CONTROLLER must be a boolean value.',
    IssueType.Value,
  );
}

/**
 * Enables the historical legal-representative controller contract for a
 * deployment whose legacy portal still registers every organization through
 * that actor. Credential ids, issuers and key ids are deliberately not pinned:
 * normal VP/credential trust checks authenticate every submission, while
 * re-registration may renew a credential or rotate the representative's key.
 */
export function allowsLegacyRepresentativeBootstrap(input: Readonly<{
  representativeCredential?: Record<string, unknown>;
  enabled?: string | boolean;
}>): boolean {
  if (!parseEnabled(input.enabled)) return false;
  const credential = input.representativeCredential;
  if (!credential) return false;
  const types = (Array.isArray(credential.type) ? credential.type : [credential.type])
    .map(type => String(type || '').trim());
  return types.includes('LegalRepresentativeCredential');
}
