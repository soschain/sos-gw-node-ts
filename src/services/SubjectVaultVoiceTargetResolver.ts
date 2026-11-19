import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService.js';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository.js';
import { normalizePhoneNumber } from '../utils/phone-number.js';
import { getEnvSectionId } from '../utils/section-env.js';
import { getTenantVaultId } from '../utils/tenant.js';
import { normalizeUuid } from 'antifraud-data-utils-ts/organization-identity';
import type { ReminderRouteContext, VoiceTargetResolver } from './UhcReminderDaemon.js';

const INDIVIDUAL_SECTION = getEnvSectionId('individual');
const E164_RE = /^\+[1-9]\d{6,14}$/;

function normalizedToken(value: string | undefined): string | undefined {
  const raw = String(value || '').trim();
  if (!raw) return undefined;
  return raw.toLowerCase();
}

function pushToken(tokens: Set<string>, value: string | undefined): void {
  const raw = String(value || '').trim();
  if (!raw) return;
  const normalized = normalizedToken(raw);
  if (normalized) tokens.add(normalized);

  const slashIdx = raw.lastIndexOf('/');
  if (slashIdx >= 0 && slashIdx < raw.length - 1) {
    const tail = normalizedToken(raw.slice(slashIdx + 1));
    if (tail) tokens.add(tail);
  }

  if (raw.startsWith('urn:uuid:')) {
    const tail = normalizedToken(raw.slice('urn:uuid:'.length));
    if (tail) tokens.add(tail);
  }
}

function buildSubjectTokens(subjectId: string): Set<string> {
  const tokens = new Set<string>();
  pushToken(tokens, subjectId);
  // Add normalized UUID (hex, no dashes) if possible
  const norm = normalizeUuid(subjectId);
  if (norm) tokens.add(norm);
  return tokens;
}

function claimString(claims: Record<string, unknown>, key: string): string | undefined {
  const value = claims[key];
  if (value === undefined || value === null) return undefined;
  const normalized = String(value).trim();
  return normalized || undefined;
}

function extractPhoneFromClaims(claims: Record<string, unknown>): string | undefined {
  const candidates = [
    claimString(claims, 'org.schema.Organization.telephone'),
    claimString(claims, 'org.schema.Organization.owner.telephone'),
    claimString(claims, SchemaOrgPersonClaim.Telephone),
    claimString(claims, 'telephone'),
    claimString(claims, 'phone'),
    claimString(claims, 'mobile'),
    claimString(claims, 'mobile-phone'),
    claimString(claims, 'subject-phone'),
    claimString(claims, 'Person.telephone'),
    claimString(claims, 'Person.telecom-value'),
  ];

  for (const rawValue of candidates) {
    if (!rawValue) continue;
    const value = rawValue.toLowerCase().startsWith('tel:')
      ? rawValue.slice(4).trim()
      : rawValue;
    const normalized = normalizePhoneNumber(value);
    const withPlus = normalized.startsWith('00') ? `+${normalized.slice(2)}` : normalized;
    if (E164_RE.test(withPlus)) return withPlus;
  }
  return undefined;
}

function matchesSubject(entity: any, subjectTokens: Set<string>, containerId?: string): boolean {
  const claims = (entity?.claims || {}) as Record<string, unknown>;
  const didDocumentId = String(entity?.didDocument?.id || '').trim();
  const internalId = String(entity?.id || '').trim();

  const candidateTokens = new Set<string>();
  pushToken(candidateTokens, containerId);
  pushToken(candidateTokens, didDocumentId);
  pushToken(candidateTokens, internalId);
  pushToken(candidateTokens, claimString(claims, SchemaOrgPersonClaim.Identifier));
  pushToken(candidateTokens, claimString(claims, 'org.schema.Organization.identifier.value'));
  pushToken(candidateTokens, claimString(claims, 'org.schema.Organization.identifier'));
  pushToken(candidateTokens, claimString(claims, 'identifier'));
  pushToken(candidateTokens, claimString(claims, 'subject'));

  for (const token of candidateTokens) {
    if (subjectTokens.has(token)) return true;
  }
  return false;
}

function resolveTenantVaultId(route: ReminderRouteContext): string {
  return route.tenantId === 'host'
    ? 'host'
    : getTenantVaultId(route.sector, route.tenantId);
}

/**
 * Resolve call target from the subject confidential storage document.
 *
 * Production intent:
 * - Task carries subject reference.
 * - Daemon resolves phone from subject vault (decrypted server-side).
 * - Task metadata phone fields remain transitional fallback.
 */
export function createSubjectVaultVoiceTargetResolver(options: {
  vaultRepository: IVaultRepository;
  kmsService: IKmsService;
  tenantsCacheManager?: {
    getCollectionName(vaultId: string): Promise<string | undefined>;
  };
}): VoiceTargetResolver {
  return async (task, route) => {
    const subjectId = String(task.subjectId || '').trim();
    if (!subjectId) {
      console.warn('[SubjectVaultVoiceTargetResolver] task.subject is missing');
      return { source: 'none', reason: 'task.subject is missing' };
    }

    const tenantVaultId = resolveTenantVaultId(route);
    const subjectTokens = buildSubjectTokens(subjectId);
    const sectionIds = [INDIVIDUAL_SECTION];
    const tenantCollectionName = await options.tenantsCacheManager?.getCollectionName(tenantVaultId);
    const storageIds = Array.from(
      new Set(
        [tenantCollectionName, tenantVaultId]
          .map((v) => String(v || '').trim())
          .filter(Boolean),
      ),
    );
    for (const storageId of storageIds) {
      for (const sectionId of sectionIds) {
        const docs = await options.vaultRepository.getContainersInSection<ConfidentialStorageDoc>(
          storageId,
          sectionId,
        );
        for (const secureDoc of docs) {
          try {
            const decrypted = await options.kmsService.unprotectConfidentialData<any>(secureDoc, tenantVaultId);
            const entity = decrypted?.content || decrypted;
            if (!entity || !matchesSubject(entity, subjectTokens, secureDoc?.id)) continue;

            const claims = (entity.claims || {}) as Record<string, unknown>;
            const phone = extractPhoneFromClaims(claims);
            if (phone) {
              return { to: phone, source: 'subject-vault' };
            }
            console.warn('[SubjectVaultVoiceTargetResolver] Matched subject has no valid phone.');
            return { source: 'none', reason: `subject found in ${sectionId} but no valid E.164 phone in claims` };
          } catch {
            console.warn('[SubjectVaultVoiceTargetResolver] Could not decrypt a subject record.');
            // Skip unreadable entries and continue scanning.
          }
        }
      }
    }

    return { source: 'none', reason: `subject not found in ${INDIVIDUAL_SECTION} section` };
  };
}
