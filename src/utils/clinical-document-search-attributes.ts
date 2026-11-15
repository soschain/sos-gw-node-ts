import { CompositionClaim } from 'fhir-data-utils-ts';
import type { AuditInfo, IndexedAttribute } from 'sos-data-utils-ts/confidential-storage';

// Established operational search profile, not the full evolving FHIR claim catalogue.
const supportedCompositionClaims: readonly string[] = [
  CompositionClaim.Subject, CompositionClaim.Section, CompositionClaim.Author,
  CompositionClaim.Attester, CompositionClaim.AttesterMode, CompositionClaim.AttesterTime,
  CompositionClaim.Custodian, CompositionClaim.Date, CompositionClaim.Entry,
  CompositionClaim.Type, CompositionClaim.Identifier, CompositionClaim.Title,
];
const csvClaims = new Set<string>([
  CompositionClaim.Author, CompositionClaim.Attester, CompositionClaim.AttesterMode,
  CompositionClaim.AttesterTime, CompositionClaim.Section, CompositionClaim.Entry,
]);

/** Derived search attributes only; never changes the canonical signed/stored claims. */
export function buildClinicalDocumentSearchAttributes(input: Readonly<{
  claims: Readonly<Record<string, unknown>>;
  sector?: string;
  audit?: Pick<AuditInfo, 'creatorDid' | 'submitterDid' | 'signingKeyId'>;
}>): IndexedAttribute[] {
  const attributes: IndexedAttribute[] = [];
  const append = (name: string, value: unknown, unique = false): void => {
    const text = String(value ?? '').trim();
    if (!text || attributes.some(attribute => attribute.name === name && attribute.value === text)) return;
    attributes.push({ name, value: text, ...(unique ? { unique: true } : {}) });
  };
  append('sector', input.sector);
  append('audit.creatorDid', input.audit?.creatorDid);
  append('audit.submitterDid', input.audit?.submitterDid);
  append('audit.signingKeyId', input.audit?.signingKeyId);
  for (const [name, rawValue] of Object.entries(input.claims)) {
    if (name === '@context' || name === '@type' || rawValue === undefined || rawValue === null || Array.isArray(rawValue)) continue;
    const value = String(rawValue).trim();
    if (!value) continue;
    const compositionName = supportedCompositionClaims.find(claim => name === claim || name.endsWith(`.${claim}`));
    const indexedName = compositionName || name;
    if (csvClaims.has(indexedName)) {
      const values = value.split(',').map(part => part.trim()).filter(Boolean);
      for (const part of values) append(indexedName, part);
      if (values.length > 1) append(indexedName, value);
      if (name !== indexedName) append(name, value);
    } else {
      append(indexedName, value, !compositionName && (name.endsWith('.identifier') || name.endsWith('.identifier.value')));
      if (name !== indexedName) append(name, value);
    }
  }
  return attributes;
}
