/** Tenant lifecycle input projection only; callers must verify the credential first. */
type TenantLegalIdentifier = Readonly<{ type: string; value: string }>;
type CandidateIdentifier = Readonly<{ type?: unknown; value?: unknown }> | undefined;

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' ? value as Record<string, unknown> : undefined;
}

function normalizeIdentifier(value: CandidateIdentifier): TenantLegalIdentifier | undefined {
  const suppliedType = String(value?.type || '').trim().toUpperCase();
  const type = suppliedType === 'TAXID' || suppliedType === 'TAX_ID' ? 'TAX' : suppliedType;
  const identifierValue = String(value?.value || '').trim().toUpperCase();
  return type && identifierValue ? { type, value: identifierValue } : undefined;
}

/** Preserve the existing first-subject representative memberOf projection. */
export function readRepresentativeOrganizationIdentifier(credential: unknown): TenantLegalIdentifier | undefined {
  const subjects = record(credential)?.credentialSubject;
  const subject = record(Array.isArray(subjects) ? subjects[0] : subjects);
  const organization = record(subject?.memberOf);
  const identifier = record(organization?.identifier);
  const taxId = organization?.taxID ?? organization?.taxId;
  return normalizeIdentifier(taxId !== undefined
    ? { type: 'TAX', value: taxId }
    : { type: identifier?.additionalType ?? identifier?.type ?? organization?.identifierType,
      value: identifier?.value ?? organization?.identifierValue });
}

/** Match the full typed value, retaining punctuation and the identifier namespace. */
export function matchesTenantLegalIdentifier(left: CandidateIdentifier, right: CandidateIdentifier): boolean {
  const expected = normalizeIdentifier(left);
  const actual = normalizeIdentifier(right);
  return Boolean(expected && actual && expected.type === actual.type && expected.value === actual.value);
}
