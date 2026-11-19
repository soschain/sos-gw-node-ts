import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import type { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import { resolveOrganizationRouteJurisdiction } from '../../utils/tenant';
import type { IcaAdmissionRequest } from './ica-admission-client';

export const GOVERNED_ORGANIZATION_ADMISSION_REQUIRED = 'New tenant admission requires Organization/_transaction on this host';

export type NewOfferAdmission = Readonly<{
  hostDid: string;
  network: string | undefined;
  sector: string;
  organizationDid?: string;
  controllerDid?: string;
  claims: ClaimsRecord;
  applicationProof?: IcaAdmissionRequest['applicationProof'];
  evidence: unknown;
  evidenceSource?: 'ica' | 'host';
  credentials: readonly Record<string, unknown>[];
}>;

function projectAdmissionEvidence(input: NewOfferAdmission, jurisdiction: string) {
  if (input.evidenceSource !== 'ica' || !input.evidence || typeof input.evidence !== 'object') return undefined;
  const evidence = input.evidence as Record<string, unknown>;
  const binding = evidence.admissionBinding as { hostDid?: unknown; applicationId?: unknown } | undefined;
  const proof = evidence.proof as { reference?: unknown } | undefined;
  if (evidence.network !== input.network || evidence.jurisdiction !== jurisdiction || evidence.sector !== input.sector
    || binding?.hostDid !== input.hostDid || typeof binding.applicationId !== 'string' || !binding.applicationId.trim()
    || typeof proof?.reference !== 'string' || !proof.reference.trim()
    || !Array.isArray(evidence.checks) || evidence.checks.some(check => typeof check !== 'string')) return undefined;
  return { applicationId: binding.applicationId, reference: proof.reference, checks: evidence.checks };
}

export function createNewOfferAdmissionAuthorizer(
  environment: Readonly<Record<string, string | undefined>>,
  transport: typeof fetch = fetch,
): ((input: NewOfferAdmission) => Promise<void>) | undefined {
  const endpoint = environment.HOST_ADMISSION_DECISION_URL?.trim();
  const token = environment.HOST_ADMISSION_DECISION_TOKEN?.trim();
  if (!endpoint && !token) return undefined;
  const url = URL.parse(endpoint || '');
  if (!token || /\s/.test(token) || !url || url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new Error('Host admission decision configuration is invalid');
  }

  return async (input) => {
    const { hostDid, network, sector, organizationDid, controllerDid, claims, applicationProof, evidence, evidenceSource, credentials } = input;
    const jurisdiction = resolveOrganizationRouteJurisdiction(claims);
    if (!network || !jurisdiction || !evidence) {
      throw new ManagerError('Verified admission evidence is required', IssueType.Security);
    }
    const scope = { hostDid, network, jurisdiction, sector };
    const verifiedEvidence = projectAdmissionEvidence(input, jurisdiction);
    const stableProof = verifiedEvidence?.checks.includes('legal-identifier-match')
      && verifiedEvidence.checks.includes('official-registry-active')
      ? { applicationId: verifiedEvidence.applicationId, proofReference: verifiedEvidence.reference }
      : undefined;
    // Registry observation timestamps and reissued credentials can change while the reviewed proof remains the same.
    const payload = canonicalize({
      scope, organizationDid, controllerDid, claims,
      ...(applicationProof
        ? { applicationId: applicationProof.applicationId, pdfSha256: applicationProof.pdfSha256.toLowerCase() }
        : { evidenceSource, ...(stableProof ? stableProof : { evidence, credentials }) }),
    });
    if (!payload) {
      throw new ManagerError('Verified admission evidence is required', IssueType.Security);
    }
    const binding = createHash('sha256').update(payload).digest('hex');
    let result: { binding?: unknown; decision?: unknown; reference?: unknown } | undefined;
    try {
      const response = await transport(url, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          ...scope, binding,
          ...(applicationProof ? { applicationId: applicationProof.applicationId } : {}),
          ...(verifiedEvidence ? { evidence: verifiedEvidence } : {}),
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Host decision returned a failure status');
      result = await response.json();
    } catch {
      throw new ManagerError('Host admission decision is unavailable', IssueType.Exception);
    }
    if ((applicationProof && !verifiedEvidence) || result?.decision !== 'approved' || result.binding !== binding
      || typeof result.reference !== 'string' || !result.reference.trim()) {
      throw new ManagerError('Host admission approval is required', IssueType.Forbidden);
    }
  };
}
