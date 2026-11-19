import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';
import { resolveOrganizationRouteJurisdiction } from '../../utils/tenant';

export type IcaAdmissionRequest = Readonly<{
  hostDid: string;
  network: string | undefined;
  sector: string;
  controllerDid?: string;
  claims: ClaimsRecord;
  applicationProof?: Readonly<{ applicationId: string; pdfSha256: string }>;
}>;

export function createIcaAdmissionClient(
  environment: Readonly<Record<string, string | undefined>>,
  transport: typeof fetch = fetch,
): ((input: IcaAdmissionRequest) => Promise<unknown | undefined>) | undefined {
  const configured = environment.HOST_ADMISSION_ICA_URL?.trim();
  const token = environment.HOST_ADMISSION_ICA_TOKEN?.trim();
  if (!configured && !token) return undefined;
  const endpoint = URL.parse(configured || '');
  if (!token || /\s/.test(token) || endpoint?.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('ICA admission service configuration is invalid');
  }

  return async ({ hostDid, network, sector, controllerDid, claims, applicationProof }) => {
    const jurisdiction = resolveOrganizationRouteJurisdiction(claims);
    const value = String(claims[SchemaOrgOrganizationClaim.IdentifierValue] || '').trim();
    const identifierType = String(claims[SchemaOrgOrganizationClaim.IdentifierType] || '').trim().toUpperCase();
    if (network !== 'test-network' || !controllerDid || !jurisdiction || !value || !identifierType
      || !applicationProof || !/^[a-zA-Z0-9._:-]{1,200}$/.test(applicationProof.applicationId)
      || !/^[a-fA-F0-9]{64}$/.test(applicationProof.pdfSha256)) return undefined;
    const proofReference = `urn:sha256:${applicationProof.pdfSha256.toLowerCase()}`;
    const scheme = jurisdiction.split('-')[0] === 'ES' && identifierType === 'TAX' ? 'NIF' : identifierType;
    try {
      const response = await transport(endpoint, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: {
          authorization: `Bearer ${token}`, 'content-type': 'application/json',
          'x-admission-actor': controllerDid, 'x-admission-application-id': applicationProof.applicationId,
        },
        body: JSON.stringify({
          network, sector, jurisdiction, identifier: { scheme, value },
          proofReference,
        }),
      });
      if (response.status !== 200) return undefined;
      const evidence = await response.json();
      if (evidence?.network !== network || evidence.jurisdiction !== jurisdiction || evidence.sector !== sector
        || evidence.admissionBinding?.hostDid !== hostDid || evidence.admissionBinding.applicationId !== applicationProof.applicationId
        || evidence.actorReference !== controllerDid || evidence.proof?.submittedReference !== proofReference
        || typeof evidence.proof?.reference !== 'string' || !evidence.proof.reference.trim()
        || !Array.isArray(evidence.checks) || evidence.checks.some((check: unknown) => typeof check !== 'string')) return undefined;
      return evidence;
    } catch {
      return undefined;
    }
  };
}
