import { v4 as uuidv4 } from 'uuid';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';
import { buildGaiaXLegalPersonCredentialDraft } from 'gdc-common-utils-ts/convert/schemaorg-to-gaia-x';

export interface GaiaXLegalParticipantCredentialOptions {
  webDomain: string;              // e.g. "https://example.com"
  officialName: string;           // legal name
  did: string;                    // DID of the participant (subject)
  issuerDid: string;              // DID of the issuer/signing entity
  vatId: string;                  // e.g. "ESB12345678"
  countryCode: string;            // ISO 3166-1 alpha-2, e.g. "ES"
  /** Resolvable ICA/GXDCH registration credential. GDC deployments may point to ICA evidence until GXDCH replacement. */
  legalRegistrationNumberCredentialId?: string;
}
/**
 * @deprecated Compatibility name. The returned ICAM 25.11 credential is a
 * Gaia-X `LegalPerson`, meaning the participating legal organization, never
 * the natural-person LegalRepresentative.
 */
export function createGaiaXLegalParticipantCredential(options: GaiaXLegalParticipantCredentialOptions) {
  const {
    webDomain,
    officialName,
    did,
    issuerDid,
    vatId,
    countryCode,
  } = options;

  const claims: ClaimsRecord = {
    [SchemaOrgOrganizationClaim.LegalName]: officialName,
    [SchemaOrgOrganizationClaim.IdentifierValue]: vatId,
    [SchemaOrgOrganizationClaim.AddressCountry]: countryCode,
    [SchemaOrgOrganizationClaim.Url]: webDomain,
  };
  return buildGaiaXLegalPersonCredentialDraft({
    claims,
    credentialId: `urn:uuid:${uuidv4()}`,
    subjectId: did,
    issuerId: issuerDid,
    legalRegistrationNumberCredentialId:
      options.legalRegistrationNumberCredentialId || `${did}#ica-legal-registration-evidence`,
    validFrom: new Date().toISOString(),
  });
}

export function buildGaiaXLegalParticipantOptionsFromClaims(params: {
  claims: ClaimsRecord;
  webDomain: string;
  did: string;
  issuerDid: string;
}): GaiaXLegalParticipantCredentialOptions {
  const { claims, webDomain, did, issuerDid } = params;
  const officialName = claims[SchemaOrgOrganizationClaim.LegalName] as string | undefined;
  const vatId = claims[SchemaOrgOrganizationClaim.IdentifierValue] as string | undefined;
  const countryCode = claims[SchemaOrgOrganizationClaim.AddressCountry] as string | undefined;

  if (!officialName || !vatId || !countryCode) {
    throw new Error('Missing required claims to build Gaia-X Legal Participant credential.');
  }

  return {
    webDomain,
    officialName,
    did,
    issuerDid,
    vatId,
    countryCode,
  };
}
