import { createHash } from 'node:crypto';
import type { VerifiableCredentialV2 } from 'antifraud-data-utils-ts/credential-contracts';
import { ReviewedOrganizationCredentialTypes } from 'antifraud-data-utils-ts/organization-credentials';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { getDidWebDocumentUrl } from './physical-identity-did';

interface OrganizationPublicationRecord {
  didDocument?: { id?: string };
  claims?: Record<string, unknown>;
  organizationCredential?: VerifiableCredentialV2;
  governanceVc?: VerifiableCredentialV2;
  selfDescriptionVc?: VerifiableCredentialV2;
}

function isSignedOrganizationCredential(value?: VerifiableCredentialV2): value is VerifiableCredentialV2 {
  if (!value || !Array.isArray(value.type) || !value.type.includes(ReviewedOrganizationCredentialTypes.Organization)
    || !Array.isArray(value['@context']) || !value['@context'].includes('https://schema.org')) return false;
  const subject = value.credentialSubject;
  const proofs = Array.isArray(value.proof) ? value.proof : [value.proof];
  return subject?.['@type'] === 'Organization' && typeof subject.id === 'string'
    && typeof value.issuer === 'string' && Boolean(value.issuer)
    && proofs.some(proof => proof?.verificationMethod?.startsWith(`${value.issuer}#`)
      && Boolean(proof.jws || proof.proofValue));
}

/** Selects the original organization VC from records already admitted by the gateway. */
export function isIssuedOrganizationCredential(value?: VerifiableCredentialV2): value is VerifiableCredentialV2 {
  return isSignedOrganizationCredential(value) && value.issuer !== value.credentialSubject.id;
}

/** Preserves the admitted original host statement and all proofs attached to it. */
export function getSignedHostOrganizationCredential(entity?: OrganizationPublicationRecord): VerifiableCredentialV2 | undefined {
  const credential = entity?.organizationCredential;
  const hostDid = entity?.didDocument?.id;
  if (isSignedOrganizationCredential(credential) && credential.issuer === hostDid
    && credential.credentialSubject.id === hostDid) return credential;
}


/** The participant signs its own declaration. Never use an ICA organization VC as a JWT payload here. */
export function getParticipantGaiaXCredential(entity?: OrganizationPublicationRecord): VerifiableCredentialV2 | undefined {
  const participant = entity?.didDocument?.id;
  return [entity?.governanceVc, entity?.selfDescriptionVc].find(credential => (
    Boolean(participant) && credential?.issuer === participant
      && credential?.credentialSubject?.id === participant
      && (credential?.credentialSubject?.type ?? credential?.credentialSubject?.['@type']) === 'gx:LegalPerson'
  ));
}

export function getIssuedOrganizationCredential(entity?: OrganizationPublicationRecord): VerifiableCredentialV2 | undefined {
  return [entity?.organizationCredential, entity?.governanceVc].find(isIssuedOrganizationCredential);
}

/** Builds the host's own statement from its configured public legal identity. */
export function buildHostOrganizationStatement(entity?: OrganizationPublicationRecord): VerifiableCredentialV2 | undefined {
  const issuer = entity?.didDocument?.id;
  const legalName = entity?.claims?.[SchemaOrgOrganizationClaim.LegalName];
  const identifier = entity?.claims?.[SchemaOrgOrganizationClaim.IdentifierValue];
  const identifierType = entity?.claims?.[SchemaOrgOrganizationClaim.IdentifierType];
  const configuredTaxId = entity?.claims?.[SchemaOrgOrganizationClaim.TaxId];
  if (!issuer || typeof legalName !== 'string' || !legalName.trim()
    || typeof identifier !== 'string' || !identifier.trim()) return undefined;

  const taxID = typeof configuredTaxId === 'string' && configuredTaxId.trim()
    ? configuredTaxId.trim()
    : typeof identifierType === 'string' && /^(TAX|VAT)$/i.test(identifierType) ? identifier.trim() : undefined;
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    id: `${issuer}#organization`,
    type: [ReviewedOrganizationCredentialTypes.VerifiableCredential, ReviewedOrganizationCredentialTypes.Organization],
    issuer,
    validFrom: getParticipantGaiaXCredential(entity)?.validFrom ?? new Date().toISOString(),
    credentialSubject: {
      id: issuer,
      '@type': 'Organization',
      legalName: legalName.trim(),
      identifier: {
        '@type': 'PropertyValue',
        value: identifier.trim(),
        ...(typeof identifierType === 'string' && identifierType.trim() ? { additionalType: identifierType.trim() } : {}),
      },
      ...(taxID ? { taxID } : {}),
    },
  };
}

/** Binds the participant's tax claim to the bytes of the admitted ICA credential. */
export function bindOrganizationRegistrationEvidence(
  declaration: VerifiableCredentialV2,
  entity: OrganizationPublicationRecord,
  organizationPath: string,
  configuredOrigin?: string,
) {
  const credential = getIssuedOrganizationCredential(entity);
  const declaredTaxId = entity.claims?.[SchemaOrgOrganizationClaim.TaxId]
    ?? entity.claims?.[SchemaOrgOrganizationClaim.IdentifierValue];
  const issuedTaxId = credential?.credentialSubject.taxID;
  if (!credential?.evidence?.length || typeof declaredTaxId !== 'string' || !declaredTaxId.trim()
    || typeof issuedTaxId !== 'string' || declaredTaxId.trim() !== issuedTaxId.trim()) return undefined;

  const organizationUrl = new URL(configuredOrigin ?? getDidWebDocumentUrl(declaration.issuer));
  organizationUrl.pathname = organizationPath;
  const { proof, ...statement } = declaration;
  const subject: Record<string, unknown> = { ...statement.credentialSubject, 'https://schema.org/taxID': declaredTaxId.trim() };
  const registrationNumber = statement.credentialSubject['gx:legalRegistrationNumber'];
  if (typeof registrationNumber === 'object' && registrationNumber !== null
    && 'id' in registrationNumber && registrationNumber.id === `${declaration.issuer}#ica-legal-registration-evidence`) {
    delete subject['gx:legalRegistrationNumber'];
  }
  return {
    ...statement,
    '@context': [...new Set([...statement['@context'], 'https://w3id.org/gaia-x/development#'])],
    credentialSubject: subject,
    relatedResource: [{
      id: organizationUrl.href,
      digestSRI: `sha256-${createHash('sha256').update(JSON.stringify(credential)).digest('base64')}`,
    }],
  };
}
