import type { ICryptography } from 'antifraud-data-utils-ts/cryptography';
import type { PublicJwk } from 'antifraud-data-utils-ts/cryptography';
import type { GatewayDidDocument as DidDocument } from 'sos-data-utils-ts/gateway-did-profile';
import type { VerificationMethod } from 'antifraud-data-utils-ts/did-document';
import type { VerifiableCredentialV2 } from 'antifraud-data-utils-ts/credential-contracts';
import {
  ReviewedOrganizationCredentialTypes,
  canonicalizeOrganizationTestNetworkCredential,
  canonicalizeTestNetworkOrganizationCredential,
} from 'antifraud-data-utils-ts/organization-credentials';
import { buildStableActorIdentifier, normalizeActorContact, type ActorContactInput } from 'antifraud-data-utils-ts/organization-identity';
import { toJwkThumbprintSha256Urn } from 'antifraud-data-utils-ts/jwk-thumbprints';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';

type VerificationInput = Readonly<{
  credential: VerifiableCredentialV2;
  claims: Record<string, unknown>;
  controller?: Record<string, unknown>;
  organization?: Record<string, unknown>;
  controllerEmail?: string;
  controllerTelephone?: string;
  legalRepresentativeEmail?: string;
  legalRepresentativeTelephone?: string;
  testNetworkCredentials?: readonly VerifiableCredentialV2[];
  cryptography: ICryptography;
  trustedIssuers: string[];
  trustedSigners?: ReadonlyArray<Readonly<{
    issuer: string;
    actorDid: string;
    role: string;
    jwkThumbprints: readonly string[];
    status?: 'active' | 'revoked';
  }>>;
  fetchImpl?: typeof fetch;
  now?: Date;
}>;

export type TestNetworkAdmissionVerificationResult = Readonly<{
  mode: 'organization-test-network-vc';
  credentialId: string;
  issuer: string;
  signer: string;
  applicationProof?: Readonly<{ applicationId: string; pdfSha256: string }>;
  checks: Readonly<{
    trustedIssuer: true;
    signerCurrentlyAuthorizedByIssuer: true;
    signerMethodActive: true;
    detachedPqcProof: true;
    applicationBinding: true;
  }>;
  credentials: readonly VerifiableCredentialV2[];
}>;

/**
 * Verifies the Test Network VC without calling ICA. Published DID governance
 * is preferred. The Test Network MVP can instead use an issuer-maintained
 * employee DID, role and key-thumbprint registry until employee governance
 * keys are published; deleting or revoking an entry fails closed.
 */
export async function verifyOrganizationTestNetworkCredential(
  input: VerificationInput,
): Promise<TestNetworkAdmissionVerificationResult> {
  const credential = input.credential;
  const issuer = typeof credential.issuer === 'string'
    ? credential.issuer
    : String((credential.issuer as { id?: string } | undefined)?.id || '');
  if (!credential.type.includes(ReviewedOrganizationCredentialTypes.Admission)) {
    fail('Unexpected organization Test Network credential type.');
  }
  if (!input.trustedIssuers.includes(issuer)) fail('Organization Test Network admission issuer is not trusted.');
  const now = input.now || new Date();
  if (credential.validFrom && now < new Date(credential.validFrom)) fail('Organization Test Network admission is not active yet.');
  if (credential.validUntil && now >= new Date(credential.validUntil)) fail('Organization Test Network admission has expired.');

  const subject = credential.credentialSubject as Record<string, any>;
  const organizationIdentifier = String(
    input.claims[SchemaOrgOrganizationClaim.IdentifierValue]
      || input.claims[SchemaOrgOrganizationClaim.TaxId]
      || '',
  ).trim();
  if (!organizationIdentifier || subject.organization?.identifier !== organizationIdentifier) {
    fail('Admission organization identifier does not match transaction claims.');
  }
  if (String(input.organization?.did || '') !== String(subject.id || '')) {
    fail('Admission subject DID does not match the requested organization DID.');
  }
  const controllerContact = reviewedPartyContact(input.controllerEmail, input.controllerTelephone, 'controller');
  const admissionControllerContact = reviewedPartyContact(subject.controller?.email, subject.controller?.telephone, 'reviewed controller');
  if (controllerContact.contactKind !== admissionControllerContact.contactKind
    || controllerContact.contact !== admissionControllerContact.contact) {
    fail('Admission controller contact does not match the transaction.');
  }
  const controllerJwk = input.controller?.publicKeyJwk as PublicJwk | undefined;
  if (!controllerJwk
    || toJwkThumbprintSha256Urn(controllerJwk) !== subject.controller?.hasCredential?.material) {
    fail('Admission controller key does not match the transaction.');
  }

  const proofs = Array.isArray(credential.proof) ? credential.proof : credential.proof ? [credential.proof] : [];
  const proof = proofs.find(item => item.proofPurpose === 'contractAgreement' && item.jws && item.verificationMethod);
  if (!proof) fail('Organization Test Network admission requires a contractAgreement proof.');
  const verificationMethod = String(proof.verificationMethod);
  const signerDid = verificationMethod.split('#')[0];
  const fetchImpl = input.fetchImpl || fetch;
  const embeddedJwk = (proof as any).publicKeyJwk as PublicJwk | undefined;
  const registeredSigner = input.trustedSigners?.find(entry => entry.issuer === issuer && entry.actorDid === signerDid);
  let signerJwk: PublicJwk;
  if (registeredSigner) {
    if (registeredSigner.status === 'revoked') fail('Admission signer is revoked.');
    if (registeredSigner.role !== 'RESPRSN') fail('Admission signer role is not authorized.');
    if (!embeddedJwk) fail('Registered admission signer proof must embed its public JWK.');
    const thumbprint = toJwkThumbprintSha256Urn(embeddedJwk);
    if (!registeredSigner.jwkThumbprints.includes(thumbprint)) {
      fail('Admission signer key is not active in the host registry.');
    }
    if (verificationMethod !== `${signerDid}#${embeddedJwk.kid}`) {
      fail('Admission verification method does not match its registered public key.');
    }
    signerJwk = embeddedJwk;
  } else {
    const [issuerDocument, signerDocument] = await Promise.all([
      resolveDidWebDocument(issuer, fetchImpl),
      resolveDidWebDocument(signerDid, fetchImpl),
    ]);
    const issuerControllers = Array.isArray(issuerDocument.controller)
      ? issuerDocument.controller
      : issuerDocument.controller ? [issuerDocument.controller] : [];
    if (!issuerControllers.includes(signerDid)) fail('Admission signer is not a current issuer controller.');
    if ((signerDocument as any).deactivated === true || String((signerDocument as any).status || '') === 'revoked') {
      fail('Admission signer is revoked.');
    }
    const method = (signerDocument.verificationMethod || []).find(item => item.id === verificationMethod);
    if (!method?.publicKeyJwk || !relationshipContains(signerDocument.assertionMethod, verificationMethod)) {
      fail('Admission signer method is not an active assertion method.');
    }
    signerJwk = method.publicKeyJwk as PublicJwk;
  }
  const header = JSON.parse(Buffer.from(String(proof.jws).split('.')[0] || '', 'base64url').toString('utf8'));
  if (header.alg !== 'ML-DSA-65') fail('Organization Test Network admission requires ML-DSA-65.');
  const valid = await input.cryptography.verifyDetachedJws(
    new TextEncoder().encode(canonicalizeOrganizationTestNetworkCredential(credential)),
    String(proof.jws),
    signerJwk,
  );
  if (!valid) fail('Organization Test Network admission proof is invalid.');

  const credentials = await verifyTestNetworkDomainCredentials({
    credentials: input.testNetworkCredentials,
    organizationTestNetworkCredential: credential,
    claims: input.claims,
    signerJwk,
    verificationMethod,
    controllerContact,
    legalRepresentativeEmail: input.legalRepresentativeEmail,
    legalRepresentativeTelephone: input.legalRepresentativeTelephone,
    cryptography: input.cryptography,
  });

  return {
    mode: 'organization-test-network-vc',
    credentialId: String(credential.id || ''),
    issuer,
    signer: signerDid,
    ...(typeof subject.applicationId === 'string' && typeof subject.applicationEvidence?.pdfSha256 === 'string'
      ? { applicationProof: { applicationId: subject.applicationId, pdfSha256: subject.applicationEvidence.pdfSha256 } }
      : {}),
    checks: {
      trustedIssuer: true,
      signerCurrentlyAuthorizedByIssuer: true,
      signerMethodActive: true,
      detachedPqcProof: true,
      applicationBinding: true,
    },
    credentials,
  };
}

function reviewedPartyContact(email: unknown, telephone: unknown, party: string): ActorContactInput {
  if ((email !== undefined && typeof email !== 'string')
    || (telephone !== undefined && typeof telephone !== 'string')) {
    fail(`Admission ${party} contact must be a string.`);
  }
  const hasEmail = typeof email === 'string' && Boolean(email.trim());
  const hasTelephone = typeof telephone === 'string' && Boolean(telephone.trim());
  if (hasEmail === hasTelephone) fail(`Admission ${party} requires exactly one email or telephone.`);
  const contactKind = hasEmail ? 'email' : 'phone';
  const contact = hasEmail ? email : telephone;
  if (typeof contact !== 'string') fail(`Admission ${party} contact is missing.`);
  try {
    return { contactKind, contact: normalizeActorContact({ contactKind, contact }) };
  } catch {
    return fail(`Admission ${party} contact is invalid.`);
  }
}

async function verifyTestNetworkDomainCredentials(input: Readonly<{
  credentials?: readonly VerifiableCredentialV2[];
  organizationTestNetworkCredential: VerifiableCredentialV2;
  claims: VerificationInput['claims'];
  signerJwk: PublicJwk;
  verificationMethod: string;
  controllerContact: ActorContactInput;
  legalRepresentativeEmail?: string;
  legalRepresentativeTelephone?: string;
  cryptography: ICryptography;
}>): Promise<readonly VerifiableCredentialV2[]> {
  const credentials = input.credentials || [];
  if (credentials.length !== 3) fail('Test Network admission requires exactly three domain credentials.');
  const find = (type: string) => credentials.filter(credential => credential.type.includes(type));
  const organization = find(ReviewedOrganizationCredentialTypes.Organization);
  const representative = find(ReviewedOrganizationCredentialTypes.LegalRepresentative);
  const controller = find(ReviewedOrganizationCredentialTypes.ServiceController);
  if (organization.length !== 1 || representative.length !== 1 || controller.length !== 1) {
    fail('Test Network admission requires Organization, LegalRepresentative and ServiceController credentials.');
  }
  const admissionSubject = input.organizationTestNetworkCredential.credentialSubject as Record<string, any>;
  const pdfEvidenceId = `urn:sha256:${String(admissionSubject.applicationEvidence?.pdfSha256 || '')}`;
  const controllerActor = buildStableActorIdentifier(input.controllerContact);
  const representativeActor = buildStableActorIdentifier(reviewedPartyContact(
    input.legalRepresentativeEmail, input.legalRepresentativeTelephone, 'legal representative',
  ));
  const reviewedOrganization = organization[0].credentialSubject;
  const identifier = reviewedOrganization.identifier as { value?: unknown; additionalType?: unknown } | undefined;
  const address = reviewedOrganization.address as { addressCountry?: unknown } | undefined;
  const offer = reviewedOrganization.makesOffer as { category?: unknown } | undefined;
  if (reviewedOrganization.id !== admissionSubject.id
    || reviewedOrganization.legalName !== admissionSubject.organization?.legalName
    || identifier?.value !== admissionSubject.organization?.identifier) {
    fail('Test Network OrganizationCredential does not match the admission VC.');
  }
  const sector = String(input.claims[SchemaOrgServiceClaim.Category] || '').trim();
  if (!sector || offer?.category !== sector) {
    fail('Reviewed organization sector does not match transaction claims.');
  }
  const country = String(input.claims[SchemaOrgOrganizationClaim.AddressCountry] || '').trim().toUpperCase();
  if (!country || address?.addressCountry !== country) {
    fail('Reviewed organization country does not match transaction claims.');
  }
  const identifierType = String(input.claims[SchemaOrgOrganizationClaim.IdentifierType] || '').trim();
  if (!identifierType || identifier?.additionalType !== identifierType) {
    fail('Reviewed organization identifier type does not match transaction claims.');
  }
  if (representative[0].credentialSubject.sameAs !== representativeActor) {
    fail('Test Network LegalRepresentativeCredential does not match the reviewed representative.');
  }
  const owner = controller[0].credentialSubject.owner;
  const ownerObject = owner !== null && typeof owner === 'object' ? owner : undefined;
  const ownerSameAs = ownerObject && 'sameAs' in ownerObject ? ownerObject.sameAs : undefined;
  const ownerRole = ownerObject && 'additionalType' in ownerObject ? ownerObject.additionalType : undefined;
  const ownerCredential = ownerObject && 'hasCredential' in ownerObject ? ownerObject.hasCredential : undefined;
  const ownerKeyMaterial = ownerCredential !== null && typeof ownerCredential === 'object' && 'material' in ownerCredential
    ? ownerCredential.material : undefined;
  if (ownerSameAs !== controllerActor
    || ownerRole !== 'RESPRSN'
    || ownerKeyMaterial !== admissionSubject.controller?.hasCredential?.material) {
    fail('Test Network ServiceControllerCredential does not match controller authority and key.');
  }
  for (const domainCredential of credentials) {
    if (!domainCredential.type.includes(ReviewedOrganizationCredentialTypes.TestNetwork)
      || domainCredential.issuer !== input.organizationTestNetworkCredential.issuer
      || !Array.isArray(domainCredential.evidence)
      || !(domainCredential.evidence as any[]).some(item => item?.id === pdfEvidenceId)) {
      fail('Test Network domain credential scope, issuer or PDF evidence is invalid.');
    }
    const proofs = Array.isArray(domainCredential.proof)
      ? domainCredential.proof : domainCredential.proof ? [domainCredential.proof] : [];
    const proof = proofs.find(item => item.proofPurpose === 'assertionMethod'
      && item.verificationMethod === input.verificationMethod && item.jws);
    if (!proof) fail('Test Network domain credential requires the reviewer assertion proof.');
    const header = JSON.parse(Buffer.from(String(proof.jws).split('.')[0] || '', 'base64url').toString('utf8'));
    if (header.alg !== 'ML-DSA-65') fail('Test Network domain credentials require ML-DSA-65.');
    const valid = await input.cryptography.verifyDetachedJws(
      new TextEncoder().encode(canonicalizeTestNetworkOrganizationCredential(domainCredential)),
      String(proof.jws),
      input.signerJwk,
    );
    if (!valid) fail('Test Network domain credential proof is invalid.');
  }
  return credentials;
}

function relationshipContains(
  relationship: Array<string | VerificationMethod> | undefined,
  methodId: string,
): boolean {
  return (relationship || []).some(item => typeof item === 'string' ? item === methodId : item.id === methodId);
}

async function resolveDidWebDocument(did: string, fetchImpl: typeof fetch): Promise<DidDocument> {
  if (!did.startsWith('did:web:')) fail('Admission proof requires did:web identities.');
  const parts = did.slice('did:web:'.length).split(':');
  const domain = decodeURIComponent(parts.shift() || '');
  const url = parts.length > 0
    ? `https://${domain}/${parts.map(decodeURIComponent).join('/')}/did.json`
    : `https://${domain}/.well-known/did.json`;
  const response = await fetchImpl(url, { headers: { accept: 'application/did+json, application/json' } });
  if (!response.ok) fail(`Could not resolve authorization DID '${did}'.`);
  const document = await response.json() as DidDocument;
  if (document.id !== did) fail(`Resolved authorization DID does not match '${did}'.`);
  return document;
}

function fail(message: string): never {
  throw new ManagerError(message, IssueType.Security);
}
