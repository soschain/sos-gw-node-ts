// Local image-gate fixture only. This does not operate a deployed ICA, establish
// production trust, or read/rewrite any existing credential or signing key.
import { createHash, randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, calculateJwkThumbprint, FlattenedSign, importJWK, SignJWT } from 'jose';
import canonicalize from 'canonicalize';
import { buildTestNetworkOrganizationCredentialSet } from 'antifraud-data-utils-ts/organization-credentials';
import { toJwkThumbprintSha256Urn } from 'antifraud-data-utils-ts/jwk-thumbprints';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';

/** Issue only governed synthetic evidence for one explicit local Fabric run. */
export async function createLocalFabricFixtureIssuer({ profile, controllerJwk, organizationDid = `${e.didWeb}:organization`, deferIssuance = false }) {
  if (profile !== 'local-fabric' || [process.env.NODE_ENV, process.env.DEPLOYMENT_ENV].some(value => ['staging', 'production', 'prod'].includes(String(value || '').toLowerCase()))) {
    throw new Error('Synthetic fixture issuance is restricted to the explicit local Fabric harness.');
  }
  const issuerDid = `${e.didWeb}:ica`;
  const pair = await generateKeyPair('ES384');
  const publicJwk = { ...await exportJWK(pair.publicKey), alg: 'ES384', use: 'sig' };
  publicJwk.kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  const credentials = []; const states = new Map();
  async function issueOrganizationSet({ controllerJwk, organizationDid = `${e.didWeb}:organization` }) {
    if (credentials.length) throw new Error('This local fixture already issued its organization credential set.');
  if (!controllerJwk || typeof controllerJwk !== 'object' || !['EC', 'AKP'].includes(controllerJwk.kty)
    || ['d', 'k', 'priv', 'dBytes', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some(key => Object.hasOwn(controllerJwk, key))) {
    throw new Error('A public asymmetric controller key is required.');
  }
  if (controllerJwk.kty === 'EC') await importJWK(controllerJwk, controllerJwk.alg || 'ES384');
  else if (!['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'].includes(controllerJwk.alg)
    || typeof controllerJwk.pub !== 'string' || !/^[A-Za-z0-9_-]+$/.test(controllerJwk.pub)) throw new Error('A public supported controller signing key is required.');
  if (typeof organizationDid !== 'string' || organizationDid.length > 2048 || !/^did:web:[A-Za-z0-9._:%-]+$/.test(organizationDid)) throw new Error('The caller must supply its canonical organization DID.');
  const now = Date.now();
  const drafts = buildTestNetworkOrganizationCredentialSet({
    issuerDid, organizationDid, applicationId: randomUUID(),
    validFrom: new Date(now - 1000).toISOString(), validUntil: new Date(now + 900_000).toISOString(),
    pdfSha256: createHash('sha256').update('synthetic local image-gate evidence').digest('hex'), documentVersion: 'local-fixture',
    legalName: e.organizationLegalName, organizationIdentifier: e.organizationBusinessNumber,
    identifierType: e.organizationIdentifierType, addressCountry: e.countryIso2, serviceCategory: e.sector,
    legalRepresentativeFullName: `${e.individualGivenName} ${e.personFamilyName}`,
    legalRepresentativeEmail: e.individualEmail, controllerEmail: e.firstContactEmail,
    legalRepresentativeOccupation: HealthcareActorRoles.Controller,
    controllerOccupation: HealthcareActorRoles.Controller, controllerAuthorityRole: HealthcareActorRoles.Controller,
    controllerKeyMaterial: toJwkThumbprintSha256Urn(controllerJwk),
  });
  const issued = await Promise.all(drafts.map(async draft => {
    const signed = await new FlattenedSign(new TextEncoder().encode(canonicalize(draft)))
      .setProtectedHeader({ alg: 'ES384', kid: publicJwk.kid }).sign(pair.privateKey);
    return { ...draft, proof: { type: 'JsonWebSignature2020', created: new Date(now).toISOString(),
      verificationMethod: `${issuerDid}#${publicJwk.kid}`, proofPurpose: 'assertionMethod',
      jws: `${signed.protected}..${signed.signature}` } };
  }));
  credentials.push(...issued);
  for (const credential of issued) states.set(credential.id, 'good');
  return issued;
  }
  if (!deferIssuance) await issueOrganizationSet({ controllerJwk, organizationDid });
  return {
    issuerDid, jwks: { keys: [publicJwk] }, get credentials() { return [...credentials]; }, issueOrganizationSet,
    status: id => states.get(id) || 'unknown',
    async mintOidc({ issuer, subject, email, audience }) {
      const origin = new URL(issuer);
      if (origin.protocol !== 'https:' || !['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'].includes(origin.hostname)
        || issuer !== origin.origin || origin.username || origin.password || !subject || !email || !audience) throw new Error('OIDC fixture issuer and claims must use the explicit local harness.');
      const timestamp = Math.floor(Date.now() / 1000);
      return new SignJWT({ email, email_verified: true }).setProtectedHeader({ alg: 'ES384', kid: publicJwk.kid })
        .setIssuer(issuer).setSubject(subject).setAudience(audience).setIssuedAt(timestamp).setExpirationTime(timestamp + 120)
        .setJti(randomUUID()).sign(pair.privateKey);
    },
    revoke(id) { if (!states.has(id)) throw new Error('Unknown local fixture credential.'); states.set(id, 'revoked'); },
  };
}
