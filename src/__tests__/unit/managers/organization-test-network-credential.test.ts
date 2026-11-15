// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
/**
 * Flow contract: Test Network bypasses ICA only when the attached VC is bound
 * to the same reviewed application, organization and controller key, and a
 * currently authorized employee of a configured issuer supplied the
 * ML-DSA-65 proof. Tests cover both published DID governance and the explicit,
 * revocable Test Network signer registry used by the MVP.
 */
import { verifyOrganizationTestNetworkCredential } from '../../../managers/hosting/organization-test-network-credential';
import { processOrganizationVerificationTransaction } from '../../../managers/hosting/process-organization-verification';
import { buildOrganizationTestNetworkCredential } from 'gdc-common-utils-ts/utils/organization-test-network-credential';
import { buildTestNetworkOrganizationCredentialSet } from 'gdc-common-utils-ts/utils/test-network-organization-credentials';
import { SchemaOrgOfferClaim, SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import { readFileSync } from 'node:fs';
import { createECDH } from 'node:crypto';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { canonicalizeOrganizationTestNetworkCredential, canonicalizeTestNetworkOrganizationCredential } from 'antifraud-data-utils-ts/organization-credentials';
import { toJwkThumbprintSha256Urn as ownedThumbprint } from 'antifraud-data-utils-ts/jwk-thumbprints';
import { REPOSITORY_SAFE_EXAMPLES as safe } from 'sos-data-utils-ts/repository-privacy';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import type { JsonValue } from 'antifraud-data-utils-ts/identity-assurance';
import type { ReviewedOrganizationCredential } from 'antifraud-data-utils-ts/organization-credentials';

const controllerJwk = { kty: 'AKP', alg: 'ML-DSA-65', pub: 'controller-public' } as const;
const signerJwk = { kid: 'pqc', kty: 'AKP', alg: 'ML-DSA-65', pub: 'unid-signer-public' } as const;
const issuer = 'did:web:unid.example:VATES-G02793479';
const signer = 'did:web:unid.example:VATES-G02793479:member:cto';
const organizationDid = 'did:web:host.example:VATES-B00112233';

function credential() {
  const unsigned = buildOrganizationTestNetworkCredential({
    issuerDid: issuer,
    subjectDid: organizationDid,
    credentialId: 'urn:uuid:application-dsrc',
    validFrom: '2026-08-10T00:00:00.000Z',
    validUntil: '2027-08-10T00:00:00.000Z',
    legalName: 'DSRC',
    organizationIdentifier: 'VATES-B00112233',
    controllerEmail: 'developer@dsrc.example',
    controllerKeyMaterial: toJwkThumbprintSha256Urn(controllerJwk),
    applicationId: 'application-dsrc',
    accessPath: 'test-network',
  });
  return {
    ...unsigned,
    credentialSubject: {
      ...unsigned.credentialSubject,
      applicationEvidence: { pdfSha256: 'a'.repeat(64) },
    },
    proof: {
      type: 'JsonWebSignature2020',
      proofPurpose: 'contractAgreement',
      verificationMethod: `${signer}#pqc`,
      publicKeyJwk: signerJwk,
      jws: `${Buffer.from(JSON.stringify({ alg: 'ML-DSA-65' })).toString('base64url')}..signature`,
    },
  };
}

function domainCredentials() {
  return buildTestNetworkOrganizationCredentialSet({
    issuerDid: issuer,
    organizationDid,
    applicationId: 'application-dsrc',
    validFrom: '2026-08-10T00:00:00.000Z',
    validUntil: '2027-08-10T00:00:00.000Z',
    pdfSha256: 'a'.repeat(64),
    documentVersion: '2026081001',
    legalName: 'DSRC',
    organizationIdentifier: 'VATES-B00112233',
    identifierType: 'taxID',
    addressCountry: 'ES',
    serviceCategory: 'health-care',
    legalRepresentativeEmail: 'developer@dsrc.example',
    legalRepresentativeFullName: 'Example Representative',
    controllerEmail: 'developer@dsrc.example',
    controllerKeyMaterial: toJwkThumbprintSha256Urn(controllerJwk),
  }).map(item => ({
    ...item,
    proof: {
      type: 'JsonWebSignature2020',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${signer}#pqc`,
      jws: `${Buffer.from(JSON.stringify({ alg: 'ML-DSA-65' })).toString('base64url')}..signature`,
    },
  }));
}

describe('organization Test Network credential verifier', () => {
  it('has no symmetric portal-to-host key-enrollment bypass', () => {
    const verifier = readFileSync('src/managers/hosting/organization-test-network-credential.ts', 'utf8');
    const manager = readFileSync('src/managers/HostingManager.ts', 'utf8');
    expect(`${verifier}\n${manager}`).not.toMatch(/allowHostAttestedKeys|hostAttestationSecret|verifyHostAttestation/);
  });

  it('accepts a current UNID controller proof bound to the submitted application', async () => {
    const fetchImpl = jest.fn(async (url: string | URL | Request) => {
      const value = String(url);
      const document = value.includes('/member/cto/')
        ? {
            '@context': 'https://www.w3.org/ns/did/v1',
            id: signer,
            verificationMethod: [{ id: `${signer}#pqc`, type: 'JsonWebKey2020', controller: signer, publicKeyJwk: signerJwk }],
            assertionMethod: [`${signer}#pqc`],
          }
        : { '@context': 'https://www.w3.org/ns/did/v1', id: issuer, controller: [signer] };
      return { ok: true, json: async () => document } as Response;
    }) as typeof fetch;
    const verifyDetachedJws = jest.fn().mockResolvedValue(true);

    const result = await verifyOrganizationTestNetworkCredential({
      credential: credential(),
      claims: { [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233' },
      controller: { publicKeyJwk: controllerJwk },
      organization: { did: organizationDid },
      controllerEmail: 'developer@dsrc.example',
      legalRepresentativeEmail: 'developer@dsrc.example',
      testNetworkCredentials: domainCredentials(),
      cryptography: { verifyDetachedJws } as any,
      trustedIssuers: [issuer],
      fetchImpl,
      now: new Date('2026-08-10T12:00:00.000Z'),
    });

    expect(result.mode).toBe('organization-test-network-vc');
    expect(result.signer).toBe(signer);
    expect(result.checks).not.toHaveProperty('postalDelivered');
    expect(verifyDetachedJws).toHaveBeenCalledTimes(4);
  });

  it('fails closed after the signer is removed from the issuer controller list', async () => {
    const fetchImpl = jest.fn(async (url: string | URL | Request) => ({
      ok: true,
      json: async () => String(url).includes('/member/cto/')
        ? {
            '@context': 'https://www.w3.org/ns/did/v1', id: signer,
            verificationMethod: [{ id: `${signer}#pqc`, publicKeyJwk: signerJwk }],
            assertionMethod: [`${signer}#pqc`],
          }
        : { '@context': 'https://www.w3.org/ns/did/v1', id: issuer, controller: [] },
    })) as unknown as typeof fetch;
    await expect(verifyOrganizationTestNetworkCredential({
      credential: credential(),
      claims: { [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233' },
      controller: { publicKeyJwk: controllerJwk },
      organization: { did: organizationDid },
      controllerEmail: 'developer@dsrc.example',
      cryptography: { verifyDetachedJws: jest.fn() } as any,
      trustedIssuers: [issuer],
      fetchImpl,
      now: new Date('2026-08-10T12:00:00.000Z'),
    })).rejects.toThrow('not a current issuer controller');
  });

  it('accepts the MVP signer registry without pretending the employee DID is already published', async () => {
    const fetchImpl = jest.fn();
    const verifyDetachedJws = jest.fn().mockResolvedValue(true);
    const result = await verifyOrganizationTestNetworkCredential({
      credential: credential(),
      claims: { [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233' },
      controller: { publicKeyJwk: controllerJwk },
      organization: { did: organizationDid },
      controllerEmail: 'developer@dsrc.example',
      legalRepresentativeEmail: 'developer@dsrc.example',
      testNetworkCredentials: domainCredentials(),
      cryptography: { verifyDetachedJws } as any,
      trustedIssuers: [issuer],
      trustedSigners: [{
        issuer,
        actorDid: signer,
        role: 'RESPRSN',
        status: 'active',
        jwkThumbprints: [toJwkThumbprintSha256Urn(signerJwk)],
      }],
      fetchImpl: fetchImpl as typeof fetch,
      now: new Date('2026-08-10T12:00:00.000Z'),
    });

    expect(result.checks.signerCurrentlyAuthorizedByIssuer).toBe(true);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(verifyDetachedJws).toHaveBeenCalledWith(expect.any(Uint8Array), expect.any(String), signerJwk);
  });

  it('fails closed when the MVP signer registry revokes the employee', async () => {
    await expect(verifyOrganizationTestNetworkCredential({
      credential: credential(),
      claims: { [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233' },
      controller: { publicKeyJwk: controllerJwk },
      organization: { did: organizationDid },
      controllerEmail: 'developer@dsrc.example',
      cryptography: { verifyDetachedJws: jest.fn() } as any,
      trustedIssuers: [issuer],
      trustedSigners: [{
        issuer,
        actorDid: signer,
        role: 'RESPRSN',
        status: 'revoked',
        jwkThumbprints: [toJwkThumbprintSha256Urn(signerJwk)],
      }],
      now: new Date('2026-08-10T12:00:00.000Z'),
    })).rejects.toThrow('signer is revoked');
  });
});

describe('Test Network transaction routing', () => {
  it('uses the attached Test Network admission credential and never calls ICA', async () => {
    const organizationTestNetworkCredential = credential();
    const issuedCredentials = domainCredentials();
    const forwardToIca = jest.fn();
    const createPendingTenantRegistrationFromClaims = jest.fn(async () => ({
      ...claims,
      [SchemaOrgOfferClaim.Identifier]: 'urn:example:Offer:dsrc',
    }));
    const verifyTestNetworkAdmissionCredential = jest.fn().mockResolvedValue({
      mode: 'organization-test-network-vc',
      credentialId: organizationTestNetworkCredential.id,
      issuer,
      signer,
      checks: {},
      credentials: issuedCredentials,
    });
    const claims = {
      [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233',
      [SchemaOrgServiceClaim.Category]: 'health-care',
    };
    const response = await processOrganizationVerificationTransaction({
      job: {
        action: 'Organization/_transaction',
        tenantId: 'host',
        sector: 'test-network',
        content: {
          thid: 'transaction-dsrc',
          iss: 'did:web:controller.dsrc.example',
          body: { data: [{
            resource: {
              meta: { claims },
              organizationTestNetworkCredential,
              testNetworkCredentials: issuedCredentials,
              verification: { resourceType: 'contract' },
              organization: { did: organizationDid },
              controller: { email: 'developer@dsrc.example', publicKeyJwk: controllerJwk },
              legalRepresentativePayload: { email: 'developer@dsrc.example' },
            },
          }] },
        },
      } as any,
      issuerDid: 'did:web:host.example',
      config: { namespace: 'example', sectorsAllowed: [], networkMode: 'test-network' },
      normalizeClaims: value => value,
      createPendingTenantRegistrationFromClaims,
      createOrganizationIssueClaimsFromClaims: jest.fn(),
      forwardOrganizationVerificationTransactionToIca: forwardToIca,
      extractCredentialResourcesFromIcaPayload: jest.fn(),
      verifyTestNetworkAdmissionCredential,
    });

    expect(forwardToIca).not.toHaveBeenCalled();
    expect(verifyTestNetworkAdmissionCredential).toHaveBeenCalledTimes(1);
    expect(createPendingTenantRegistrationFromClaims).toHaveBeenCalledWith(
      expect.not.objectContaining({ postalActivationCodeBinding: expect.anything() }),
    );
    expect(response.body.data[0]?.resource).toMatchObject({
      verificationResponse: { mode: 'organization-test-network-vc' },
      next: { action: 'Order/_batch' },
    });
    expect(response.body.data[0]?.resource.verificationResponse).not.toHaveProperty('credentials');
    expect(response.body.data[0]?.vc).toEqual(issuedCredentials);
  });

  it('runs the same reviewed Test Network transaction in the explicit in-memory demo stage', async () => {
    const organizationTestNetworkCredential = credential();
    const issuedCredentials = domainCredentials();
    const forwardToIca = jest.fn();
    const verifyTestNetworkAdmissionCredential = jest.fn().mockResolvedValue({
      mode: 'organization-test-network-vc',
      credentials: issuedCredentials,
    });
    const claims = {
      [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00112233',
      [SchemaOrgServiceClaim.Category]: 'health-care',
    };

    await expect(processOrganizationVerificationTransaction({
      job: {
        action: 'Organization/_transaction', tenantId: 'host', sector: 'test',
        content: { thid: 'transaction-local-demo', body: { data: [{
          resource: {
            meta: { claims },
            organizationTestNetworkCredential,
            testNetworkCredentials: issuedCredentials,
            verification: { resourceType: 'contract' },
            organization: { did: organizationDid },
            controller: { email: 'developer@dsrc.example', publicKeyJwk: controllerJwk },
            legalRepresentativePayload: { email: 'developer@dsrc.example' },
          },
        }] } },
      } as any,
      issuerDid: 'did:web:host.example',
      config: { namespace: 'example', sectorsAllowed: [], networkMode: 'test', securityMode: 'demo' },
      normalizeClaims: value => value,
      createPendingTenantRegistrationFromClaims: jest.fn(async () => ({
        ...claims,
        [SchemaOrgOfferClaim.Identifier]: 'urn:example:Offer:local-demo',
      })),
      createOrganizationIssueClaimsFromClaims: jest.fn(),
      forwardOrganizationVerificationTransactionToIca: forwardToIca,
      extractCredentialResourcesFromIcaPayload: jest.fn(),
      verifyTestNetworkAdmissionCredential,
    })).resolves.toMatchObject({ body: { data: [expect.objectContaining({ vc: issuedCredentials })] } });
    expect(forwardToIca).not.toHaveBeenCalled();
    expect(verifyTestNetworkAdmissionCredential).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['network route', 'network', 'test-network', undefined],
    ['network runtime', 'test-network', 'network', undefined],
    ['non-demo test runtime', 'test', 'test', 'strict'],
  ])('rejects the Test Network admission credential on a %s', async (_label, sector, networkMode, securityMode) => {
    const organizationTestNetworkCredential = credential();
    await expect(processOrganizationVerificationTransaction({
      job: {
        action: 'Organization/_transaction', tenantId: 'host', sector,
        content: { thid: 'transaction-dsrc', body: { data: [{
          resource: {
            meta: { claims: { [SchemaOrgServiceClaim.Category]: 'health-care' } },
            organizationTestNetworkCredential,
            verification: { resourceType: 'contract' },
          },
        }] } },
      } as any,
      issuerDid: 'did:web:host.example',
      config: { namespace: 'example', sectorsAllowed: [], networkMode, securityMode },
      normalizeClaims: value => value,
      createPendingTenantRegistrationFromClaims: jest.fn(),
      createOrganizationIssueClaimsFromClaims: jest.fn(),
      forwardOrganizationVerificationTransactionToIca: jest.fn(),
      extractCredentialResourcesFromIcaPayload: jest.fn(),
      verifyTestNetworkAdmissionCredential: jest.fn(),
    })).rejects.toThrow('Test Network or its explicit in-memory demo simulation');
  });
});

describe('reviewed Organization contact with real ML-DSA-65 proofs', () => {
  // Validate the complete JSON wire before invoking the independently owned
  // canonicalizer; proof is intentionally excluded from detached signing.
  function json(value: unknown): JsonValue {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (Array.isArray(value)) return value.map(json);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, json(item)]));
    throw new TypeError('Fixture must contain JSON values');
  }
  function jsonObject(value: JsonValue | undefined): value is Readonly<Record<string, JsonValue>> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function reviewed(value: Parameters<typeof verifyOrganizationTestNetworkCredential>[0]['credential']): ReviewedOrganizationCredential {
    const subject = json(value.credentialSubject);
    if (!value.id || !value.validUntil || !jsonObject(subject)) {
      throw new TypeError('Fixture requires a complete reviewed credential');
    }
    return { '@context': value['@context'], id: value.id, type: value.type, issuer: value.issuer,
      validFrom: value.validFrom, validUntil: value.validUntil, credentialSubject: subject,
      ...(value.evidence ? { evidence: value.evidence.map(json) } : {}) };
  }
  async function signedFixture(contactKind: 'email' | 'phone') {
    const cryptography = new CryptographyService(new AdapterCryptoSdkNode());
    const key = await cryptography.generateKeyPairMlDsa(new Uint8Array(32).fill(37), 'ML-DSA-65');
    const curve = createECDH('secp384r1');
    const scalar = new Uint8Array(48).fill(1);
    curve.setPrivateKey(scalar);
    scalar.fill(0);
    const point = curve.getPublicKey(undefined, 'uncompressed');
    const controllerPublicJwk = { kty: 'EC', crv: 'P-384', alg: 'ES384',
      x: point.subarray(1, 49).toString('base64url'), y: point.subarray(49, 97).toString('base64url') } as const;
    const keyMaterial = ownedThumbprint(controllerPublicJwk);
    const contact = contactKind === 'phone' ? safe.phoneE164 : safe.individualEmail;
    const actor = buildStableActorIdentifier({ contactKind, contact });
    const base = credential();
    const subject = json(base.credentialSubject);
    if (!jsonObject(subject) || !jsonObject(subject.organization) || typeof subject.organization.identifier !== 'string') {
      throw new TypeError('Fixture requires its original organization identifier');
    }
    const organizationIdentifier = subject.organization.identifier;
    const admissionDraft = {
      ...base,
      credentialSubject: {
        ...base.credentialSubject,
        controller: {
          ...(contactKind === 'phone' ? { telephone: contact } : { email: contact }),
          hasCredential: { material: keyMaterial },
        },
      },
    };
    const domainDrafts = domainCredentials().map(item => ({
      ...item,
      credentialSubject: {
        ...item.credentialSubject,
        ...(item.type.includes('LegalRepresentativeCredential') ? { id: actor, sameAs: actor } : {}),
        ...(item.type.includes('ServiceControllerCredential')
          ? { owner: { ...item.credentialSubject.owner, sameAs: actor,
            hasCredential: { material: keyMaterial } } } : {}),
      },
    }));
    const header = Buffer.from(JSON.stringify({ alg: 'ML-DSA-65', b64: false, crit: ['b64'] })).toString('base64url');
    async function detached(canonical: string) {
      const bytes = Buffer.concat([Buffer.from(`${header}.`, 'ascii'), Buffer.from(canonical, 'utf8')]);
      const signature = await cryptography.signBytes(bytes, key.secretKeyBytes, 'ML-DSA-65');
      return `${header}..${Buffer.from(signature).toString('base64url')}`;
    }
    const admission = { ...admissionDraft, proof: {
      ...admissionDraft.proof,
      verificationMethod: `${signer}#${key.publicJWKey.kid}`,
      publicKeyJwk: key.publicJWKey,
      jws: await detached(canonicalizeOrganizationTestNetworkCredential(reviewed(admissionDraft))),
    } };
    const domains = await Promise.all(domainDrafts.map(async item => ({ ...item, proof: {
        ...item.proof,
        verificationMethod: `${signer}#${key.publicJWKey.kid}`,
        jws: await detached(canonicalizeTestNetworkOrganizationCredential(reviewed(item))),
      } })));
    key.secretKeyBytes.fill(0);
    return {
      credential: admission,
      claims: { [SchemaOrgOrganizationClaim.IdentifierValue]: organizationIdentifier },
      controller: { publicKeyJwk: controllerPublicJwk },
      organization: { did: organizationDid },
      ...(contactKind === 'phone'
        ? { controllerTelephone: contact, legalRepresentativeTelephone: contact }
        : { controllerEmail: contact, legalRepresentativeEmail: contact }),
      testNetworkCredentials: domains,
      cryptography,
      trustedIssuers: [issuer],
      trustedSigners: [{ issuer, actorDid: signer, role: 'RESPRSN', status: 'active' as const,
        jwkThumbprints: [ownedThumbprint(key.publicJWKey)] }],
      now: new Date('2026-08-10T12:00:00.000Z'),
    };
  }

  it('accepts reviewed telephone-only parties with four verified detached signatures', async () => {
    const input = await signedFixture('phone');
    const result = await verifyOrganizationTestNetworkCredential(input);
    expect(result.credentials).toHaveLength(3);
    expect(result.checks.detachedPqcProof).toBe(true);
  });

  it('retains real-signature email admission compatibility', async () => {
    expect((await verifyOrganizationTestNetworkCredential(await signedFixture('email'))).credentials).toHaveLength(3);
  });

  it('rejects a different transaction telephone and ambiguous contact channels', async () => {
    const input = await signedFixture('phone');
    const wrongTelephone = { ...input, controllerTelephone: safe.firstContactPhoneE164 };
    await expect(verifyOrganizationTestNetworkCredential(wrongTelephone)).rejects.toThrow();
    await expect(verifyOrganizationTestNetworkCredential({ ...input,
      controllerEmail: safe.individualEmail })).rejects.toThrow();
  });

  it('retains revoked reviewer and tampered proof denials for telephone admission', async () => {
    const input = await signedFixture('phone');
    await expect(verifyOrganizationTestNetworkCredential({ ...input,
      trustedSigners: input.trustedSigners.map(entry => ({ ...entry, status: 'revoked' as const })) })).rejects.toThrow('revoked');
    const jws = input.credential.proof.jws;
    await expect(verifyOrganizationTestNetworkCredential({ ...input,
      credential: { ...input.credential, proof: { ...input.credential.proof,
        jws: `${jws.slice(0, -8)}AAAAAAAA` } } })).rejects.toThrow('proof is invalid');
  });
});
