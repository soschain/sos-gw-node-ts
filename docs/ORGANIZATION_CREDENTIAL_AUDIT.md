# Verify legal identity and fiscal registration

Use the scoped host or tenant base URL and append `/.well-known/` followed by the filename.

| Filename | What the verifier receives |
| --- | --- |
| `vc.json` | The organization's Legal Person declaration, signed by the organization with a detached proof. |
| `self-description.json` | The original participant-signed Gaia-X self-description as credential JSON. Verify its detached proof with the participant's assertion key. |
| `legal-participant.vc.json` | The same Legal Person declaration in a signed JWT. The W3C envelope's top-level `id` contains the JWT after `data:application/vc+jwt,`. |
| `organization.json` | The `OrganizationCredential` identifies the Schema.org `Organization`, gives its legal identifier and carries any evidence included by the issuer. The host may publish a self-signed statement. An ICA-issued credential is published with its original issuer, evidence and proofs. For enrollment by digitally signed PDF, the ICA's evidence records the document digest and the signature and certificate checks. |

## Professional credentials

The application contract distinguishes an organization's legal identity from a professional's employment authorization. A professional `EmployeeCredential` used in SMART presentations uses Schema.org person properties. It identifies the professional by DID, carries the role in `hasOccupation` and can include a normalized email hash in `sameAs`, a hashed telephone and a reference to public signing material. The base projection omits the name and raw contact fields. A stable contact hash is a pseudonymous identifier.

Deliver a professional credential through an authenticated flow scoped to the holder and organization. The public `vc.json` file below is reserved for organization discovery. A public professional DID can supply verification keys. The credential belongs in the holder's protected profile or wallet. For wallet issuance, OpenID4VCI binds the issued credential to the wallet's public key. OpenID4VP lets the holder prove control of that key when presenting the credential. [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html) · [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)

A professional SMART Health Card is a separate signed FHIR representation of the authorization. It carries an `Organization`, a `Practitioner` and a `PractitionerRole` in a FHIR `Bundle`. Verify its issuer signature and authorization reference. Issuing this representation requires a FHIR projection and signature.

The gateway's existing `/identity/oidc/credential` route issues the legacy Gaia-X `LegalParticipant` credential. It rejects professional and OpenID4VCI configuration requests. The professional wallet flow requires its own holder-authorized issuance from the tenant.

The portal prepares the offer through the professional's unlocked profile at
`/{tenantId}/cds-{jurisdiction}/v1/{sector}/identity/openid/wallet/_authorize`.
The employing tenant serves the offer, issuer metadata, code exchange, nonce
and credential endpoint. The wallet supplies a signature over the tenant's
issuer URL and nonce to prove that it controls the key. The tenant rechecks
the professional's registered device, employment and licence, then signs the
credential with its own key. The SD-JWT binds to the wallet key and carries
the professional occupation as a selective disclosure. The ICA issues
organization credentials for admission to the data space.

Configure `PROFESSIONAL_WALLET_PROFILE_JSON` with `tenantId`, `jurisdiction`,
`sector`, `configurationId` and the profile's `vct` URL. Use the tenant
issuer's HTTPS gateway origin. A local TLS listener may supply the HTTPS
loopback origin through `PROFESSIONAL_WALLET_PUBLIC_ORIGIN`. All hosted
gateway replicas use the same base64url `PROFESSIONAL_WALLET_OFFER_SECRET`
with at least 32 random bytes and the same Firestore database. Enable TTL on
`deleteAfter` in the `wallet-offers-<sha256(hostCollectionName)>` collection
group. Set `credentialSigningAlgorithm` to `ML-DSA-65` for the data-space
wallet profile. `ES256` is the default compatibility profile for existing
wallet integrations. The tenant publishes the configured assertion key in
its DID document. Configure an ES256 pilot before enrolling its tenant to
provision that key. The holder's proof uses its own ES256 key. The issued
credential continues to use the tenant algorithm advertised by its profile.
The signed profile assertion targets the exact configured gateway
`_authorize` URL.

See the [request examples](./openapi-examples/core-flow-examples.json) under
`PROFESSIONAL_WALLET_REQUESTS`.

### Shared wallet integration

Antifraud SDK Core owns the transport-independent offer and presentation contracts. Its Node adapter calls the issuer and verifier services from an authenticated backend. Its frontend adapter opens a validated wallet offer and resumes the transaction after the wallet returns. An installed app supplies native linking and secure storage adapters for the same flow.

SOS SDK Core supplies the professional credential profile and the organization, active employment and role checks. SOS SDK Node exposes the server operation to the portal backend. The portal and installed app display the same operation and status. The issuer signs with the tenant's credential signing key after confirming eligibility. The holder's signing key remains in the wallet.

## Verify the credential and its evidence

Start at `organization.json`. Read `credentialSubject.identifier` and `credentialSubject.taxID` when present. Check every available entry in `proof` against its `verificationMethod`. A host self-signature establishes who made the statement and protects its contents. Evidence in an ICA-issued credential describes the checks that the ICA attests to. Each additional proof must verify against the credential it signs and be assessed against the authority of its signer.

The gateway retains every endorsement of the host's existing organization
statement. For locally issued JSON, it can add a compatible detached EC
proof alongside a detached ML-DSA-65 assertion over the same contents.
An ICA-issued organization credential keeps its exact published bytes
and original proofs. A change to signed contents requires fresh signatures.

The Gaia-X compact VC-JWT uses the issuer's compatible EC assertion key.
The gateway uses ML-DSA-65 for newly provisioned credential assertion keys,
including employee issuance through the internal credential issuer. A
tenant carrying a historical ML-DSA-44 key needs an additive key migration
before it can publish a new ML-DSA-65 proof. Changing the generation
default does not rotate stored keys.

1. Download either representation of the participant declaration. Resolve its issuer's DID, confirm that its assertion key is authorized, and verify the signature. Decoding the JWT only reveals the claims.
2. If the signed declaration includes a `relatedResource[].id` ending in `/organization.json`, follow that link. Compute a SHA-256 digest of the response bytes before reformatting the JSON, encode the digest in standard Base64, and compare it with `digestSRI` after `sha256-`.
3. Verify the original ICA credential's proof using the ICA issuer's published verification material. Confirm that the ICA is trusted for organization issuance by the data space and check validity and status where available.
4. Compare `credentialSubject["https://schema.org/taxID"]` in the declaration with `credentialSubject.taxID` in the ICA credential. Review the ICA-signed `evidence` to establish what was checked and whether the identifier came from the certificate or the signed document. An auditor with authorized access to the original PDF can independently check its digest and digital signature.

The gateway publishes the signed link when the admitted ICA credential contains evidence and its fiscal identifier matches the participant's configured identifier. The host's self-signed organization statement remains independently verifiable by checking its signature against the host DID.

With the repository dependencies installed, this Node command runs on Windows, macOS and Linux. Pass the full scoped URL before `/.well-known/`. Repeat `--tenant` for each tenant in the verification inventory.

```text
node scripts/verify-organization-publications.mjs --host <host-scoped-base-url> --tenant <tenant-scoped-base-url>
```

The command verifies the JWT envelope, both signed Gaia-X JSON publications, the organization credential and any signed evidence link. Issuer authorization, credential status and the validity of an underlying document are separate audit checks.

For an archived `OrganizationCredential`, pass its exact URL and the trusted ICA origin. This mode verifies the organization's proofs and reports evidence presence. It checks a historical `did:jwt` against the ICA's public assertion key and its JWK thumbprint.

```text
node scripts/verify-organization-publications.mjs --organization <credential-url> --ica <trusted-ica-origin>
```

## Standards and scope

- The ICA evidence for PDF enrollment uses the **OpenID Identity Assurance** evidence model to describe the checks behind the verified claims. The ICA proof authenticates those claims and their evidence. [OpenID Identity Assurance Schema Definition](https://openid.net/specs/openid-ida-verified-claims-1_0.html)
- The signed `relatedResource` binds the Legal Person declaration to the actual ICA credential through its URL and content digest. [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources)
- **Gaia-X Loire** describes how a participant signs a Legal Person declaration and obtains a separate Legal Registration Number credential from a Gaia-X Digital Clearing House notary. The data space's ICA credential supports its own legal identity and registration checks. A formal Loire conformity claim requires the separate notary credential and the Gaia-X compliance process. [Gaia-X Loire participant process](https://docs.gaia-x.eu/policy-rules-committee/compliance-document/3.0.0/Process/#1312-process-description)
