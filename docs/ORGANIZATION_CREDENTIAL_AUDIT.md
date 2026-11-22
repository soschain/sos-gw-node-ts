# Verify legal identity and fiscal registration

Use the scoped host or tenant base URL and append `/.well-known/` followed by the filename.

| Filename | What the verifier receives |
| --- | --- |
| `vc.json` | The organization's Legal Person declaration, signed by the organization with a detached proof. |
| `legal-participant.vc.json` | The same Legal Person declaration in a signed JWT. The W3C envelope's top-level `id` contains the JWT after `data:application/vc+jwt,`. |
| `organization.json` | The `OrganizationCredential` identifies the Schema.org `Organization`, gives its legal identifier and carries any evidence included by the issuer. The host may publish a self-signed statement. An ICA-issued credential is published with its original issuer, evidence and proofs. For enrollment by digitally signed PDF, the ICA's evidence records the document digest and the signature and certificate checks. |

## Verify the credential and its evidence

Start at `organization.json`. Read `credentialSubject.identifier` and `credentialSubject.taxID` when present. Check every available entry in `proof` against its `verificationMethod`. A host self-signature establishes who made the statement and protects its contents. Evidence in an ICA-issued credential describes the checks that the ICA attests to. Each additional proof must verify against the credential it signs and be assessed against the authority of its signer.

When the host has an existing organization statement with additional proofs, the gateway returns that original statement with its complete proof set. A change to the signed contents requires a new signature from each attesting party.

1. Download either representation of the participant declaration. Resolve its issuer's DID, confirm that its assertion key is authorized, and verify the signature. Decoding the JWT only reveals the claims.
2. If the signed declaration includes a `relatedResource[].id` ending in `/organization.json`, follow that link. Compute a SHA-256 digest of the response bytes before reformatting the JSON, encode the digest in standard Base64, and compare it with `digestSRI` after `sha256-`.
3. Verify the original ICA credential's proof using the ICA issuer's published verification material. Confirm that the ICA is trusted for organization issuance by the data space and check validity and status where available.
4. Compare `credentialSubject["https://schema.org/taxID"]` in the declaration with `credentialSubject.taxID` in the ICA credential. Review the ICA-signed `evidence` to establish what was checked and whether the identifier came from the certificate or the signed document. An auditor with authorized access to the original PDF can independently check its digest and digital signature.

The gateway publishes the signed link when the admitted ICA credential contains evidence and its fiscal identifier matches the participant's configured identifier. The host's self-signed organization statement remains independently verifiable by checking its signature against the host DID.

With the repository dependencies installed, this Node command runs on Windows, macOS and Linux. Pass the full scoped URL before `/.well-known/`. Repeat `--tenant` for each tenant in the verification inventory.

```text
node scripts/verify-organization-publications.mjs --host <host-scoped-base-url> --tenant <tenant-scoped-base-url>
```

The command verifies the JWT envelope, signatures and any signed evidence link. Issuer authorization, credential status and the validity of an underlying document are separate audit checks.

For an archived `OrganizationCredential`, pass its exact URL and the trusted ICA origin. This mode verifies the organization's proofs and reports evidence presence. It checks a historical `did:jwt` against the ICA's public assertion key and its JWK thumbprint.

```text
node scripts/verify-organization-publications.mjs --organization <credential-url> --ica <trusted-ica-origin>
```

## Standards and scope

- The ICA evidence for PDF enrollment uses the **OpenID Identity Assurance** evidence model to describe the checks behind the verified claims. The ICA proof authenticates those claims and their evidence. [OpenID Identity Assurance Schema Definition](https://openid.net/specs/openid-ida-verified-claims-1_0.html)
- The signed `relatedResource` binds the Legal Person declaration to the actual ICA credential through its URL and content digest. [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources)
- **Gaia-X Loire** describes how a participant signs a Legal Person declaration and obtains a separate Legal Registration Number credential from a Gaia-X Digital Clearing House notary. The data space's ICA credential supports its own legal identity and registration checks. A formal Loire conformity claim requires the separate notary credential and the Gaia-X compliance process. [Gaia-X Loire participant process](https://docs.gaia-x.eu/policy-rules-committee/compliance-document/3.0.0/Process/#1312-process-description)
