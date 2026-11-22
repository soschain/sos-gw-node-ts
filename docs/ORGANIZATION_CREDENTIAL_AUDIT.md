# Verify legal identity and fiscal registration

Use the scoped host or tenant base URL and append `/.well-known/` followed by the filename.

| Filename | What the verifier receives |
| --- | --- |
| `vc.json` | The organization's Legal Person declaration, signed by the organization with a detached proof. |
| `legal-participant.vc.json` | The same Legal Person declaration in a signed JWT. The W3C envelope's top-level `id` contains the JWT after `data:application/vc+jwt,`. |
| `organization.json` | The original `OrganizationCredential` signed by the data space's intermediate certification authority (ICA). Its subject is a Schema.org `Organization`. Where the organization enrolled with a digitally signed PDF, the signed credential contains evidence of the document, its signature and certificate checks, and the document digest. |

## Independent verification

1. Download either representation of the participant declaration. Resolve its issuer's DID, confirm that its assertion key is authorized, and verify the signature. Decoding the JWT only reveals the claims.
2. In the signed declaration, follow the `relatedResource[].id` ending in `/organization.json`. Compute a SHA-256 digest of the response bytes before reformatting the JSON, encode the digest in standard Base64, and compare it with `digestSRI` after `sha256-`.
3. Verify the original ICA credential's proof using the ICA issuer's published verification material. Confirm that the ICA is trusted for organization issuance by the data space and check validity and status where available.
4. Compare `credentialSubject["https://schema.org/taxID"]` in the declaration with `credentialSubject.taxID` in the ICA credential. Review the ICA-signed `evidence` to establish what was checked and whether the identifier came from the certificate or the signed document. An auditor with authorized access to the original PDF can independently check its digest and digital signature.

The gateway publishes the signed link only when the admitted ICA credential contains evidence and its fiscal identifier matches the participant's configured identifier. An unlinked declaration by itself is the participant's assertion. A `404` on `organization.json` means the original credential is unavailable at that URL.

## Standards and scope

- The ICA evidence for PDF enrollment uses the **OpenID Identity Assurance** evidence model to describe the checks behind the verified claims. The ICA proof authenticates those claims and their evidence. [OpenID Identity Assurance Schema Definition](https://openid.net/specs/openid-ida-verified-claims-1_0.html)
- The signed `relatedResource` binds the Legal Person declaration to the actual ICA credential through its URL and content digest. [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources)
- **Gaia-X Loire** describes how a participant signs a Legal Person declaration and obtains a separate Legal Registration Number credential from a Gaia-X Digital Clearing House notary. The data space's ICA credential supports its own legal identity and registration checks. A formal Loire conformity claim requires the separate notary credential and the Gaia-X compliance process. [Gaia-X Loire participant process](https://docs.gaia-x.eu/policy-rules-committee/compliance-document/3.0.0/Process/#1312-process-description)
