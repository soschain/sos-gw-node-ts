# API and interoperability

The generated OpenAPI contract is the endpoint-level source of truth. Build it
with:

```bash
npm run build:swagger
```

This produces `swagger-spec.json` and generated profiles under
`docs/openapi-profiles/`. Do not hand-maintain a second endpoint inventory in
Markdown.

Routes are scoped by host or tenant, jurisdiction, API version, sector and data
section. Authentication proves the caller; request content identifies the
business subject or participant. Those identities are not interchangeable.

The `resource.meta.claims` field is an SOS/GW extension, not a standard FHIR
element. Standard FHIR exports must materialize valid resources and must not
leak internal claims or storage metadata.

## SDK and data repositories

- [antifraud-data-utils-ts](https://github.com/antifraudservices/antifraud-data-utils-ts)
- [antifraud-sdk-node-ts](https://github.com/antifraudservices/antifraud-sdk-node-ts)
- [fhir-data-utils-ts](https://github.com/Fundacion-UNID/fhir-data-utils-ts)
- [sos-data-utils-ts](https://github.com/soschain/sos-data-utils-ts)
- [sos-sdk-core-ts](https://github.com/soschain/sos-sdk-core-ts)

Integrators should use published package versions and the generated gateway
OpenAPI contract. A client method never widens server-side authorization.

## Reviewed organization admission

The gateway initializes its internal host identity in the reserved `system`
sector. A deployment can also provision a designated organization tenant through
its governed bootstrap workflow. That tenant uses its configured business sector
and service DID. Admit additional sectors through the organization registration
workflow. Each sector has its own tenant identity and onboarding record, even when
the same legal entity applies. Enable each supported sector explicitly in
`ALLOWED_SECTORS`. This list controls routing eligibility.

For a reviewed Test Network application, submit the admission and domain
credentials together through `Organization/_transaction`. The gateway checks
the reviewer's signature and the signed reference to the reviewed PDF. It
requires the signed organization identity, sector, country and identifier type
to match the transaction before creating an Offer. Confirm the Offer through
`Order/_batch` and complete activation using the resulting licence. Use
production identity verification for the production route.

### Verification evidence by jurisdiction

Keep the downloadable terms separate from the evidence submitted for
verification. Resolve the evidence policy by exact jurisdiction, then by
its jurisdiction family when the authority publishes one.

| Jurisdiction | Evidence |
| --- | --- |
| CA-BC | Use a verified controller presentation or governed host preauthorization without an applicant-signed PDF. For a marketplace claim, use the official registry entry and the contact verification required by the active admission policy. |
| ES | The certificate-PDF workflow submits the applicable agreement signed with a supported representative certificate. Preserve the original attachment and verify the certificate trust and the represented organization. |

Use the host's published terms URL for the downloadable agreement. When a
workflow requires a signed template, bind the applicable document version to
the jurisdiction and sector. The existing verification URL contains a
`pdf` path segment even for a PDF-free request. Confirm the verification
contract supported by the selected Antifraud ICA deployment before testing
organization activation.

## Signed device enrollment

Use `sos-sdk-node-ts` 0.6.0 or later for native device enrollment. Before a device
is registered, its signed inner JWS commits to the reply encryption key through
`skid`. The outer JWE carries that same public ML-KEM key and identifier. The
gateway verifies their exact thumbprint binding before accepting the request.
Registered requests use the encryption key in the current device registration.

Responses contain a communication-key signature inside the encrypted envelope.
Clients verify the provider signing key before reading the response payload.
The SDK owns this transport; applications retain the normal activation, account
and device-enrollment steps.

## Device registration recovery

The existing Device registration operation can return its original receipt for
an exact retry of an active installation. Recovery still requires the current
verified initial-access account and activation binding, current active licence,
unchanged actor/subject/tenant context, complete public-key material and request
metadata. An installation identifier alone grants no lookup or registration
right. Unordered JWKS serialization does not rotate keys; changed key material
retains the existing authorized replacement path.

Successful recovery does not write another profile, revoke the current device,
change its licence or repeat ledger registration. Historical profiles without a
server-stored replay binding are not inferred to have one. The response retains
the actual registration fields; it does not manufacture a registration access
token. These manager/API tests do not establish online or blockchain acceptance.
