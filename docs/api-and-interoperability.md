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

- [fhir-data-utils-ts](https://github.com/Fundacion-UNID/fhir-data-utils-ts)
- [sos-data-utils-ts](https://github.com/soschain/sos-data-utils-ts)
- [sos-sdk-core-ts](https://github.com/soschain/sos-sdk-core-ts)
- [gdc-common-utils-ts](https://github.com/Global-DataCare/gdc-common-utils-ts)
- [gdc-sdk-core-ts](https://github.com/Global-DataCare/gdc-sdk-core-ts)
- [gdc-sdk-node-ts](https://github.com/Global-DataCare/gdc-sdk-node-ts)

Integrators should use published package versions and the generated gateway
OpenAPI contract. A client method never widens server-side authorization.

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
