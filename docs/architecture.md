# Architecture

SOSCHAIN Gateway derives from the gateway architecture established by GW CORE
in the Global Data Care ecosystem. Its current implementation owns its runtime
and consumes independent Antifraud, FHIR and SOS contracts.

```text
Antifraud neutral identity and cryptography ----> SOS data and SDK contracts
FHIR interoperability ------------------------> SOS data and SDK contracts
SOS data and SDK Core ------------------------> SOSCHAIN Gateway service
SOS SDK Node ---------------------------------> application/BFF integrations
```

The diagram describes shared ownership. The service manifest and lockfile record
its direct and transitive packages; the boundary gate checks declarations,
emitted imports and the registry graph. Historical lineage is documented in
[Upstream projects and history](upstream-and-history.md).

## Gateway boundary

The gateway validates authenticated tenant-scoped requests, applies
claims-first resource contracts, routes governed operations to configured
adapters and generates OpenAPI for its implemented routes. Applications and
BFFs own user interaction, wallet/device coordination and presentation. A UI
selection does not grant gateway authority.

## Interoperability boundary

HL7 FHIR resource names and coding systems are used where the selected FHIR
version defines them. SOS claims carried in `resource.meta.claims` are a
project extension and are not part of base FHIR. Translation between the
claims-first operational model and strict FHIR belongs at explicit import or
export boundaries.

## Human and animal emergency profiles

SOSCHAIN supports emergency continuity for people and animals through shared
gateway infrastructure and separate policy profiles. Those profiles must not
merge subject indexes, tenant data, cryptographic custody, ledger identities,
deployment configuration or authorization evidence.
