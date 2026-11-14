# GDC Core to SOSChain GW synchronization

SOSChain GW originates from <https://github.com/Global-DataCare/gwtemplate-node-ts>.
Synchronization is selective and
one-way: downstream products and deprecated gateways do not define this
repository's architecture.

## Procedure

1. Start from current SOSChain GW `main` and identify the exact GDC Core source
   commit or contract.
2. Review the semantic diff; never merge or cherry-pick a complete upstream
   release.
3. Record the disposition as `adopted`, `already-equivalent`,
   `profile-specific` or `blocked`.
4. Write the smallest failing SOSChain contract first and reproduce only the
   applicable behavior in its neutral owner.
5. Keep human and animal policy separate, and never copy a product tenant,
   hostname, controller or deployment identity into neutral source.
6. Complete the gates in
   [`docs/LOCAL_FIRST_RELEASE_CONTRACT.md`](docs/LOCAL_FIRST_RELEASE_CONTRACT.md).

## Current baseline

The baseline is current SOSChain GW `main` plus only the GDC Core contracts
explicitly reproduced and proven here. New entries record source commit,
disposition, owning files and test evidence; they do not inventory downstream
consumers.

## Independent healthcare roles and Consent scope projection

Disposition: `adopted` through the independent SOS Data owner.
Original repository: <https://github.com/Global-DataCare/gdc-common-utils-ts>.
Reviewed source: [healthcare role contracts](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/healthcare.ts)
and [Consent scope projection](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/smart-scope.ts).

Healthcare occupation definitions come from Antifraud, relationship vocabulary
from FHIR utilities, and healthcare selection/family policy from SOS Data.
EmployeeManager projects professional clinical identities only for occupation
roles, including Dentistry. Controller authority is not a clinical occupation.
OpenIdAuthManager consumes SOS Data's read-only Composition scope projection.
Existing compact and reverse-DNS wire values remain valid; external coding
identifiers are specific to their interoperability profiles.

Validation: the ownership guard and type check pass. The 14 affected role and
Consent suites pass 191 tests; the two family suites pass another 49 tests.
The full project dependency-independence gate remains incomplete and blocks
promotion until all remaining direct and transitive dependencies are removed.

ISCO query compatibility is `profile-specific`: Antifraud owns recognition of
the WHO SMART system URI, HL7 Terminology's OID URI, and existing compact or
reverse-DNS identifiers. Employee search compares exact extracted occupation
codes without modifying persisted claims; Consent preserves its existing wire
normalization. Six affected suites pass 93 tests, including the real in-memory
API, worker and polling flow with native `valueCoding.system` filters. A wrong
code or unknown system produces no employee match.

Identity/routing foundation disposition: `already-equivalent` for previous public
values and compatible contact/organization identifier outputs. Original repository:
<https://github.com/Global-DataCare/gdc-common-utils-ts>. Reviewed source:
[contact identifiers](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/actor-identifier.ts)
and [organization authorization identifiers](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/organization-authorization-urn.ts).
Imports and re-exports now use Antifraud
for contact identity, SOS Data for routing taxonomy and legal identity URNs, and
FHIR utilities for clinical purpose/category vocabulary. A negative architecture
test protects those owners. The fresh default Jest matrix passes 261 suites and
1,544 tests without pending tests. Configured network E2E, browser journeys and
full registry-dependency independence remain separate promotion gates.

Record/job protocol disposition: `adopted` as independent data contracts. SOS
Data owns records, routing, lifecycle values and batch entry views; Antifraud
owns neutral signature header/serialization shapes. Original repository:
<https://github.com/Global-DataCare/gdc-common-utils-ts>. Reviewed source:
[record contracts](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/confidential-storage.ts)
and [job contracts](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/confidential-job.ts).
The scoped ownership guard
and type check pass. All 48 changed default suites plus three additional crypto,
queue and storage suites pass 597 tests without pending cases. The full default
261-suite result above belongs to the preceding foundation checkpoint; configured
network and browser gates remain pending for the cumulative release.

Encrypted persistence disposition: `adopted` through SOS Data's projection and
SDK Core's explicit blob ports. Original repository:
<https://github.com/Global-DataCare/gdc-common-utils-ts>; reviewed
[persistence helper source](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/confidential-storage-persistence.ts).
Gateway adapters retain their inline-size policy and share the portable record
and blob contracts. The type check, ownership guard and six affected repository,
worker and hydration suites pass 41 tests. SDK Core's registry guard remains
unresolved until corrected shared dependencies are published and pinned.
