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

DID profile disposition: `adopted` with explicit SOS routing fields over the
neutral Antifraud DID model. Original repository:
<https://github.com/Global-DataCare/gdc-common-utils-ts>; reviewed
[DID contract source](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/did.ts).
The profile declares selectors and action lists while verification methods remain
neutral. The type check, scoped ownership guard and 14 affected discovery,
onboarding and identity suites pass 159 tests without pending cases.

Service-capability parsing disposition: `adopted` from independent SOS Data.
Original repository: <https://github.com/Global-DataCare/gdc-common-utils-ts>;
reviewed [capability source](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/service-capabilities.ts).
Legacy tokens and extension ordering remain compatible. Gateway allowlists still
filter advertised capabilities before policy evaluation; family recognition alone
does not grant access. The type check, scoped ownership guard and six affected
hosting/discovery suites pass 105 tests with no pending cases. This slice does not
resolve the remaining project-wide GDC dependencies or registry lockfile gate.

Neutral flat-claim catalog disposition: `adopted` from Antifraud Data, including
person, organization, service, action, offer, order and individual product fields.
Original repository: <https://github.com/Global-DataCare/gdc-common-utils-ts>;
reviewed [flat claim source](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/schemaorg.ts).
The migration resolves import symbols before changing member names, preserves
exact indexed wire values and explicitly distinguishes containing identifier
references from `identifier.value`. Qualified member type queries are migrated
with their runtime counterparts. The type check, scoped ownership guard and all
64 changed default consumer suites pass 470 tests without pending cases. This
includes memory-backed API/queue flows for employees, registration, hosting
orders and clinical/Consent searches. Configured browser/network gates and the
project-wide dependency/registry gate remain pending for cumulative acceptance.

Response and clinical profile disposition: `adopted` from the independent SOS
Data and SDK Core owners. Original repository:
<https://github.com/Global-DataCare/gdc-common-utils-ts>; reviewed
[gateway response catalogs](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/gateway-response.ts),
[clinical creator profile](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/fhir-ips-creator-identity.ts)
and [document successor profile](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/clinical-resource-replacement.ts).
The stable person UUID, assignment UUID and owning organization remain distinct.
Gateway authentication, tenant/subject admission, persistence and delete checks
retain their owning boundaries. Descriptive ownership and successor comparison
do not grant actor authority or deletion rights.

OpenID, DIDComm and native clinical exchange disposition: `adopted` using the
existing neutral Antifraud client/device profile, neutral protocol envelope,
SOS-owned message entries/wire catalog and FHIR-owned Communication/claim syntax.
Original repository: <https://github.com/Global-DataCare/gdc-common-utils-ts>;
reviewed [OpenID device contracts](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/openid-device.ts)
and [token profile](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/auth.ts),
and [communication declarations](https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/comm.ts).
The registration response retains its required issuance time, and native FHIR
metadata extensions remain explicitly separate from protocol verification.
The type check and all 14 scoped ownership guards pass. The 22 affected/default
consumer suites pass 399 assertions without pending cases, including the actual
manager path that accepts an authorized successor update, rejects deletion by
the former attesting assignment and preserves the record. Memory-backed DCR,
composition readback, employee and organization API flows also pass. These are
backend suites and assertions, not additional UI user journeys. Configured ICA
and browser/network journeys remain pending. The project-wide GDC declaration,
source and registry checks still fail and block main/release acceptance.


## Tenant lifecycle representative identifier projection

Adopted only the existing typed memberOf matching behavior in the GW-owned
lifecycle admission helper. First credential subject, TAXID/TAX_ID aliases and
complete punctuation-sensitive values are retained. Credential verification,
controller proof and tenant lifecycle decisions remain at their original boundary;
this projection grants no occupation or controller authority.
Read-only compatibility source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/activation-policy.ts .
No source or release change was made in that original repository.


## Hosted service activation scope

Adopted the verified-credential service scope admission profile in a GW-owned
helper. Canonical capability normalization and known-capability recognition are
consumed from SOS Data; no vocabulary or issuer-verification implementation was
copied. Category-only wildcard behavior, first-subject/makesOffer precedence and
ordered error codes/messages are retained at the existing activation boundary.
Read-only compatibility sources: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/activation-policy.ts and https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/dataspace-discovery.ts .
Owning capability source: https://github.com/soschain/sos-data-utils-ts/blob/main/src/service-capabilities.ts .


## Clinical document search index projection

Adopted only the derived storage-index behavior in the GW owner. The operational
profile explicitly selects twelve published FHIR Composition claim constants and
six CSV claims; qualified Status remains an unmodified passthrough attribute.
Canonical stored/signed resources, FHIR views and content-CID input are unchanged.
AuditInfo/IndexedAttribute contracts come from SOS Data.
Read-only compatibility source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/confidential-document-provenance.ts .

## Licence pool and issuance policy

Adopted the used pool-family classification and issued-seat allowance behavior
in the GW owner. Coding-system recognition comes from Antifraud ISCO and FHIR
RoleCode identifiers; classification is not credential or occupation authority.
Relationship and occupation pools remain separate. The issuance receipt retains
its fallback of two installations, while the existing GW authorization/device
and search compatibility fallback of five remains profile-specific and unchanged.
No general license builder or unused runtime API was moved.
Read-only compatibility source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/main/src/utils/license.ts .


## Operational content CID composition

Adopted the default flat-claim content-version profile through the owning SOS
Data projection and neutral Antifraud DAG-JSON/SHA2-256 primitive. Eight exact
canonical UTF-8/CID vectors from the read-only original are retained as immutable
compatibility evidence. Canonical Status/Entry data and significant array order
remain intact; the distinct SHA3 ledger-reference profile is not replaced.
Own prototype-control keys are rejected rather than repeating silent data loss.
Read-only original source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/fhir-cid.ts .
The original repository was not modified and new production/tests import no
original hashing implementation.


## Canonical ConsentRule owner

The eight existing type consumers use the published FHIR contract. A read-only
original declaration fixture proves all thirty-two members, optionality and type
expressions plus complete decision/status and forty-claim catalogs. Mixed test
imports retain actual runtime values. Consent evaluation/SMART policy is unchanged.
Read-only original source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/models/consent-rule.ts .


## ResearchStudy standard owner

The manager's four generic ResearchStudy exports and its retained unit projector
come from the existing FHIR R5 owner. Complete catalog/search/role wire tables and
eight accepted/rejected normalizer vectors are compared before the import change.
Controller and party authorization, claims-only persistence and active Consent
remain in GW and are exercised through the real asynchronous HTTP boundary.
Canonical standard references: https://hl7.org/fhir/R5/researchstudy.html and https://hl7.org/fhir/R5/researchstudy-search.html .

## Identity/auth wire owner

Adopt the SOS Data operational identity/auth wire leaf in eleven existing
consumers, including retained manager and HTTP fixtures. All six frozen catalogs
and thirty literal members match the read-only original. Response-entry
discriminators remain in the separate existing gateway response contract.
These are wire names, not bearer, grant, licence or controller authority; current
manager checks and SMART compatibility polling remain unchanged.
Validation: native ownership/full-catalog controls pass after the genuine import
owner RED; seven retained manager/HTTP suites pass all 131 cases, with strict
TypeScript and scoped privacy checks green. This is functional integration,
not a package publication or gateway promotion.
Read-only original source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/identity-auth.ts .

## Discovery advertisement wire owner

The three complete service fragment/type and DSP metadata-path catalogs now
come from the SOS gateway DID profile at four existing consumers. Seventeen
literal values are preserved, including the qualified SMART service fragment.
Generic DID types remain owned by Antifraud. Existing URL builders, discovery
scope and endpoint access checks are unchanged; this wire-owner migration does
not resolve the separate remaining runtime URL-helper dependencies.
Validation: genuine import-owner RED plus a full-catalog control precede the
import-only change; both native cases, four retained service/discovery suites
(twenty cases), strict TypeScript and scoped privacy checks pass.
Read-only original sources: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/did-services.ts and https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/constants/dataspace-protocol.ts .

## DSP relative-path owner

Six deterministic relative-path builders move to the SOS Data owner across
five route/service/test consumers, with canonical names and no compatibility
aliases. A symbol-bound source packet changes imports and bound call names
only. All 106 read-only original tenant/host, precedence, whitespace/slash,
unscoped fallback and explicit dataset-ID vectors remain exact without input
mutation. The mixed metadata-payload helper import is deliberately retained
and remains a separate owner gap; this does not claim full module independence.
No new endpoint or access policy is introduced.
Validation: actual ownership RED plus a 106-vector control precede migration;
both native cases, five retained suites (46 cases including discovery HTTP),
strict TypeScript and scoped privacy pass. The touched DID compliance fixture
uses governed synthetic routing values and its two cases pass on rerun.
Read-only original source: https://github.com/Global-DataCare/gdc-common-utils-ts/blob/f4031b221216cacd9917d1d20c5ff0b03bed7045/src/utils/dataspace-protocol.ts .

## Reviewed Organization contact channels (profile-specific)

The existing Test Network admission verifier now compares normalized typed
controller contacts and derives the reviewed controller and representative
identifiers using their actual email or telephone channel. Hosting forwards
telephone fields from the existing Organization transaction resource. Missing,
ambiguous and mismatched channels fail closed; signer authorization/revocation,
key commitment, PDF evidence and production-route denials remain enforced.
This is an SOS host admission correction, not an upstream mutation or a new
credential authority. Controller Order/licence issuance and online enrollment
remain separate lifecycle boundaries.

Validation: a genuine real-signature telephone admission RED preceded the fix.
Both affected suites pass all 26 cases, including four new real-crypto cases;
full strict TypeScript, integrated privacy and owned-file diff checks pass.
These are manager/cryptography tests, not an online user-journey acceptance.

## Telephone Organization controller Order (profile-specific)

The existing controller builder accepts a telephone-only Person without
substituting an email. It uses the neutral actor DID/hash and the existing
stable-actor employee URN; private phone indexing follows the current employee
index profile. Both Order licence callers pass the actual phone channel to the
existing pool and ledger identity builder. Existing primary-email selection,
required role, supplied/provisioned-key checks, postal-code binding and
technical-seat reservation remain unchanged.

Validation: a real memory-manager Offer-to-Order case first returned the exact
required-email OperationOutcome instead of 201. After the fix, three suites
pass 45 executions (37 distinct cases; the sector fixture reimports eight Order
cases), including phone-bound licence persistence and retained activation
controls. Strict TypeScript and scoped privacy/diff pass. This is manager
coverage, not online Firebase, HTTP, ledger or complete phone-lifecycle proof.
