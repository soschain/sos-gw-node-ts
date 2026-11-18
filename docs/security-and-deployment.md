# Security and deployment

SOSCHAIN Gateway is fail-closed. Production startup and protected operations
must reject missing or untrusted authentication, tenant authority, subject
scope, consent, key custody or persistence configuration.

## Secrets

- Never commit private keys, bearer tokens, cloud credentials or populated
  environment files.
- Public templates contain placeholders only.
- Use the deployment platform's secret manager and workload identity.
- Treat test private keys as disposable fixtures and keep them isolated from
  any real trust domain.

## Key custody

Production key-encryption keys are unwrapped through the configured KMS during
process bootstrap. Tenant operations use the process-owned runtime resource;
they must not silently fall back to demo secrets or infer custody from a
selected tenant or index provider.

Decrypted tenant keysets remain in a bounded time-limited process cache. Cache
expiry, replacement, eviction and invalidation overwrite private key bytes,
data-encryption keys and HMAC keys before removing the entry. Graceful shutdown
stops request processing, clears cached and pending tenant keys, and destroys
the process-owned runtime key. A destroyed runtime key cannot wrap or unwrap
tenant key material.

## Deployment

The service is released as an immutable container image, not as an npm package.
Validate the complete affected local matrix before building an image. Promote
the same verified source through local-network and later environments, and
deploy by image digest.

Environment-specific domains, tenant identifiers, cloud projects, service
accounts, ledger channels and KMS identifiers are deployment configuration.
They do not belong in this public repository.

Follow [SECURITY.md](../SECURITY.md) to report vulnerabilities. Do not open a
public issue containing a credential, exploit payload or tenant information.

## Canonical public origin and historical URLs

Set `HOST_PUBLIC_URL` to the canonical public origin and
`HOST_EXTERNAL_DOMAIN` to that origin's host. The host DID and advertised
operational endpoints use this canonical origin. Keep the host jurisdiction
and coverage unchanged when changing its public hostname.

`HOST_LEGACY_PUBLIC_URLS` optionally lists previous public origins, separated
by commas. It defaults to an empty list. Supply complete HTTPS origins, for
example `https://previous.example.invalid,https://earlier.example.invalid:8443`.
Resource paths, query strings, fragments, user information and wildcards are
rejected. Configuration normalizes and deduplicates origins and excludes the
canonical origin from the legacy list. HTTP is restricted to explicitly
permitted local tests; staging and production require HTTPS.

The list supplies explicit transport compatibility. It does not trust a caller,
grant a role, authenticate a device or change consent. Existing tenant DIDs,
issued-credential issuers and registered device identities retain their values;
public endpoint projection must not rewrite those identities. Request headers
cannot add legacy origins. Select the corresponding server-owned provider
route and retain its pinned keys and exact authorization context.

A public hostname change is separate from key custody and data ownership.
Preserve the host storage scope, physical host collection, database project,
bucket, KMS root and wrapped key, tenant records and Fabric identities. Services
sharing an ingress address can still have separate backends and data stores.
Check their actual routes rather than treating a previous hostname as a DNS
alias of the new service. Use a guarded image/configuration delta after local
compatibility and exact-image gates; do not repeat host onboarding.

## ICA issuer trust and credential status

`CREDENTIAL_TRUSTED_ISSUERS_JSON` is trusted server configuration indexed by the
exact issuer in an ICA credential. Each active issuer sets `status` to `active` and supplies its public
signing keys (`jwks.keys`), its HTTPS credential-status endpoint template
(`statusEndpointTemplate`, including `{credentialType}`), and the exact existing
DIDComm status-request protocol identifier (`statusRequestType`). When one issuer
uses several approved credential stores or sector routes, supply
`statusEndpointTemplates` instead (one to sixteen distinct templates).
The generic GKE deployer reads the three trust maps from its environment
(`CREDENTIAL_TRUSTED_ISSUERS_JSON`, `CLEARING_HOUSE_REQUESTERS_JSON`, and
`GXDCH_TENANTS_JSON`). It validates each as a JSON object before calling
Kubernetes and serializes it as a quoted YAML string, preserving JSON content
including apostrophes and backslashes. Empty maps remain empty trust, not
permission to enroll. Keep operational values in the reviewed private runtime
configuration.

Obtain these status fields from the approved ICA deployment. The protocol identifier names
the wire message; it is separate from the network endpoint and must not be
renamed when changing a library or gateway implementation.

Composition injects the issuer's endpoint and message identifier into the status
client. Request bodies cannot choose them. Missing status metadata fails closed.
The client performs the existing read-only lookup, preserves the complete
credential type list, checks the polling origin/path, and binds a fresh response
to its thread and credential identifier. It neither changes credentials nor
regenerates their keys or identifiers. Loopback HTTP is available only through
an explicitly enabled test option while `NODE_ENV=test`; deployment uses HTTPS.

Every configured status source must answer successfully with a fresh, bound
result. A revocation in any approved source takes precedence over every `good`
result. Acceptance requires at least one `good` result and only `good` or
`unknown` elsewhere. All-unknown results and unavailable sources do not permit
activation. This supports a shared issuer without guessing which store issued a
credential or accepting another store's answer after a revocation.

For issuer-signed credentials checked against Fabric, the trusted issuer also
sets its explicit governed signing-key `channelName`. The verifier checks its
pinned key and current ledger status on that channel. First-controller ICA
verification uses the separate ICA signature and status checks below.

First-controller activation checks current ICA-signed authority before a device
has been enrolled. It reports no Fabric verification. Enrolled professional and
individual-member presentations additionally use current registration and the
configured credential/key provider; a network label is not ledger evidence.

## Verification profiles

`NETWORK_MODE=test` selects local ledger adapters. It does not disable signature
verification. Use `CLEARING_HOUSE_MODE=local` for native verification against
registered public keys, current tenant/member/device state and current consent.
The local provider records are local evidence, never a Fabric transaction.

Unsigned synthetic identities and disabled replay are permitted only when
`SECURITY_MODE=demo`, `NETWORK_MODE=test`, and the deployment is local. Neither
`NODE_ENV=test` nor a development hostname enables this profile. Staging and
production retain the same identity and policy gates, with their configured
Fabric and durable replay providers. The issuer's public verification keys and
status lookup configuration must be supplied by the operator before enrollment
and protected flows can succeed.

For `NETWORK_MODE=test-network` and `NETWORK_MODE=network`, configure an
explicit durable replay provider. With an existing `DB_PROVIDER=firestore`
vault, `REPLAY_PROTECTION_PROVIDER=firestore` uses that same database instance
and a dedicated `REPLAY_FIRESTORE_COLLECTION` (default: the host collection
name followed by `_replay`). It stores only a SHA256 of the full namespaced
replay key and an `expiresAt` timestamp, using an atomic transaction. It does
not initialize another database or change vault custody. The collection must
be separate from the host vault and credential-verification collections.

Alternatively, `REPLAY_PROTECTION_PROVIDER=redis` requires an explicit
`REDIS_URL` using `redis:` or `rediss:` and an approved existing durable service.
The generic deployer defaults to native `CLEARING_HOUSE_MODE=local`. For an
enrolled network with an existing Firestore backend it selects Firestore replay
when the replay provider is unset. It never changes `DB_PROVIDER`; other backends
must select their approved durable provider explicitly. Enrolled deployments
reject `stub` verification and memory-only or disabled replay before Kubernetes.
Bootstrap rejects memory-only or disabled replay for enrolled networks. The
native tenant endpoint and SMART authorization share the same configured port.
Strict local tests use a real memory replay store by default;
`REPLAY_PROTECTION_PROVIDER=none` requires the explicit local demo profile.

Firestore expiry is enforced by each reservation transaction. An optional TTL
policy on the dedicated collection's `expiresAt` field only removes expired
records asynchronously; authorization never relies on that cleanup. Review and
configure that policy separately against the verified collection, never a vault
or ICA collection. No TTL policy is created by bootstrap.

The replay integration gate uses only an operator-leased loopback emulator.
Set `NODE_ENV=test`, `FIRESTORE_EMULATOR_HOST` to its loopback host and port,
and `REPLAY_EMULATOR_PROJECT_ID` to an explicit synthetic `demo-` project.
Run the exact suite with the repository's Node runtime:

```bash
node --experimental-vm-modules node_modules/jest/bin/jest.js --runTestsByPath \
  src/__tests__/integration/repositories/firestore/replay-protection-store.emulator.test.ts \
  --runInBand --no-coverage --testPathIgnorePatterns=/node_modules/
```

It rejects absent or non-loopback emulator settings, creates its own random
replay collection and cleans only that collection. It proves concurrent atomic
reservation, client recreation and persisted expiry without a live database.

## Tenant verifier and GXDCH

The tenant's backend verifier authenticates explicitly trusted requesting
backends, checks exact audience and signed request digest, consumes replay
identifiers and signs a short-lived result bound to the original authorization
context. `CLEARING_HOUSE_REQUESTERS_JSON` maps each recipient tenant DID to the
requesting tenant DIDs, their pinned public `jwks` and `capabilities` containing
`verifier`. Request bodies cannot select trusted keys or the verifier endpoint.

`GXDCH_TENANTS_JSON` selects each tenant's standard-compliance service. Its value
is a map from the exact tenant DID to `endpoint`, `issuer`, `jwks` and
`rulesVersion`. The gateway sends the tenant-signed presentation with
`application/vp+jwt` and accepts only the pinned issuer's signed
`application/vc+jwt` result covering the submitted credential identifiers and
canonical content digests under that rules version. It preserves the original
credential signature. Missing configuration fails closed; the private endpoint
and trust entries belong in deployment configuration, not public source.

## Updating an existing host

An existing deployment can reuse its peer and external chaincode services when
its installed channel definitions, package identifiers and methods satisfy the
new gateway's contracts. The CORE infrastructure guide may help operate those
Fabric components; it does not determine this gateway's channel inventory or add
a runtime dependency. Review the actual deployment before choosing a lifecycle
change. A gateway image update alone does not configure issuer trust, current
credential status checks, trusted verifier callers or durable replay.

Preserve the original host and tenant identities, protected data, KMS custody and
Fabric bindings. Review explicit container `env` entries as well as `envFrom`:
explicit entries override imported configuration. Capture private snapshots and
compare decoded Secret hashes, public verification methods, effective settings
and authoritative data before and after a guarded rollout. Do not repeat
onboarding or recreate keys to update an admitted host. The operator's private
runbook owns the actual target, prerequisite services and rollback configuration.

## Real local Professional UI gate

`./scripts/run-secure-e2e-google-user.sh` delegates to the existing Professional
portal's `test:e2e:local` runner. Set `PORTAL_PROJECT_ROOT` to that reviewed
external checkout. The launcher requires Node.js 26.13.0, selects this exact SOS
gateway checkout through `VET_GW_PROJECT_ROOT`, rejects another gateway path and
runs with one Playwright worker. It forwards the runner's output and exit code;
it accepts no arguments that could filter the complete journey.

The owning portal runner exercises its selected real browser journey through
UI, BFF, high-level SDK and gateway, including organization admission, wallet
and device enrollment, professional lifecycle and protected subject operations.
Its versioned journey defines the exact coverage and authorization invariants.
It leases its local ports and owns its ephemeral services, generated test state
and bounded cleanup. The gateway launcher does not synthesize bearer tokens,
start another ICA, tear down a host or kill unrelated listeners.

The external portal runner is an interoperability test consumer, not a runtime
dependency of this gateway or a claim of frontend package independence. Launcher
unit tests use an npm stub only to verify target selection, arguments and exit
propagation. Record a real unskipped browser execution and authoritative readback
before reporting the UI gate as passed. Local browser and emulator results do not
establish staging or production readiness.

The standalone native-FHIR router requires an explicit server-owned authorization policy through `startServer({ authManager })`. Its default authorizer denies requests, including missing authentication and unavailable policy decisions. The claims-first tenant API uses its own registered-client, credential, consent and scope checks.

## Phone verification provider

When phone verification is enabled outside explicit local Demo, bootstrap
requires a real Twilio provider with its account SID, auth token and Verify
service SID configured. Missing or blank Verify configuration stops composition;
it does not select a simulated provider. Actual staging and production labels
remain authoritative even when a supplied test configuration requests Demo.

The local Demo profile retains the in-memory phone adapter for UI exercises.
Its simulated webhook signature validation is enabled only in that profile.
Directly injected unit doubles can still exercise deterministic OTP behavior;
those tests do not authenticate a real webhook or establish provider readiness.

## Individual registration and controller activation

A currently authorized professional can propose a human or animal registration
and complete the Order for that same registration. The gateway stores the
creator reference inside encrypted registration content and rechecks the
registered device, active licence, organization Group membership and current
registration Consent before allowing this continuation. Request metadata cannot
provide the stored creator reference. An older Offer without that reference can
be continued only by its verified proposed controller.

Order creates the individual, its controller assignment and the first issued
controller licence. It does not register the controller's device, create a
controller session or approve the professional's clinical access. The controller
uses the portal and the email or phone contact bound to the licence for its own
activation. Access permissions requiring controller approval remain pending
until that separate authorized decision. Controller activation metadata is not
an invitation to an employee or family member.

## Registered device ledger bindings

Professional device enrolment records the current professional assignment and
its employee/organization links on the governed regional identity channel.
Authenticated re-registration can reconcile those links for the same registered
key after checking the current employee and assignment; it does not regenerate
keys or rewrite device profiles.

Personal device enrolment records the governed `person-device-signing` binding
on the global identity channel, using the currently licensed member's stable
actor identifier. Account identity, actor identity and the authorized human or
animal subject remain distinct. Verification reads that current registration
and rejects an inactive licence, revoked key binding or unauthorized subject.


## Local image and Fabric proof

The local image gate runs one inspected `linux/amd64` image ID against the
prepared local Fabric network. Its reviewed external SDK driver performs the
actual signed HTTP operations; that test consumer is separate from runtime
package ownership. Configure its explicit module and private fixture JSON with
`STRICT_FABRIC_DRIVER_MODULE` and `STRICT_FABRIC_DRIVER_CONFIG`.

The harness owns a temporary asymmetric ICA/OIDC fixture and TLS certificate,
public issuer pins, a local Redis replay instance and the selected image
container. Credentials use the canonical organization/representative/controller
builder and bind the real test wallet key. The fixture has no connection to a
production ICA or credential store. Unknown or revoked fixture credentials
cannot become active. Only labelled resources created by that run are cleaned.

A successful gate includes real ConsentAccess and role-licence ledger readback,
SMART IPS access allowed by the current policy, and denial after revocation.
Missing stage results or readback remain failures. Source-level orchestration
and fixture tests alone do not prove an image or blockchain execution. Research
has a separate, explicitly selected journey. Private receipts identify the
image ID, channels and actual results; fixture keys and runtime environment
files are removed after the owned run.
