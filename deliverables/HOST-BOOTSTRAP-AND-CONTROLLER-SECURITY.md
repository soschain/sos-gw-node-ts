# Host bootstrap and controller security

This guide traces how an SOS Gateway host starts, how an organization is admitted, and how a person gains controller access. It identifies the checks performed by the Gateway, the controller portal and the Identity Credential Authority (ICA).

## 1. Start the host

At startup, the Gateway uses operator-supplied configuration to establish its hosting-service identity and route. The bootstrap stores an internal `system` record. The host identity, its network and the business sector of an organization hosted there are distinct configuration and authorization decisions. The first organization tenant follows its configured activation path for its business sector.

The managed deployment profile uses the configured Key Management Service (KMS) to unwrap the Gateway's runtime key during process bootstrap. That key protects Gateway service data. The controller's wallet is held under a separate portal custody boundary. For a Fabric-backed deployment, record the host peer and the network enrollment separately from the human controller's account and signing keys.

[Gateway host bootstrap](../src/bootstrap/host-bootstrap.ts) · [Operator deployment guide](../charts/sos-gateway/README.md)

## 2. Authenticate the user and open the controller wallet

The user signs in through a trusted identity provider. For example, a portal configured for Google sign-in can receive a Firebase ID token after the Google sign-in. The portal backend validates the token under its configured provider policy, requires a verified email where the flow uses email, and resolves the profile against the authenticated account. Sign-in establishes who is requesting access. Controller authority comes from a separate binding to the organization or host and its authorized scope.

In the server-custodied portal flow, the backend generates the seed for a new wallet. It stores the seed in protected form and opens it on the server when the authenticated user unlocks the profile with the PIN. The wallet derives its keys from the seed and versioned derivation parameters for each purpose. Reopening the same seed with the same parameters recovers the same keys. The PIN unlocks the protected seed. The sign-in credential authenticates the account. Neither is an input to key derivation.

The portal backend reconstructs the private keys and uses them for proofs and signatures. The browser receives the profile session, and the Gateway receives the public keys and proofs required by the relevant protocol. The audit must cover which portal workload can open the protected seed, how the workload and KMS privileges are governed, and what happens during recovery, rotation and revocation.

## 3. Verify the evidence and authorize admission

The applicant submits the organization details and the evidence required for its jurisdiction and sector. On the ICA path, the Gateway forwards the signed verification request with the requested sector and preserves the signed payload. The ICA applies its verification and issuer policy and returns credentials for the verified claims. Where a jurisdiction uses a signed document, the representative's certificate used on that document and the controller's wallet signing key have separate purposes and bindings.

An authorized reviewer manages applications through a host controller portal. The portal displays the request and submits the decision through its backend. The designated admission authority approves or rejects the requested host, network and sector, directly or through an authorized delegate. An email notification can route the request to a reviewer. The reviewer's authenticated identity, current authority and evidence are what support the decision. Each sector requires its own admission decision when review is required.

The Gateway also supports a governed Test Network admission credential. Its verifier checks the trusted issuer, signer and authorized signing key, scope and validity, and verifies the ML-DSA-65 signature. This credential is scoped to Test Network and its explicit local simulation. A communication-signing key, such as an ML-DSA-44 key in the portal wallet profile, does not satisfy that admission signature check.

[Host admission responsibilities](../docs/HOST_AND_TENANT_ADMINISTRATION.md#admission-decisions) · [Gateway verification transaction](../src/managers/hosting/process-organization-verification.ts) · [Test Network admission verifier](../src/managers/hosting/organization-test-network-credential.ts)

When a host enables the admission decision service, the Gateway checks the
stored decision after verification and before creating a licence Offer. The
check sends the host, network, jurisdiction, sector and a digest of the
verified transaction to the configured HTTPS service. The result must
contain an affirmative decision and a reference for that exact digest.
Absent approval, a mismatched digest or an unavailable service prevents the
new Offer. Record the accepted decision reference, corresponding evidence and
policy revision in the admission service's audit history.
New tenants on a governed host enter through the verification transaction.
The existing-tenant controller re-registration path retains its own
authorization checks.
The signed application and its document digest identify the same review
case when the ICA is temporarily unavailable. A replacement document
requires its own decision. Reusing an approval requires the same verified
ICA evidence and checks. The approval remains in the audit history during
an outage.
The Gateway can use the configured ICA admission endpoint to resolve the
signed application ID and PDF digest before sending the decision request.
The ICA response must match the authenticated controller DID and the
submitted proof reference before its checks reach the decision service.
Connect the ICA proof provider to the authoritative document store for
that application.

For a governed Test Network deployment, set `HOST_ADMISSION_ICA_URL` to the
ICA verification endpoint and `HOST_ADMISSION_DECISION_URL` to the host
controller's internal decision endpoint. Use the deployment ConfigMap for
the HTTPS URLs and the deployment secret store for
`HOST_ADMISSION_ICA_TOKEN` and `HOST_ADMISSION_DECISION_TOKEN`. Each service
uses a separate token scoped to that host and network. Deploy the ICA
revision that returns `proof.submittedReference` before enabling the
Gateway revision that requires it. An older ICA response leaves the case
in review. Deploy the controller decision endpoint that accepts the signed
application reference before the Gateway sends it with the decision request.

## 4. Activate the tenant and register the device

The standard new-tenant flow submits `Organization/_transaction`, obtains an Offer and confirms it through `Order/_batch`. The resulting activation context is used with the controller proof in `Token/_exchange` to obtain an initial access token. The portal then performs Dynamic Client Registration (DCR) through `Device/_dcr`. The Gateway binds the authorized client instance and its public keys to the license. A valid login by itself leaves this registration pending. Subsequent requests use the resulting client and profile context under the applicable authorization policy.

The historical first-controller compatibility path uses the ICA-backed `Organization/_activate` operation to bind the first legal representative's public key during tenant activation. In that path this binding completes first-controller bootstrap. Later service controllers, employees and replacement devices use their own applicable token exchange and DCR. Audit records should show which activation path ran.

[Compatibility and profile enforcement](../docs/HOST_AND_TENANT_ADMINISTRATION.md#profile-and-route-enforcement) · [Gateway device registration](../src/managers/DeviceRegistrationManager.ts) · [Activation trust tests](../src/__tests__/unit/adapters/activation-trust-security.test.ts)

## Public implementation references

- [Controller portal source](https://github.com/antifraudservices/antifraud-controller-nextjs/tree/d4ebad2aaba908748d02587832e208ddee279db1) shows the portal and backend boundary. Its [host registry handler](https://github.com/antifraudservices/antifraud-controller-nextjs/blob/d4ebad2aaba908748d02587832e208ddee279db1/src/app/api/host/organizations/route.ts) is one reference for host-scoped administration.
- [ICA source](https://github.com/antifraudservices/antifraud-ica-node-ts/tree/788d0efe77dc1f847d04297292fd9c4507577222) describes the public authority contract and implementation status. The [authoritative issuance manager](https://github.com/antifraudservices/antifraud-ica-node-ts/blob/788d0efe77dc1f847d04297292fd9c4507577222/src/authoritative-issuance-manager.ts) is a reference for provider-side verification and issuance.

For the deployment under assessment, record the exact Gateway image digest and the portal and ICA revisions. Supply the applicable admission policy, configured issuer and signer evidence, and authenticated traces of the approved and rejected cases through the audit channel. Include verified sign-in followed by denied access without controller authority, an out-of-scope admission request, a successful activation and client binding, and a client denial after revocation. Keep recovery material, private configuration and identifiable evidence in the operator's restricted records.
