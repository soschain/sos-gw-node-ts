---
name: gw-unid-local-image-release
description: Build, test, publish and deploy the UNID profile of one immutable shared SOS GW Docker image from sos-gw-node-ts. Use for local-network container validation, Artifact Registry publication, GKE staging rollout, release verification, rollback preparation, or changes to the UNID deployment profile, Docker, environment, Fabric or Kubernetes configuration.
---

# GW UNID local image release

## Mandatory TDD

Use red-green-refactor TDD for every behavior or flow change. Write and run the smallest executable contract test first; it must fail for the intended reason before implementation begins. Then implement the minimum change and make focused, integration and affected end-to-end tests green. Begin every new or modified test suite with a flow-contract comment. Begin every Playwright or other E2E file with the complete numbered journey and its authorization and persistence invariants. Mocks may isolate units but never replace real boundary proof. Never make a test green by accepting an error, placeholder, pending setup or other incomplete terminal state.

Produce one local `linux/amd64` image, validate that image against the local
Fabric `local-network`, push the same image and deploy its registry digest.
Keep Cloud Build optional; do not use it as the default release path.

## Inviolable persistence red lines

- Treat either `NODE_ENV` or `DEPLOYMENT_ENV` equal to `staging` or
  `production` as authoritative. `NODE_ENV=demo` never permits an in-memory
  database, confidential storage or local/memory KMS in a deployed workload.
- Require the target's private governed `HOST_ID_TYPE` and `HOST_ID_VALUE`
  before staging or production mutation. Public example identities fail
  closed so the runtime cannot select another vault or bootstrap another host.
- Configuration is not operational proof. Before accepting a digest, run a
  real write/read/compare/delete against the configured object store with the
  deployment service account and Workload Identity.
- After rollout, repeat the roundtrip from the application container, delete
  that exact pod, wait for its replacement and repeat it there. Pings, unit
  mocks, provider names and another persistence profile never substitute for
  effective Firestore/GCS/KMS proof.
- Verify the deployed digest and package version, Firestore, bucket, enabled
  Cloud KMS key, wrapped runtime KEK ciphertext, absence of plaintext KEK,
  region, uniform access, public-access prevention and versioning without
  printing secrets or ciphertext.
- `QUEUE_PROVIDER=mem` is staging-only transient state, never confidential
  storage, and is forbidden in production until a persistent queue and restart
  readback are proven.
- A missing local, canary, roundtrip, restart, policy, endpoint or clean-main
  gate blocks production. Preserve the previous digest for rollback; never
  weaken a provider merely to make a rollout start.
- Read
  [`docs/PERSISTENCE_RELEASE_RED_LINES.md`](../../../docs/PERSISTENCE_RELEASE_RED_LINES.md)
  before a human-care staging or production release.

## Read before acting

1. Read the repository `AGENTS.md`.
2. Read [references/unid-staging.md](references/unid-staging.md) for the target
   and isolation contract.
3. Read [references/vetchain-adaptation.md](references/vetchain-adaptation.md)
   only when creating or reviewing the future GW VetChain variant.
4. Inspect `git status`, `origin/main`, `package.json`, `Dockerfile`,
   `docker_build_local.sh`, `cloud_deploy.sh` and the selected deployment
   profiles. Never assume remembered project, cluster, namespace, IP or image.

## Release gates

Stop before publication or deployment unless all applicable gates pass:

- Worktree changes are intentional and committed.
- Local branch is synchronized with the intended remote branch.
- The source checkout is the shared SOS gateway
  (`package.json#name=sos-gw-node-ts`), the release commit exists in this
  repository and the selected deployment profile is the approved SOS profile. Never tag a GW CORE
  or veterinary-profile image into the GW UNID Artifact Registry path.
- Image tag is `<package-version>-<short-commit-sha>`.
- `DOCKER_PLATFORM=linux/amd64`.
- `docker_build_local.sh` uses the repository itself as Docker context.
- `npm run docker:smoke:local-network` validates the selected local image.
- Organization activation tests prove that eight public/hosted DID methods
  backed by four JWKs issue four unique `EnsureKey` calls, and that only the
  stable `ORGANIZATION_CONFLICT` / `CRYPTOGRAPHIC_KEY_CONFLICT` detail tokens
  map Fabric endorsement failures to 409.
- The `rolelicense-sc` compatibility copy is byte-identical to the canonical
  `fabric-multicloud` source, is deployed on the regional organization
  identity channel (`identity-eu` for UNID), and its tests prove deterministic
  role identity, exact-over-catch-all sector policy, per-sector DCR limits,
  replacement and revocation. Never deploy it on `identity-global`.
- Professional Test Network seats prove Offer -> Order -> invoice/payment
  verification -> materialization -> role-licence registration. A direct
  professional `License/_add` is a release blocker in every environment.
- The target GCloud and kube contexts are isolated from other threads.
- Project, region, cluster, context, namespace, reserved IP and current image
  are printed and checked before mutation.
- `FIREBASE_PROJECT_ID` is the primary GW Admin/data project, while
  `FIREBASE_ADDITIONAL_AUTH_PROJECT_IDS` adds only verified Firebase token
  audiences; neither variable is a public URL.
- Publication pushes the already-tested local image with `SKIP_BUILD=true`.
- Kubernetes receives the registry digest, not a mutable tag.
- Rollout, effective image ID, `/host/ping` and `/api-docs/` pass.
- Public DID/JWKS checks confirm that private KMS `purpose` labels are absent,
  the communication signer is under `authentication`, VC signers are under
  `assertionMethod`, and encryption keys are under `keyAgreement`.

Do not invent `SUBJECT_IDENTITY_BINDING_TRUSTED_ISSUERS`. An empty value is the
deny-by-default policy and does not block the current non-cross-portal MVP.

## Network-mode boundary

The image is environment-neutral. Keep the modes and profiles separate:

- image smoke: `NETWORK_MODE=local-network` from `.env.local-fabric`
- SOS staging: `NETWORK_MODE=test-network` from the selected private SOS profile
  and its Kubernetes `ConfigMap`/`Secret`
- SOS production: `NETWORK_MODE=network` from a separately reviewed
  production profile

Never copy `.env*` into the image. Before and after rollout, inspect the
effective Deployment `env`/`envFrom` configuration and confirm the expected
mode, Firebase project and persistent providers. A successful local-network
smoke proves the image; it does not change or prove the staging runtime mode.

For an emergency image-only correction, select the Deployment and container
from the approved private inventory and update only its image digest. Preserve
ConfigMaps, Secrets, Firebase audiences and ledger bindings. A change requiring
new verifier configuration needs a separately reviewed configuration delta; it
is not an image-only correction. Record the original digest and verify the
replacement after rollout.

## DIDComm signature and DCR authorization

- Decryption exposes the nested JWS; it neither verifies nor authorizes it.
- Verify every nested JWS. Signing and encryption keys have distinct purposes.
- Embedded signing keys are allowed only on explicit pre-DCR bootstrap routes.
- First DCR separately proves possession of the new device key and verifies the
  host-issued initial access token; the operation registers that new key.
- Post-DCR requests resolve persisted actor/device keys even if the caller
  supplies another key.
- Legacy `Organization/_activate` remains separate from DCR and creates no
  device profile, OAuth client id or licence-device binding.
- High-level BFF examples use the SDK profile-session facade. JOSE construction
  and queue inspection remain transport-integration concerns.
- Communication journeys that create local clinical projections require a
  verified actor token. An imported IPS may preserve its explicit external
  author URN; an anonymous demo bearer proves no author.

## Authored clinical batch deletion

- Accept mixed typed `POST` and `DELETE` entries only in `Bundle.type = batch`;
  do not silently convert the flow to a transaction.
- A `DELETE` targets exactly `ResourceType/id`, has no resource body and may
  carry `ifMatch` for optimistic locking.
- Locally authored data inherits only the creator DID as
  `Composition.author`; creator identity is not source-document provenance.
- Preserve an external `Composition.author = urn:*` on IPS import, but never
  treat the controller or BFF transport actor as that author. Repeating an
  author URN is not authentication; replacement needs independently verified
  provenance.
- Authorize deletion for the exact subject plus authenticated DID or privately
  linked verified contact. Never copy contacts or their hashes into FHIR.
- Return independent `201`, `204`, `403`, `404` or `412` entry outcomes. A
  failed delete does not roll back a successful sibling create.
- Remove the exact operational fact and synchronized Digital Twin projection;
  secondary-use deny and provider-offboarding purge remain separate operations.

## Build and local-network validation

Run from `sos-gw-node-ts`:

```bash
release_tag="$(node -p "require('./package.json').version")-$(git rev-parse --short HEAD)"
local_image="sos-gw:${release_tag}"

DOCKER_PLATFORM=linux/amd64 \
LOCAL_IMAGE_NAME="${local_image}" \
  ./docker_build_local.sh

IMAGE_NAME="${local_image}" \
  npm run docker:smoke:local-network
```

The smoke prepares Fabric without starting the host TypeScript process, uses
its selected local-network bridge and peer, verifies the canonical local-network
ping and runs:

- atomic ConsentAccess writes, reads and duplicate no-op verification
- same-portal individual SMART token issuance
- authenticated IPS `Bundle/_search`
- organization role-licence ensure, sector policy, DCR replacement and read on
  `identity-local` using the canonical `rolelicense-sc`

`RUN_RESEARCH_SMART_SMOKE=false` is the GW UNID release default because this
MVP does not require cross-portal research access. Enable that opt-in extension
only after bootstrapping an active inter-tenant access contract.

For a quick container connectivity check only, set `RUN_FULL_SMOKE=false`.
That shortcut is insufficient for a release.

## Fast fix validation versus release validation

1. During implementation, run the smallest owning unit/integration contracts
   and affected portal local browser journey. Do not add Docker or Fabric when
   that boundary is unchanged.
2. Commit implementation, tests, contracts, docs, skill and changelog on the
   feature branch; merge only after those local gates pass.
3. Build the immutable image only from the resulting merged `main` commit.
4. Run the complete local-network image smoke, then publish that exact image by
   digest and deploy it to Test Network staging.
5. Run authenticated live E2E/readback after rollout. Production requires
   separate authorization and complete staging evidence.

PostgreSQL, IPFS and other optional local dependencies are separate profiles;
enable them only when the changed contract uses them.

## Isolate deployment clients

Create task-specific temporary directories. Never change the shared active
GCloud configuration or shared kube context.

```bash
release_gcloud_dir="$(mktemp -d /tmp/gw-unid-gcloud.XXXXXX)"
release_kube_dir="$(mktemp -d /tmp/gw-unid-kube.XXXXXX)"
release_docker_dir="$(mktemp -d /tmp/gw-unid-docker.XXXXXX)"
source_gcloud_dir="$(gcloud info --format='value(config.paths.global_config_dir)')"

cp -R "${source_gcloud_dir}/." "${release_gcloud_dir}/"
export CLOUDSDK_CONFIG="${release_gcloud_dir}"
export KUBECONFIG="${release_kube_dir}/config"
export DOCKER_CONFIG="${release_docker_dir}"
```

Create and activate a task-specific GCloud configuration, set the expected
account/project/region, fetch only the expected cluster credentials, then
verify every value against `references/unid-staging.md`.

Remove the three exact temporary directories after final verification. Do not
remove a path that was not created and checked by this run.

## Dry-run, publish and deploy

Run from the shared SOS gateway checkout. Read the structural
`deploy/profiles/soschain/staging/` examples, then select the approved private
runtime environment and GKE configuration. Infrastructure repositories do not
select or deploy this application profile:

```bash
: "${SOS_GKE_CONFIG_FILE:?Select the reviewed private SOS GKE config}"
: "${SOS_RUNTIME_ENV_FILE:?Select the reviewed private SOS runtime environment}"
config="${SOS_GKE_CONFIG_FILE}"

GDC_IMAGE_TAG="${release_tag}" \
GKE_ENV_FILE="${SOS_RUNTIME_ENV_FILE}" \
DEPLOY_DRY_RUN=true \
  ./cloud_deploy.sh gke soschain "${config}"
```

After explicit deployment authorization:

```bash
GDC_IMAGE_TAG="${release_tag}" \
GKE_ENV_FILE="${SOS_RUNTIME_ENV_FILE}" \
SKIP_BUILD=true \
LOCAL_IMAGE_NAME="${local_image}" \
DEPLOY_CONFIRM=true \
  ./cloud_deploy.sh gke soschain "${config}"
```

This path tags and pushes the tested local image, resolves its registry digest,
renders the GW manifests, deploys the digest, waits for rollout and checks both
public endpoints.

## Finish

- Record build tag, local image ID, registry digest, commit, project, cluster,
  namespace, public IP, effective `NETWORK_MODE` and endpoint results.
- Update `CHANGELOG.md` for script, environment or manifest behavior.
- Commit and push repository-owned changes before claiming completion.
- State separately any ignored `.env` or non-Git infrastructure profile that
  cannot be preserved by the repository commit.
- Never claim deployment from a successful build alone.

## Mandatory local-first release order

Follow the repository `AGENTS.md` and the canonical workspace runtime contract.
The order is local packages, the complete affected local test matrix without
skips, merge every validated branch to `main`, publish changed shared packages
bottom-up, install exact registry versions and commit lockfiles on `main`, then
stage the validated immutable service image. Do not publish before the local
matrix and integrated `main`. A staging failure starts a new local patch cycle.

Use immutable `npm pack` artifacts with `--no-save` for local proof. Never commit
file, Git, workspace or vendored dependencies. The gateway is a private service:
shared-package publication and container-image publication are distinct steps.

Local proof includes the real UI -> BFF -> high-level SDK -> gateway journey
without blockchain before the affected local-network/Fabric gate. Mocks,
fixture-only pages, skips and health responses do not replace that evidence.
Keep local, local-network, staging and production results identified separately.
Use canonical independent Antifraud, FHIR and SOS contracts and governed examples;
never infer identity, role or access authority from a transport or deployment label.

## Frozen shared-v1 boundary

- Treat GW CORE v1 (`gwtemplate-node-ts`) and every `gdc-*` repository or package as frozen for new functionality. Only make a narrowly necessary bug, security, or compatibility fix there, backed by a regression test and without product-behavior expansion.
- Implement new VetChain, UHC/UNID, or SOSChain behavior in the corresponding `vet-*`, `uhc-*`, or `sos-*` repository. Keep product roadmaps, feature documentation, examples, and skills in those product repositories; do not add them to GW CORE or `gdc-*`.

## npm authorization continuity

Follow [`docs/LOCAL_FIRST_RELEASE_CONTRACT.md`](../../../docs/LOCAL_FIRST_RELEASE_CONTRACT.md).
Make at most three authorization attempts and keep each session alive for up to
five minutes. After failure, continue local tests using an immutable `npm pack`
tarball installed temporarily with `--no-save`; restore the dependency and
lockfile before committing. Authorization failure never stops the local test
stage. Resume the smallest failed gate without repeating a green gate unless
its boundary or required state changed. Publication follows the blocking
local-first release order above, after the complete local matrix and integrated
`main`. Do not publish or deploy while a required gate is incomplete.
