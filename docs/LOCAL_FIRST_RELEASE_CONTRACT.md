# Local-first TDD and release contract

This contract applies to every behavior, flow, documentation-contract,
deployment-profile and shared-dependency change in this repository. Read it
with [`AGENTS.md`](../AGENTS.md) and the applicable skill in the
[rules index](RULES_INDEX.md).

## Required sequence

1. Start from current `main` on a named branch and preserve unrelated work.
2. Write and run the smallest executable contract first. It must fail because
   the required behavior is absent or wrong.
3. Make focused unit and integration gates green, then prove any affected real
   local UI -> BFF -> high-level SDK -> GW journey without mocks replacing a
   boundary.
4. Promote cumulatively: `test -> local-network -> test-network -> network`.
   No later environment substitutes for an earlier gate.
5. Update the changelog and linked rule/API documentation in the same branch.
6. Commit and push the branch, merge with an explicit merge commit, push
   `main`, verify matching refs and finish clean.

A skip, accepted error, placeholder, HTTP 200 alone or unverified manual step
is not passing evidence. After a failure, resume at the smallest failed gate
unless an earlier boundary changed or its state is no longer trustworthy.

## Dependency and artifact boundary

This repository is a deployable service and must never be published to npm.
Changed reusable packages are released lowest-owner first. A temporary
immutable `npm pack` tarball may be installed only with `--no-save` for local
proof; no `file:`, Git, workspace or vendored dependency may be committed.

Build an immutable service image only from the exact pushed `main` commit after
all affected local gates pass. Deploy by digest and keep source, image,
deployment and authenticated live evidence separate.

## Canonical data and privacy

Reuse standards and exports from their owning shared package. Do not invent or
duplicate governed identifiers, claims, roles, sectors, terminology or test
identities. Public source, tests and documentation must not contain private
deployment topology, credentials, tenant evidence or production data.

## Reusing a local Fabric environment

The memory lane starts a fresh gateway with `NETWORK_MODE=test`. The local
Fabric lane uses `NETWORK_MODE=local-network`. The local Fabric ledger and
the gateway vault have independent lifetimes. A memory vault loses its state
when the gateway stops. Use a configured PostgreSQL vault and retain the
same Fabric volumes and key custody when testing restart and recovery.

With an already prepared and running gateway, check the selected profile
without bootstrapping or resetting the network:

```bash
npm run local:fabric:stack -- --reuse-fabric --env-file "$LOCAL_FABRIC_PROFILE" --base-url "$LOCAL_GATEWAY_ORIGIN"
```

Use a loopback origin. This checks readiness. Portal acceptance still
requires the controller and professional journeys, authoritative readback,
and transaction evidence from the selected Fabric network.

The provisioning command with `--reset-fabric` recreates Fabric volumes.
Reserve provisioning for an isolated test stack that can be discarded.
An ordinary lifecycle uses dedicated fixtures, then disables or purges
the resources it created through their supported APIs. Keep the test host
in place for tenant and professional journeys. Test the host's own
decommissioning separately with an isolated host and its own authorization.

### Persistent PostgreSQL and IPFS profile

Use a prepared local Fabric profile with the local ICA, trusted OIDC and
Redis replay protection configured. Create a storage overlay once. Use the same private overlay and Docker Compose project whenever you resume
the environment. The overlay retains the database password and local
encryption key. A restarted gateway needs the same key to open existing data.

```bash
FABRIC_ENV=.env.local-fabric
STORAGE_ENV=.env.local-fabric-postgres-ipfs
STORAGE_PROJECT=sos-local-fabric-storage

node scripts/prepare-local-fabric-persistence.mjs "$FABRIC_ENV" "$STORAGE_ENV"
docker compose --env-file "$STORAGE_ENV" -p "$STORAGE_PROJECT" \\
  -f docker-compose.local-fabric-storage.yml up -d --wait

npm run build
node --env-file="$FABRIC_ENV" --env-file="$STORAGE_ENV" \\
  --import ./scripts/register-tsnode.mjs build/main.js
```

PostgreSQL holds the vault records and IPFS holds encrypted document bodies.
The local test overlay externalizes even small envelopes so the proof exercises
both stores. IPFS runs offline, with its API and HTTP gateway bound to loopback.
Use a distinct overlay, Compose project and port set for a second gateway.
The initial ports can be set with `LOCAL_FABRIC_POSTGRES_PORT`,
`LOCAL_FABRIC_IPFS_API_PORT` and `LOCAL_FABRIC_IPFS_GATEWAY_PORT`.
Use `docker compose stop` to pause the storage services and `up -d --wait` to
resume with the same volumes. Existing bucket objects stay in their original
bucket. Migrating them requires a separate verified copy and credential
migration.

The storage probe uses real PostgreSQL and IPFS and verifies decryption in a
separate process. Use the same synthetic fixture identifier for both commands:

```bash
fixture_id=$(node -p "require('node:crypto').randomBytes(16).toString('hex')")
node --env-file="$STORAGE_ENV" scripts/runtime-tests/local-fabric-storage-proof.mjs write "$fixture_id"
# Restart the gateway or the owned storage services here.
node --env-file="$STORAGE_ENV" scripts/runtime-tests/local-fabric-storage-proof.mjs read "$fixture_id"
```

The read removes its isolated synthetic fixture after comparing the decrypted
bytes. Fabric write receipts and portal lifecycle acceptance remain separate
checks.
