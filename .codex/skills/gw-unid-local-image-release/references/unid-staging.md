# Selected SOS staging target

Resolve the target from the approved private inventory for the selected SOS
profile. This public reference contains no project, region, cluster, context,
namespace, service identity, image registry, public address or storage inventory.
Do not infer a deployment destination from the historical skill filename.

Before any operation, compare the private inventory with fresh reads of the
explicit Kubernetes context, namespace, Deployment UID and resource version,
container, image digest, service route and referenced ConfigMaps and Secrets.
Use isolated GCloud and Kubernetes clients; never switch another thread's
shared active configuration. Keep those reads and any resolved profile private.

The checked-in `deploy/profiles/soschain/staging/` directory supplies structural
examples only. Select the reviewed private runtime environment and GKE config
explicitly. Do not apply a generic manifest or another gateway's profile over an
existing admitted host.

Kubernetes destination and application custody are separate. The selected host
may retain a different project's Firestore, buckets, queue, Fabric identity or
KMS references. Retargeting a cluster does not authorize replacing those values.
`FIREBASE_PROJECT_ID` identifies the primary Admin/data project;
`FIREBASE_ADDITIONAL_AUTH_PROJECT_IDS` is an allowlist of verified token audiences,
not another data destination, an identity assertion or permission to read data.
Values are Firebase project IDs found in the token `aud` claim.

Preserve the original host/tenant identities, wrapped keys, data and actual
Fabric channels, package IDs and committed definitions. Infrastructure guidance
can help operate existing peer and chaincode services; it does not add a runtime
dependency or determine the selected host's topology. Confirm contract methods
and endorsement policy against its own configured peers and channels.

For a verifier upgrade, resolve effective `env` and `envFrom` precedence,
configure the approved issuer's real status metadata and an explicit durable
replay provider, and compare private pre/post Secret hashes, public verification
methods and authoritative data. Never replace those requirements with a network
label, ping response or generic contract count.

Use the existing private operator runbook and its guarded rollout plan for the
resolved target and rollback. Local, staging and production evidence remain
separate. Public TLS/readiness and an authenticated allowed/denied journey with
readback are required before declaring that environment operational.
