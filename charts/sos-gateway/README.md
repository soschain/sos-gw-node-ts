# SOS Gateway on Kubernetes

This chart installs the Gateway workload and an internal ClusterIP Service.
It uses an existing namespace, service account, ConfigMap and Secret. The
operator provides the approved image, TLS route, workload identity, durable
services, and applicable ICA and Fabric connections. The chart never provisions
or joins a Fabric peer. The host operator completes that lifecycle under the
network governance rules before enabling its Gateway connection.

The chart requires a digest, HTTPS public origin, strict runtime and external
KMS. Its HTTP port is internal. The rollout probes establish process health.
An authenticated application roundtrip and persistent readback establish
service readiness.

## Render and install

Run from the repository root. Keep the real values file and kube context in
the operator's private directory. The example is for rendering only.

```bash
helm lint charts/sos-gateway -f charts/sos-gateway/ci/example-values.yaml
helm template sos-gateway charts/sos-gateway -f charts/sos-gateway/ci/example-values.yaml
node --test scripts/tests/helm-sos-gateway.contract.test.mjs
```

Prepare the private values from the keys shown in `values.yaml`. Supply an
approved image repository and digest, origin and the names of existing
resources. Confirm the route terminates HTTPS and targets the internal Service.
Set the approved configuration and secret values through the operator's
managed workflow. Inspect the render before changing the cluster.

```bash
helm template "$SOS_RELEASE" charts/sos-gateway \
  --namespace "$SOS_NAMESPACE" -f "$SOS_PRIVATE_VALUES"

helm upgrade --install "$SOS_RELEASE" charts/sos-gateway \
  --kube-context "$SOS_KUBE_CONTEXT" --namespace "$SOS_NAMESPACE" \
  -f "$SOS_PRIVATE_VALUES" --wait --atomic --timeout 10m

kubectl --context "$SOS_KUBE_CONTEXT" -n "$SOS_NAMESPACE" \
  rollout status "deployment/$SOS_RELEASE" --timeout=10m
```

Run the exact [persistence checks](../../docs/PERSISTENCE_RELEASE_RED_LINES.md)
and [release sequence](../../docs/LOCAL_FIRST_RELEASE_CONTRACT.md). Record the
release revision and previous known-good digest. An image rollback does not
undo a data or queue format change. Apply the reviewed queue cutover or data
recovery procedure before changing revisions when the formats differ.

## Validation on a shared cluster

Use `networkMode: test-network` in the validation values. Create an isolated
namespace and provide its own workload identity, quotas, network policy,
config and secret references. Allocate its own host identity and endpoints,
test data and service resources. The chart keeps the same secure container
and KMS requirements as production.

A namespace shares the control plane and may share worker nodes. Review who
can administer the whole cluster, access nodes or act as another workload.
Before co-locating production, verify hard isolation of identities, network
and data, and size the workload against cluster capacity. A dedicated cluster
is warranted when the required administrative boundary cannot be enforced.

Admission of a host and its peer to a production Fabric network is a separate
operation. First validate with the authorized Test Network configuration and
synthetic data. Obtain the approved production MSP, channel participation,
endpoints and credentials for the peer before installing the production
profile. Production ledger operations use the production release evidence.

## Governed organization admission in Test Network

Set `testNetworkAdmissionEnabled: true` with `networkMode: test-network`.
The chart requires `HOST_ADMISSION_ICA_URL` and
`HOST_ADMISSION_DECISION_URL` from the existing ConfigMap and
`HOST_ADMISSION_ICA_TOKEN` and `HOST_ADMISSION_DECISION_TOKEN` from the
existing Secret. A missing key prevents Kubernetes from starting the
container. The Gateway validates the HTTPS endpoints and credential
configuration at startup. Use dedicated credentials for the selected host
and network.

Deploy the matching ICA and controller revisions before starting the
Gateway. Check the controller assignment and selected sector and country
in the controller portal, then confirm a verified application advances
through Offer, Order, activation and device registration. Confirm an
application with incomplete evidence stays in review. See the
[admission sequence](../../deliverables/HOST-BOOTSTRAP-AND-CONTROLLER-SECURITY.md#3-verify-the-evidence-and-authorize-admission).

## Google Cloud profile

Select `kmsProvider: gcp`. The company operating GKE and the organization
owning Firebase and Cloud KMS can use different projects. Grant the Gateway
workload identity the required access in each owning project. Review the
effective policy and keep operator administration separate from access to
clinical data and use of cryptographic keys.

Set `FIREBASE_PROJECT_ID` in the runtime ConfigMap to the primary Firebase
project that owns the Firestore data. The Gateway uses that value for its
default Firebase Admin app. Additional Firebase token issuers configured in
`FIREBASE_ADDITIONAL_AUTH_PROJECT_IDS` are Auth-only and do not select storage.
Verify the expected token audience and the actual Firestore write destination
independently. If the portals use a separate approved Firebase Auth project,
review the corresponding trusted issuer and portal config.

For the Firestore, GCS and Pub/Sub profile, set:

| Area | Runtime configuration to review |
|---|---|
| Vault and files | `DB_PROVIDER=firestore`, `STORAGE_PROVIDER=gcs`, `FIREBASE_PROJECT_ID`, `GCS_BUCKET_NAME` |
| Queue | `QUEUE_PROVIDER=gcp-pubsub`, `GCP_PUBSUB_PROJECT_ID`, `GCP_PUBSUB_TOPIC`, `GCP_PUBSUB_SUBSCRIPTION`, `GCP_PUBSUB_JOB_BUCKET`, `GCP_PUBSUB_JOB_PREFIX` |
| Responses | `ASYNC_RESPONSE_STORE_PROVIDER=firestore`, dedicated collection and retention |
| Custody | `KMS_KEY_ID`, `KMS_RUNTIME_KEK_ID` and encrypted `KMS_RUNTIME_KEK_CIPHERTEXT` through the managed secret workflow |
| Trust | Host and tenant configuration, approved issuers, and environment-specific ICA and Fabric configuration |

Declare the storage and processing location for each service in the private
deployment record. Verify any identity-to-project binding, queue and bucket
permissions, and storage isolation on the exact release. See the official
[GKE workload identity guide](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
and [Cloud KMS separation of duties](https://docs.cloud.google.com/kms/docs/separation-of-duties).
