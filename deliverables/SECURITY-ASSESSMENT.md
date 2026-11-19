# SOS Gateway security assessment

This is the public engineering assessment. It records verified controls and
the evidence needed for deployment. An independent assessment and production
sign-off are separate records.

| Boundary | Implementation and validation |
|---|---|
| Durable jobs | The common payload store encrypts and authenticates jobs before writing. The storage adapter receives ciphertext. A local test checks recovery using another runtime instance and rejects cleartext or an object substituted at a different reference. |
| Development transport | A local demonstration can use the in-memory queue. With a durable queue, stored jobs require encryption regardless of the incoming transport. |
| Custody | Key custody is independent of storage. The repository tests the envelope contract for Google Cloud KMS, AWS KMS and HashiCorp Transit with controlled provider doubles. The application worker can temporarily process decrypted content. |
| Telemetry | Regression tests check that the HTTP and worker diagnostics, SMS webhook and voice lookup under test omit sensitive values. These tests cover the named paths. |
| Deployment | The Helm render contract checks immutable image references, HTTPS origin, external KMS, strict mode and an internal Kubernetes Service. Runtime validation is required on the exact image. |

For the Google profile, verify the GKE identity and deployment permissions,
Cloud KMS custody, private GCS objects, Pub/Sub redelivery and Firestore
persistence against the actual deployment. Validate authenticated delivery
through the production-facing portals and confirm restart and recovery.
Review every persistence destination, including auxiliary storage,
diagnostics and ledger metadata. See the
[operator guide](../charts/sos-gateway/README.md) and
[persistence release criteria](../docs/PERSISTENCE_RELEASE_RED_LINES.md).

Verify the runtime's plaintext boundary before claiming that infrastructure
operators are technically excluded from content. The portal's terms should
identify the actual operator, storage and processing locations and scope of
the demonstrated protections. An audit records results and residual risk
for a specific revision and configuration.

Report a suspected vulnerability through the private channel described in
[SECURITY.md](../SECURITY.md).
