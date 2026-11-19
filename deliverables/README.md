# SOS Gateway deliverables

- [Public security report](SECURITY-ASSESSMENT.md) covers adapter contracts,
  evidence and the checks for promotion.
- [Host bootstrap and controller security](HOST-BOOTSTRAP-AND-CONTROLLER-SECURITY.md)
  traces portal sign-in, wallet custody, ICA verification, admission and device
  registration, with links to the implementation.
- [Reproducible Kubernetes deployment](../charts/sos-gateway/README.md) covers
  the operator-managed Helm workload and the Google Cloud profile.
- [Release contract](../docs/LOCAL_FIRST_RELEASE_CONTRACT.md) and
  [persistence evidence](../docs/PERSISTENCE_RELEASE_RED_LINES.md) specify how
  to validate the image and deployment.

Operating organizations keep their real deployment values, custody records
and evidence containing infrastructure or personal information in their
private operations repository.
