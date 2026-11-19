# SOSCHAIN Gateway documentation

Repository governance, task skills and release contracts are linked from the
[rules index](RULES_INDEX.md). Treat a broken rule link as a failed local gate.

This repository owns the SOS gateway-facing BFF and portal composition
documentation, as GW CORE did for the original integration. SDK documentation
describes reusable APIs and runtime mechanics only. Start with the
[BFF beginner contract](101-PORTAL_BFF_CONTRACT.md), continue with the
[complete portal API reference](PORTAL_API_TO_GW_CORE.md), then the
[host and tenant administration reference](HOST_AND_TENANT_ADMINISTRATION.md)
and [BFF Node runtime integration](BFF_NODE_RUNTIME.md).

This documentation describes SOSCHAIN Gateway v2. It intentionally does not
copy the inherited GW CORE manuals. Follow the upstream links when you need the
foundation's original design or version-specific reference.

## Reading order

1. [Architecture](architecture.md)
2. [BFF beginner contract](101-PORTAL_BFF_CONTRACT.md)
3. [Complete portal API reference](PORTAL_API_TO_GW_CORE.md)
4. [Host and tenant administration](HOST_AND_TENANT_ADMINISTRATION.md)
5. [Organization sectors and admission](https://github.com/soschain/sos-data-utils-ts/blob/main/docs/ORGANIZATION_SECTORS.md)
6. [Portal and demo deployment scope](PORTAL_DEPLOYMENT_SCOPE.md)
7. [BFF integration profile](bff-integration.md)
8. [BFF Node runtime integration](BFF_NODE_RUNTIME.md)
9. [Getting started](getting-started.md)
10. [API and interoperability](api-and-interoperability.md)
11. [Identifier-free public-health statistics](PUBLIC_HEALTH_STATISTICS.md)
12. [Security and deployment](security-and-deployment.md)
13. [Upstream projects and history](upstream-and-history.md)

## Sources of truth

- Runtime API: the generated `swagger-spec.json` and `/api-docs` in a running
  gateway.
- Installed code: `package.json` and `package-lock.json`.
- Release history: `CHANGELOG.md`.
- Upstream GW behavior: the linked GW CORE v1/v2 documentation, not a copied
  local manual.

Documents should distinguish implemented behavior from planned behavior and
must not include tenant identities, credentials, private endpoints or copied
deployment evidence.
