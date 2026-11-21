# Publish and verify your tenant catalogue

Run the first check against the development host. Select the controller
session for the exact tenant, jurisdiction and sector that will publish the
listing. In the portal, use the same authenticated server-side
`WorkforceClient` that already makes controller requests for that tenant.

## Publish a product or service

1. Prepare the reviewed catalogue entries with a stable `id`, a `type` of
   `Product` or `Service`, and their public Schema.org attributes. Send
   products and services in separate batches.
2. Add this function to the portal's server code and call it with the
   existing controller client and the reviewed batch. The example uses
   `antifraud-data-utils-ts@0.4.5` and `sos-sdk-node-ts@0.6.4`. Store the operation ID
   alongside the change and reuse it when retrying that change.

```ts
import { readPublicOfferingDraftDocument } from 'antifraud-data-utils-ts/public-offering-catalog'
import type { WorkforceClient } from 'sos-sdk-node-ts/workforce-client'

export async function publishTenantOfferings(
  client: WorkforceClient,
  entries: unknown,
  operationId: string,
) {
  const document = readPublicOfferingDraftDocument({ data: entries })
  return client.publishOfferingBatch({ document, operationId })
}
```

3. Use `await client.getPublishedOfferings()` to check that the expected IDs
   and updated values are visible in that tenant. Its public DCAT catalogue
   at `/dsp/catalog/dcat.json` beneath the tenant base URL links the offering
   feed. Repeat with a second tenant and verify each listing appears under
   its own publisher.

## Edit or withdraw an offering

Keep the same JSON:API `type` and `id` when sending an edit. A change to the
validated listing creates a new version. Its history has a `versionId` and a
SHA-256 `contentHash` for the recorded listing. Two versions can have the
same hash if an edit restores older terms.

With the updated controller SDK, use the same open controller session that
published the listing. Pass the type and ID from the published entry and a
separate operation ID for each request.

```ts
await client.unpublishOffering({ type: 'Product', id: listingId, operationId: withdrawalId })
const { versions } = await client.getOfferingHistory({
  type: 'Product', id: listingId, operationId: historyRequestId,
})
```

The SDK sends the JSON:API reference to `Catalog/_unpublish` or
`Catalog/_history` and confirms the result before returning.
Withdrawal records the version that was public and removes just that entry
from discovery. Re-importing a snapshot preserves its withdrawal. Publishing
that exact entry again explicitly through `Catalog/_upsert` makes it visible.
The history includes versions recorded from this update onwards and any
older listing still available when version tracking began.

The public Schema.org listing and a signed Gaia-X service offering have
separate publication paths. The currently supported signed tenant offerings
come from enabled provider capabilities and their configured terms. Updating
a commercial listing through the example above updates the public listing.
Automatic updates to the corresponding signed Gaia-X offer require the
listing-to-credential integration.

## Prepare external dataset metadata

Given a resolved Ocean DDO, the BFF can prepare the dataset and its linked
access services while preserving the original asset DID.

```ts
import {
  buildCataloguePrimaryDocument,
  projectOceanDatasetEntries,
} from 'antifraud-data-utils-ts/ocean-catalogue'

export function prepareDatasetNotification(ddo: unknown, landingPage?: string) {
  return buildCataloguePrimaryDocument(projectOceanDatasetEntries({ ddo, landingPage }))
}
```

Use the generic dataset receiver once the target gateway exposes a mapping
for `Dataset` and `DataService`. The current commercial batch accepts
`Product` or `Service`. For a research dataset, publish through the existing
HealthDCAT lifecycle and check the tenant DCAT catalogue after publishing and
archiving the record.

## Read the host's signed offer

With the host's legal participant credential available, configure the public
terms document URL and its SHA-256 digest together using `HOST_TERMS_URL` and
`HOST_TERMS_SHA256`. Then read
`/host/cds-{coverage}/v1/{network}/.well-known/service-offering-hosting.json`.
The host's `/dsp/catalog/dcat.json` under the same base advertises that URL.
Use that host catalogue URL as a configured source for ICA discovery.
