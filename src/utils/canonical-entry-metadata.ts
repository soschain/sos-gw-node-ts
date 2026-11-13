// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';

/** Moves legacy claims to resource metadata while preserving other entry metadata. */
export function canonicalizeBundleEntryMetadata(
  meta: Record<string, unknown> | undefined,
): Readonly<Record<string, unknown>> {
  if (!meta || typeof meta !== 'object') return {};
  const { claims, ...entryMeta } = meta;
  return {
    ...(Object.keys(entryMeta).length > 0 ? { meta: entryMeta } : {}),
    ...(claims && typeof claims === 'object'
      ? { resource: { resourceType: ResourceTypesFhirR4.OperationOutcome, meta: { claims } } }
      : {}),
  };
}
