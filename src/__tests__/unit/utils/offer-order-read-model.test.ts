// Flow contract: independent identity and commerce claim catalogs preserve exact stored keys and authorization boundaries.
// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import { describe, expect, it } from '@jest/globals';
import { EXAMPLE_LICENSE_OFFER_ID, LicenseCommercialSearchOperation, LicenseCategories, LicenseClaimContext, LicenseStatuses } from 'gdc-common-utils-ts';
import { SchemaOrgOfferClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import {
  buildOfferOrderSearchRow,
  extractOfferOrderSearchClaims,
  matchOfferOrderSearchClaims,
} from '../../../utils/offer-order-read-model';

describe('offer-order-read-model utils', () => {
  it('extracts normalized claims from resource.meta.claims and ignores transport nesting details', () => {
    const claims = extractOfferOrderSearchClaims({
      resource: {
        meta: {
          claims: {
            '@context': LicenseClaimContext.SchemaOrg,
            [SchemaOrgOfferClaim.Identifier]: EXAMPLE_LICENSE_OFFER_ID,
          },
        },
      },
    } as any);

    expect(claims[SchemaOrgOfferClaim.Identifier]).toBe(EXAMPLE_LICENSE_OFFER_ID);
  });

  it('matches only exact non-empty business filters and ignores @-prefixed vocab keys', () => {
    const matches = matchOfferOrderSearchClaims(
      {
        [SchemaOrgOfferClaim.Identifier]: EXAMPLE_LICENSE_OFFER_ID,
        [SchemaOrgOfferClaim.Category]: LicenseCategories.Professional,
      },
      {
        '@type': LicenseCommercialSearchOperation.Offer,
        [SchemaOrgOfferClaim.Identifier]: EXAMPLE_LICENSE_OFFER_ID,
      },
    );

    expect(matches).toBe(true);
  });

  it('projects one compact row shape for portal-oriented read models', () => {
    const row = buildOfferOrderSearchRow(
      {
        id: EXAMPLE_LICENSE_OFFER_ID,
        status: LicenseStatuses.Active,
      } as any,
      {
        [SchemaOrgOfferClaim.Identifier]: EXAMPLE_LICENSE_OFFER_ID,
      },
      SchemaOrgOfferClaim.Identifier,
    );

    expect(row).toEqual({
      id: EXAMPLE_LICENSE_OFFER_ID,
      meta: {
        status: LicenseStatuses.Active,
        claims: {
          [SchemaOrgOfferClaim.Identifier]: EXAMPLE_LICENSE_OFFER_ID,
        },
      },
    });
  });
});
