// Flow contract: one unreadable historical seat never grants access or prevents valid tenant seats from being listed.
// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import { describe, expect, it } from '@jest/globals';
import { DeviceAppTypes, DeviceUserClasses, EXAMPLE_LICENSE_ACTIVE_RECORD, EXAMPLE_LICENSE_AVAILABLE_RECORD, EXAMPLE_LICENSE_OFFER_ID, EXAMPLE_LICENSE_SEAT_UUID_ACTIVE, EXAMPLE_LICENSE_SUBJECT_ID_ACTIVE, LicenseCategories, LicenseClaimContext, LicenseStatuses } from 'gdc-common-utils-ts';
import { SchemaOrgOfferClaim, SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import {
  buildLicenseSearchClaims,
  extractLicenseSearchFilters,
  mapLicenseCategory,
  matchesLicenseFilters,
  searchLicenseDocuments,
} from '../../../utils/license-search';

describe('license-search utils', () => {
  it('extracts claims-first filters used by current shared search editors', () => {
    const filters = extractLicenseSearchFilters({
      meta: {
        status: EXAMPLE_LICENSE_AVAILABLE_RECORD.status,
        claims: {
          [SchemaOrgOfferClaim.SerialNumber]: EXAMPLE_LICENSE_ACTIVE_RECORD.id,
          [SchemaOrgPersonClaim.Email]: EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email],
        },
      },
    } as any);

    expect(filters[SchemaOrgOfferClaim.SerialNumber]).toEqual([EXAMPLE_LICENSE_ACTIVE_RECORD.id]);
    expect(filters[SchemaOrgPersonClaim.Email]).toEqual([EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email]]);
    expect(filters.status).toEqual([EXAMPLE_LICENSE_AVAILABLE_RECORD.status]);
  });

  it('projects stored device licenses into schema.org-flavored search claims', () => {
    const claims = buildLicenseSearchClaims({
      id: EXAMPLE_LICENSE_SEAT_UUID_ACTIVE,
      userClass: DeviceUserClasses.Employee,
      type: DeviceAppTypes.Mobile,
      orderId: EXAMPLE_LICENSE_OFFER_ID,
      issuedToEmail: EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email],
      issuedToRole: EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.OccupationIdentifierValue],
    } as any);

    expect(claims['@context']).toBe(LicenseClaimContext.SchemaOrg);
    expect(claims[SchemaOrgOfferClaim.SerialNumber]).toBe(EXAMPLE_LICENSE_SEAT_UUID_ACTIVE);
    expect(claims[SchemaOrgOfferClaim.Identifier]).toBe(EXAMPLE_LICENSE_OFFER_ID);
    expect(claims[SchemaOrgPersonClaim.Email]).toBe(EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email]);
  });

  it('matches exact license filters against the current storage model', () => {
    const matches = matchesLicenseFilters(
      {
        id: EXAMPLE_LICENSE_SEAT_UUID_ACTIVE,
        status: LicenseStatuses.Available,
        userClass: DeviceUserClasses.Employee,
        type: DeviceAppTypes.Mobile,
        orderId: EXAMPLE_LICENSE_OFFER_ID,
        subjectId: EXAMPLE_LICENSE_SUBJECT_ID_ACTIVE,
      } as any,
      {
        [SchemaOrgOfferClaim.SerialNumber]: [EXAMPLE_LICENSE_SEAT_UUID_ACTIVE],
        status: [LicenseStatuses.Available],
      },
    );

    expect(matches).toBe(true);
    expect(mapLicenseCategory(DeviceUserClasses.Employee)).toBe(LicenseCategories.Professional);
  });

  it('fails closed for one unreadable historical document while returning valid seats', async () => {
    const validLicense = {
      id: EXAMPLE_LICENSE_SEAT_UUID_ACTIVE,
      status: LicenseStatuses.Active,
      userClass: DeviceUserClasses.Employee,
      type: DeviceAppTypes.Mobile,
      issuedToEmail: EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email],
    };
    const validDocument = { id: 'valid', content: validLicense };
    const unreadableDocument = { id: 'legacy-corrupt', content: { protected: 'invalid' } };
    const repository = {
      getContainersInSection: jest.fn().mockResolvedValue([unreadableDocument, validDocument]),
    };
    const unprotect = jest.fn(async (document: any) => {
      if (document.id === 'legacy-corrupt') throw new Error('Invalid authentication tag length: 3');
      return document.content;
    });

    const rows = await searchLicenseDocuments(repository, 'tenant-vault', {
      [SchemaOrgPersonClaim.Email]: [EXAMPLE_LICENSE_ACTIVE_RECORD.claims[SchemaOrgPersonClaim.Email]],
    }, unprotect);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: EXAMPLE_LICENSE_SEAT_UUID_ACTIVE });
    expect(unprotect).toHaveBeenCalledTimes(1);
  });
});
