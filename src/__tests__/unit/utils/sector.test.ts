// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';
import { isFhirSector } from '../../../utils/sector';

describe('FHIR sector classification', () => {
  it('publishes FHIR metadata for the onehealth research sector', () => {
    expect(isFhirSector(DataspaceSectors.OneHealthResearch)).toBe(true);
  });

  it('publishes FHIR Consent services for the animal-insurance sector', () => {
    expect(isFhirSector(DataspaceSectors.AnimalInsurance)).toBe(true);
  });
});
