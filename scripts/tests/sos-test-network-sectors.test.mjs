// Flow contract: the SOS Test Network deployment enables both reviewed research
// sectors and the canonical technical sectors configured for automatic admission.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { DataspaceSectors } from 'sos-data-utils-ts/dataspace-sectors';

const expectedSectors = [
  DataspaceSectors.OneHealthResearch, DataspaceSectors.AnimalResearch,
  DataspaceSectors.AnimalTech, DataspaceSectors.HealthTech, DataspaceSectors.OneHealthTech,
].sort();

test('the SOS Test Network profile enables its research and technical sectors', () => {
  const profile = readFileSync(new URL('../../deploy/profiles/soschain/staging/gke.config.example', import.meta.url), 'utf8');
  for (const variable of ['ALLOWED_SECTORS', 'GDC_REQUIRED_SECTORS']) {
    const sectors = profile.match(new RegExp(`^export ${variable}=(.*)$`, 'm'))?.[1].split(',').sort();
    assert.deepEqual(sectors, expectedSectors, variable);
  }
});

test('the UHC Test Network configuration also enables the five SOS sectors', () => {
  const config = readFileSync(new URL('../../deploy/profiles/human/staging/configmap.yaml', import.meta.url), 'utf8');
  const sectors = new Set(config.match(/^  ALLOWED_SECTORS: (.*)$/m)?.[1].split(','));
  for (const sector of expectedSectors) assert.ok(sectors.has(sector), sector);
});
