// Flow contract: the source manifest retains explicit reviewed registry pins; this check does not establish runtime API availability or a GDC-free release graph.
/**
 * 1. Shared dependencies use explicit source-manifest pins.
 * 2. Local immutable snapshots may prove unpublished source APIs during migration.
 * 3. Registry export availability and removal of transitive GDC dependencies are
 *    separate release gates; the manifest alone is never release evidence.
 */
import fs from 'node:fs';
import path from 'node:path';

describe('shared runtime dependency contract', () => {
  it('retains the reviewed shared dependency pins while replacement releases are pending', () => {
    const packageJson = JSON.parse(
      fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8'),
    ) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };

    expect(packageJson.dependencies?.['gdc-common-utils-ts']).toBe('2.9.30');
    expect(packageJson.dependencies?.['antifraud-data-utils-ts']).toBe('0.2.0');
    expect(packageJson.dependencies?.['fhir-data-utils-ts']).toBe('0.6.24');
    expect(packageJson.dependencies?.['sos-data-utils-ts']).toBe('0.6.28');
    expect(packageJson.dependencies?.['sos-sdk-core-ts']).toBe('0.5.5');
    expect(packageJson.dependencies?.['vet-data-utils-ts']).toBe('0.8.7');
    expect(packageJson.devDependencies?.['vet-sdk-core-ts']).toBe('0.7.1');
  });
});
