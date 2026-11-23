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
  it('requires exact independent registry pins for the shared runtime and test clients', () => {
    const packageJson = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>; devDependencies?: Record<string, string>;
    };
    for (const name of ['antifraud-data-utils-ts', 'antifraud-sdk-node-ts', 'fhir-data-utils-ts', 'sos-data-utils-ts', 'sos-sdk-core-ts']) {
      expect(packageJson.dependencies?.[name]).toMatch(/^\d+\.\d+\.\d+$/);
    }
    expect(packageJson.devDependencies?.['sos-sdk-node-ts']).toMatch(/^\d+\.\d+\.\d+$/);
    expect(packageJson.devDependencies?.['antifraud-sdk-node-ts']).toBeUndefined();
    for (const section of [packageJson.dependencies, packageJson.devDependencies]) {
      expect(Object.keys(section || {}).some(name => name.startsWith('gdc-'))).toBe(false);
      for (const name of ['vet-data-utils-ts', 'vet-sdk-core-ts', 'uhc-sdk-core-ts']) expect(section?.[name]).toBeUndefined();
    }
  });
});
