// Flow contract: the local role-licence compatibility source follows its
// canonical Fabric owner. Ledger policy/history and gateway DCR capacity are
// separate responsibilities; a local source reconciliation never deploys CCAAS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const root = resolve(import.meta.dirname, '../..');
const canonicalRoot = process.env.FABRIC_MULTICLOUD_DIR || resolve(root, '../../fabric-multicloud');

test('compatibility contract source matches canonical regional role licence', () => {
  const canonical = readFileSync(resolve(canonicalRoot, 'devnet/fabric-v3/external-chaincodes/rolelicense-sc/lib/role-license-contract.js'), 'utf8');
  const local = readFileSync(resolve(root, 'chaincode/rolelicense-sc-javascript/lib/role-license-contract.js'), 'utf8');
  assert.equal(local, canonical);
  assert.doesNotMatch(local, /async (?:RegisterDevice|registerDevice)\(/);
});

test('smoke checks licence policy without claiming device registration on chain', () => {
  const smoke = readFileSync(resolve(root, 'scripts/smoke-rolelicense-local-network.sh'), 'utf8');
  for (const operation of ['EnsureRoleLicense', 'UpsertSectorPolicy', 'ReadRoleLicense']) assert.ok(smoke.includes(operation));
  assert.doesNotMatch(smoke, /invoke (?:RegisterDevice|registerDevice)/);
  assert.ok(smoke.includes('has("devices") | not'));
  assert.doesNotMatch(smoke, /maxDevices:5|\.maxDevices == 5/);
  assert.ok(smoke.includes('buildOrganizationRoleLicenseId'));
});
