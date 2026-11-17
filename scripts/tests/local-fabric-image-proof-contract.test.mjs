// Flow contract: an exact local image and explicit external SDK driver prove
// ConsentAccess, SMART IPS allow/deny and role-licence readback. Missing stages,
// Demo verification, unknown targets or incomplete receipts cannot pass.
import test from 'node:test';
import assert from 'node:assert/strict';
const load = () => import('../local-fabric-image-proof.mjs');
const config = { image: 'local-image:reviewed', envFile: '/fixture/local.env', dockerNetwork: 'fixture-devnet',
  redisImage: 'local-redis:reviewed', driverModule: '/fixture/external-sdk-driver.mjs', driverConfig: '/fixture/driver.json' };

test('requires explicit image, local infrastructure and external SDK driver inputs', async () => {
  const { validateImageProofConfig } = await load();
  assert.doesNotThrow(() => validateImageProofConfig(config));
  for (const name of Object.keys(config)) assert.throws(() => validateImageProofConfig({ ...config, [name]: '' }));
});

test('complete native image gate requires real allow/deny and both ledger readbacks', async () => {
  const { validateRequiredStageReceipts } = await load();
  const complete = { consentAccess: { status: 'passed', readbackVerified: true }, smartIps: { status: 'passed', allowed: true, denied: true }, roleLicense: { status: 'passed', readbackVerified: true } };
  assert.doesNotThrow(() => validateRequiredStageReceipts(complete));
  for (const stage of Object.keys(complete)) assert.throws(() => validateRequiredStageReceipts({ ...complete, [stage]: undefined }));
  assert.throws(() => validateRequiredStageReceipts({ ...complete, smartIps: { status: 'passed', allowed: true, denied: false } }));
  assert.throws(() => validateRequiredStageReceipts({ ...complete, roleLicense: { status: 'passed', readbackVerified: false } }));
  assert.throws(() => validateRequiredStageReceipts({ ...complete, roleLicense: { status: 'passed', readbackVerified: 'true' } }));
});
