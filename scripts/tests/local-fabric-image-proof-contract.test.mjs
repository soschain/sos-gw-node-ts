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

test('reviewer startup trust is explicit public metadata distinct from the ICA', async () => {
  const { validateFixtureReviewerTrust } = await load();
  const publicTrust = { issuer: 'did:web:example.invalid:organization', actorDid: 'did:web:example.invalid:organization:employee:reviewer:RESPRSN', role: 'RESPRSN', status: 'active', jwk: { kty: 'AKP', alg: 'ML-DSA-65', kid: 'synthetic-governance-key', pub: 'c3ludGhldGljLXB1YmxpYy1tYXRlcmlhbA' } };
  assert.doesNotThrow(() => validateFixtureReviewerTrust(publicTrust, 'did:web:example.invalid:ica'));
  for (const mutation of [{ issuer: 'did:web:example.invalid:ica' }, { status: 'inactive' }, { role: 'doctor' }, { jwk: { ...publicTrust.jwk, d: 'private' } }, { jwk: { ...publicTrust.jwk, seed: 'private' } }, { jwk: { ...publicTrust.jwk, k: 'private' } }, { jwk: { ...publicTrust.jwk, secretKeyBytes: 'private' } }, { sign: () => {} }, { jwk: { ...publicTrust.jwk, alg: 'ES384' } }]) {
    assert.throws(() => validateFixtureReviewerTrust({ ...publicTrust, ...mutation }, 'did:web:example.invalid:ica'));
  }
});

test('actual Docker environment binds the prepared identity and data channels and selected sector', async () => {
  const { buildPreparedLedgerEnvironment } = await load();
  const prepared = { identityChannel: 'identity-local', dataChannel: 'health-tech-na', channels: new Set(['identity-local', 'health-tech-na', 'health-tech-na-research']), sector: 'health-tech' };
  assert.deepEqual(buildPreparedLedgerEnvironment(prepared), {
    LEDGER_IDENTITY_CHANNEL_DEFAULT: 'identity-local', LEDGER_ORGANIZATION_IDENTITY_CHANNEL_DEFAULT: 'identity-local',
    LEDGER_DATA_CHANNEL_DEFAULT: 'health-tech-na', DEFAULT_SECTOR: 'health-tech',
  });
  assert.throws(() => buildPreparedLedgerEnvironment({ ...prepared, dataChannel: 'unprepared-channel' }));
  assert.throws(() => buildPreparedLedgerEnvironment({ ...prepared, identityChannel: 'unprepared-identity' }));
  assert.throws(() => buildPreparedLedgerEnvironment({ ...prepared, sector: '' }));
});
