// Flow contract: the immutable-image Fabric gate retains real consent, SMART
// and role-licence stages while requiring independent signed identity evidence;
// a Demo ICA, plaintext bearer or health-only run cannot prove strict operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const root = resolve(import.meta.dirname, '../..');
const smoke = () => readFileSync(resolve(root, 'scripts/smoke-docker-local-network.sh'), 'utf8');

test('the image gate does not launch the retired ICA or silently choose Demo', () => {
  const source = smoke();
  assert.doesNotMatch(source, /CONNECT_ICA_ROOT|connect-ica-ts|SECURITY_MODE=demo/);
  assert.match(source, /CLEARING_HOUSE_MODE=local/);
  assert.match(source, /SECURITY_MODE=(?:strict|compat)/);
});

test('the complete image gate preserves Fabric consent, SMART and role-licence checks', () => {
  const source = smoke();
  assert.ok(source.includes('local-fabric-image-proof.mjs'));
  const orchestration = readFileSync(resolve(root, 'scripts/local-fabric-image-proof.mjs'), 'utf8');
  for (const stage of ['consentAccess', 'smartIps', 'roleLicense']) assert.ok(orchestration.includes(stage));
  assert.ok(orchestration.includes('validateRequiredStageReceipts(results.stages)'));
  // Research remains scoped opt-in; its separate real HTTP suite owns that proof.
  assert.doesNotMatch(source, /AUTH_BEARER=.*demo-token/);
});

test('the Fabric profile does not inherit unsigned Demo or a disabled verifier', () => {
  const profile = readFileSync(resolve(root, 'scripts/prepare-consentaccess-local-fabric-env.sh'), 'utf8');
  assert.match(profile, /CLEARING_HOUSE_MODE=local/);
  assert.match(profile, /SECURITY_MODE=(?:strict|compat)/);
  assert.match(profile, /^DEPLOYMENT_ENV=dev$/m);
  assert.doesNotMatch(profile, /^DEPLOYMENT_ENV=local$/m);
  assert.doesNotMatch(profile, /REPLAY_PROTECTION_PROVIDER=none/);
});
