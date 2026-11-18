// Flow contract: trusted server maps survive environment-to-ConfigMap rendering
// exactly; malformed maps stop before Kubernetes, and strict staging retains real
// verification with an explicit durable provider. All deployment commands are doubles.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '../..');
const names = ['CREDENTIAL_TRUSTED_ISSUERS_JSON', 'CLEARING_HOUSE_REQUESTERS_JSON', 'GXDCH_TENANTS_JSON'];
function runDeployment(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sos-deploy-contract-'));
  mkdirSync(join(dir, 'scripts')); mkdirSync(join(dir, 'bin')); mkdirSync(join(dir, 'deploy/gke-gw'), { recursive: true });
  copyFileSync(join(root, 'scripts/deploy-gke-gw.sh'), join(dir, 'scripts/deploy-gke-gw.sh'));
  // Isolate rendering from the separately tested runtime-profile validator.
  writeFileSync(join(dir, 'scripts/validate-gw-runtime-profile.sh'), '#!/bin/sh\nexit 0\n');
  const helper = 'render-deployment-trust-config.mjs';
  if (existsSync(join(root, 'scripts', helper))) copyFileSync(join(root, 'scripts', helper), join(dir, 'scripts', helper));
  for (const file of readdirSync(join(root, 'deploy/gke-gw'))) {
    if (file.endsWith('.yaml')) copyFileSync(join(root, 'deploy/gke-gw', file), join(dir, 'deploy/gke-gw', file));
  }
  writeFileSync(join(dir, 'bin/kubectl'), `#!/bin/sh\nprintf '%s\\n' "$*" >> "$DEPLOY_CONTRACT_LOG"\ncase "$*" in *configmap.yaml*) cp "$3" "$DEPLOY_CONTRACT_MAP" ;; esac\n`, { mode: 0o755 });
  const result = spawnSync('bash', [join(dir, 'scripts/deploy-gke-gw.sh')], { encoding: 'utf8', env: {
    ...process.env, PATH: `${join(dir, 'bin')}:${process.env.PATH}`,
    K8S_NAMESPACE_GDC: 'example-namespace', GDC_IMAGE: 'example.invalid/gateway:contract', GDC_PUBLIC_URL: 'https://example.invalid',
    GDC_STATIC_IP_NAME: 'example-address', GCP_PROJECT_ID: 'example-project', GDC_GSA_EMAIL: 'service@example.invalid',
    LEDGER_MSP_ID: 'ExampleMSP', LEDGER_FABRIC_MSP_ID: 'ExampleMSP',
    DEPLOYMENT_ENV: 'staging', NODE_ENV: 'staging', SECURITY_MODE: 'strict', NETWORK_MODE: 'test-network',
    DB_PROVIDER: 'firestore', REPLAY_PROTECTION_PROVIDER: 'firestore', CLEARING_HOUSE_MODE: 'local',
    GDC_INGRESS_ENABLED: 'false', GDC_TLS_SIDECAR_ENABLED: 'false', GDC_FABRIC_PEER_ALIAS_ENABLED: 'false',
    DEPLOY_CONTRACT_LOG: join(dir, 'calls'), DEPLOY_CONTRACT_MAP: join(dir, 'map'), ...overrides,
  }});
  const output = { result, calls: existsSync(join(dir, 'calls')) ? readFileSync(join(dir, 'calls'), 'utf8') : '',
    map: existsSync(join(dir, 'map')) ? readFileSync(join(dir, 'map'), 'utf8') : '' };
  rmSync(dir, { recursive: true, force: true }); return output;
}

test('all three trusted maps round-trip JSON as safe YAML strings', () => {
  const entry = { 'did:web:example.invalid': { note: 'O\'Connor "quoted" \\ path | &\nsecond line', endpoint: 'https://example.invalid/check' } };
  const values = Object.fromEntries(names.map(name => [name, JSON.stringify(entry)]));
  const { result, map } = runDeployment(values);
  assert.equal(result.status, 0, result.stderr);
  for (const name of names) {
    const scalar = map.split('\n').find(line => line.startsWith(`  ${name}: `))?.slice(`  ${name}: `.length);
    assert.ok(scalar?.startsWith('"'), `${name} must be a quoted JSON-compatible YAML scalar`);
    assert.deepEqual(JSON.parse(JSON.parse(scalar)), entry);
  }
});

for (const name of names) {
  test(`${name} malformed or non-object JSON rejects before kubectl`, () => {
    for (const value of ['{invalid', '[]', 'null']) {
      const { result, calls } = runDeployment({ [name]: value });
      assert.notEqual(result.status, 0, `${name} accepted ${value}`);
      assert.equal(calls, '', 'validation must precede every kubectl call');
    }
  });
}

test('strict staging defaults select native verification and existing Firestore replay', () => {
  const { result, map } = runDeployment({ CLEARING_HOUSE_MODE: '', REPLAY_PROTECTION_PROVIDER: '' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(map, /CLEARING_HOUSE_MODE: "local"/);
  assert.match(map, /REPLAY_PROTECTION_PROVIDER: "firestore"/);
  const staging = readFileSync(join(root, 'env.staging.example'), 'utf8');
  assert.match(staging, /^CLEARING_HOUSE_MODE=local$/m);
  assert.match(staging, /^REPLAY_PROTECTION_PROVIDER=firestore$/m);
});

test('enrolled network without existing Firestore requires explicit durable replay', () => {
  const { result, calls } = runDeployment({ DB_PROVIDER: 'mem', REPLAY_PROTECTION_PROVIDER: '' });
  assert.notEqual(result.status, 0);
  assert.equal(calls, '');
});

// The legacy-origin list is optional transport configuration, never caller authority.
test('optional legacy public origins render unchanged with an empty compatibility default', () => {
  for (const origins of ['', 'https://previous.example.invalid,https://earlier.example.invalid:8443']) {
    const { result, map } = runDeployment({ HOST_LEGACY_PUBLIC_URLS: origins });
    assert.equal(result.status, 0, result.stderr);
    const scalar = map.split('\n').find(line => line.startsWith('  HOST_LEGACY_PUBLIC_URLS: '))?.slice('  HOST_LEGACY_PUBLIC_URLS: '.length);
    assert.ok(scalar, 'the optional runtime field must be forwarded by the generic renderer');
    assert.equal(JSON.parse(scalar), origins);
  }
});
