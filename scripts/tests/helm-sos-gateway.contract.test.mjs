// Flow contract: the deployable SOS Helm profile requires an immutable image, external custody and admission configuration when enabled.
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const chart = 'charts/sos-gateway';
const valid = [
  '--set-string', 'image.repository=registry.example.invalid/sos-gateway',
  '--set-string', 'image.digest=sha256:' + 'a'.repeat(64),
  '--set-string', 'publicUrl=https://gateway.example.invalid',
  '--set-string', 'existingConfigMap=gateway-config',
  '--set-string', 'existingSecret=gateway-runtime',
  '--set-string', 'serviceAccountName=gateway-workload',
  '--set-string', 'kmsProvider=gcp',
];
function render(...overrides) {
  return spawnSync('helm', ['template', 'candidate', chart, ...valid, ...overrides], { encoding: 'utf8' });
}

test('renders a private Kubernetes service with strict production runtime and external configuration references', () => {
  const result = render();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /registry\.example\.invalid\/sos-gateway@sha256:a{64}/);
  assert.match(result.stdout, /type: ClusterIP/);
  assert.match(result.stdout, /name: SECURITY_MODE\s+value: "strict"/);
  assert.match(result.stdout, /name: NETWORK_MODE\s+value: "network"/);
  for (const setting of ['DEMO_ALLOW_INSECURE_BEARER', 'DIDCOMM_PLAIN', 'JSON_LEGACY', 'FHIR_LEGACY']) {
    assert.match(result.stdout, new RegExp('name: ' + setting + '\\s+value: "false"'));
  }
  assert.match(result.stdout, /name: KMS_PROVIDER\s+value: "gcp"/);
  assert.match(result.stdout, /secretRef:\s+name: "gateway-runtime"/);
  assert.match(result.stdout, /allowPrivilegeEscalation: false/);
  assert.doesNotMatch(result.stdout, /kind: Secret\b/);
});

test('rejects tag-only images, HTTP origins and local custody', () => {
  for (const [override, diagnostic] of [
    ['image.digest=latest', /SHA-256 digest/],
    ['publicUrl=http://gateway.example.invalid', /HTTPS origin/],
    ['kmsProvider=memory', /external KMS/],
  ]) {
    const result = render('--set-string', override);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, diagnostic);
  }
});

test('renders a strict Test Network profile for validation on a shared cluster', () => {
  const result = render('--set-string', 'networkMode=test-network');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /name: DEPLOYMENT_ENV\s+value: "staging"/);
  assert.match(result.stdout, /name: NETWORK_MODE\s+value: "test-network"/);
  assert.match(result.stdout, /name: SECURITY_MODE\s+value: "strict"/);
  const invalid = render('--set-string', 'networkMode=test');
  assert.notEqual(invalid.status, 0);
});

test('requires references to ICA and host decision configuration when Test Network admission is enabled', () => {
  const result = render('--set-string', 'networkMode=test-network', '--set', 'testNetworkAdmissionEnabled=true');
  assert.equal(result.status, 0, result.stderr);
  for (const key of ['HOST_ADMISSION_ICA_URL', 'HOST_ADMISSION_DECISION_URL']) {
    assert.match(result.stdout, new RegExp(
      `name: ${key}\\s+valueFrom:\\s+configMapKeyRef:\\s+name: "gateway-config"\\s+key: ${key}\\s+optional: false`,
    ));
  }
  for (const key of ['HOST_ADMISSION_ICA_TOKEN', 'HOST_ADMISSION_DECISION_TOKEN']) {
    assert.match(result.stdout, new RegExp(
      `name: ${key}\\s+valueFrom:\\s+secretKeyRef:\\s+name: "gateway-runtime"\\s+key: ${key}\\s+optional: false`,
    ));
  }
  assert.doesNotMatch(render('--set-string', 'networkMode=test-network').stdout, /name: HOST_ADMISSION_/);

  const production = render('--set', 'testNetworkAdmissionEnabled=true');
  assert.notEqual(production.status, 0);
  assert.match(production.stderr, /testNetworkAdmissionEnabled requires networkMode=test-network/);
});
