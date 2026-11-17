// Flow contract: the immutable-image Fabric gate retains real consent, SMART
// and role-licence stages while requiring independent signed identity evidence;
// a Demo ICA, plaintext bearer or health-only run cannot prove strict operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, chmodSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
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

test('an absent prepared peer fails before any reset or automatic bootstrap', () => {
  const dir=mkdtempSync(resolve(tmpdir(),'sos-fabric-smoke-policy-'));
  try {
    const npmLog=resolve(dir,'npm-invoked');
    for(const [name,body] of [['docker','#!/bin/sh\nexit 0\n'],['npm',`#!/bin/sh\nprintf called > '${npmLog}'\nexit 99\n`]]){
      writeFileSync(resolve(dir,name),body);chmodSync(resolve(dir,name),0o700);
    }
    const result=spawnSync('bash',[resolve(root,'scripts/smoke-docker-local-network.sh')],{encoding:'utf8',env:{...process.env,PATH:`${dir}:${process.env.PATH}`,IMAGE_NAME:'synthetic-selected-image',STRICT_FABRIC_DRIVER_MODULE:'synthetic-driver',STRICT_FABRIC_DRIVER_CONFIG:'synthetic-config',LOCAL_REDIS_IMAGE:'synthetic-replay-image',LOCAL_FABRIC_EVIDENCE_DIR:dir,SKIP_FABRIC_PREP:'false'}});
    assert.equal(result.status,2,result.stderr);
    assert.equal(existsSync(npmLog),false,'smoke must not bootstrap or reset a Fabric stack');
    assert.match(result.stderr,/prepared.*peer|peer.*prepared/i);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('an explicit prepared peer selects only that owned container, preserving the historical default', () => {
  const dir=mkdtempSync(resolve(tmpdir(),'sos-fabric-peer-selection-'));
  try {
    const npmLog=resolve(dir,'npm-invoked');
    for(const [name,body] of [['docker','#!/bin/sh\nif [ "$1" = ps ]; then printf "%s\\n" "$SYNTHETIC_RUNNING_PEER"; fi\n'],['npm',`#!/bin/sh\nprintf '%s\\n' "$*" > '${npmLog}'\nexit 99\n`]]){
      writeFileSync(resolve(dir,name),body);chmodSync(resolve(dir,name),0o700);
    }
    for(const [selected,running,expected] of [['synthetic-owned-peer','synthetic-owned-peer',99],['synthetic-owned-peer','gdc-peer0-host1',2],['','gdc-peer0-host1',99]]){
      rmSync(npmLog,{force:true});
      const result=spawnSync('bash',[resolve(root,'scripts/smoke-docker-local-network.sh')],{encoding:'utf8',env:{...process.env,PATH:`${dir}:${process.env.PATH}`,IMAGE_NAME:'synthetic-selected-image',STRICT_FABRIC_DRIVER_MODULE:'synthetic-driver',STRICT_FABRIC_DRIVER_CONFIG:'synthetic-config',LOCAL_REDIS_IMAGE:'synthetic-replay-image',LOCAL_FABRIC_EVIDENCE_DIR:dir,FABRIC_PEER_CONTAINER:selected,SYNTHETIC_RUNNING_PEER:running}});
      assert.equal(result.status,expected,result.stderr);
      if(expected===99)assert.equal(readFileSync(npmLog,'utf8').trim(),'run prepare:local-fabric-env');
      else assert.equal(existsSync(npmLog),false,'an unrelated historical peer must not satisfy the selected peer');
    }
  } finally {rmSync(dir,{recursive:true,force:true});}
});
