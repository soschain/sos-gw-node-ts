// Flow contract: keep the real local Professional UI -> BFF -> SDK -> SOS gateway gate explicit and sequential; launcher tests and source checks do not prove the browser journey.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url))
const packageJson = JSON.parse(readFileSync(`${repositoryRoot}/package.json`, 'utf8'))
const secureE2eScript = readFileSync(`${repositoryRoot}/scripts/run-secure-e2e-google-user.sh`, 'utf8')
const consentAccessDeployScript = readFileSync(
  `${repositoryRoot}/chaincode/scripts/consentaccess-local-devnet.sh`,
  'utf8',
)
const localFabricBootstrapScript = readFileSync(
  `${repositoryRoot}/scripts/bootstrap-local-fabric-stack.mjs`,
  'utf8',
)

test('runs the complete E2E suite in one Jest worker', () => {
  assert.match(packageJson.scripts['test:e2e'], /(?:^|\s)--runInBand(?:\s|$)/)
})

test('delegates the complete local UI gate to the explicitly selected Professional runner', () => {
  assert.match(secureE2eScript, /PORTAL_PROJECT_ROOT/)
  assert.match(secureE2eScript, /VET_GW_PROJECT_ROOT/)
  assert.match(secureE2eScript, /test:e2e:local/)
  assert.match(secureE2eScript, /--workers=1/)
  assert.doesNotMatch(secureE2eScript, /GDC_SDK_NODE_ROOT|gdc-sdk-node-ts|bootstrap_current_ica_tenant|local-close\.sh|pkill/)
})

test('installs exact consentaccess dependencies before local Fabric tests', () => {
  const installIndex = consentAccessDeployScript.indexOf('(cd "${CHAINCODE_DIR}" && npm ci)')
  const testIndex = consentAccessDeployScript.indexOf('(cd "${CHAINCODE_DIR}" && npm test)')

  assert.ok(installIndex >= 0, 'consentaccess deploy must run npm ci')
  assert.ok(testIndex > installIndex, 'npm ci must precede consentaccess tests')
})

test('deploys artifact-sc on both local data and research channels', () => {
  assert.match(localFabricBootstrapScript, /fabric-deploy-data-artifact-chaincode/)
  assert.match(localFabricBootstrapScript, /CHANNEL_NAME: config\.dataChannel/)
  assert.match(localFabricBootstrapScript, /fabric-deploy-research-artifact-chaincode/)
  assert.match(localFabricBootstrapScript, /CHANNEL_NAME: config\.researchChannel/)
})

// The npm fixture proves launcher argument, process and exit-code contracts only.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
function launcherFixture(run) {
 const directory=mkdtempSync(path.join(tmpdir(),'sos-ui-launcher-'))
 try{
  const portal=path.join(directory,'portal');const commands=path.join(directory,'bin');mkdirSync(portal);mkdirSync(commands);mkdirSync(path.join(portal,'scripts'))
  writeFileSync(path.join(portal,'package.json'),JSON.stringify({name:'vet-professional-next',scripts:{'test:e2e:local':'node scripts/run-local-e2e.mjs'}}))
  writeFileSync(path.join(portal,'scripts/run-local-e2e.mjs'),'// Fixture only; never executes a browser journey.\n')
  writeFileSync(path.join(commands,'npm'),'#!/bin/sh\nprintf "%s\\n" "$PWD" "$VET_GW_PROJECT_ROOT" "$@" > "$LAUNCHER_CAPTURE"\nprintf "launcher-child-output\\n"\nexit "${LAUNCHER_CHILD_EXIT:-0}"\n',{mode:0o700})
  const capture=path.join(directory,'capture.txt');const env={...process.env,PATH:commands+path.delimiter+process.env.PATH,PORTAL_PROJECT_ROOT:portal,VET_GW_PROJECT_ROOT:repositoryRoot,LAUNCHER_CAPTURE:capture}
  return run({portal,capture,commands,env,launch:(overrides={},args=[])=>spawnSync('bash',[path.join(repositoryRoot,'scripts/run-secure-e2e-google-user.sh'),...args],{cwd:repositoryRoot,env:{...env,...overrides},encoding:'utf8',timeout:10000})})
 }finally{rmSync(directory,{recursive:true,force:true})}
}
test('launches the selected external runner against this exact SOS checkout with one worker',()=>launcherFixture(({portal,capture,launch})=>{
 const result=launch({LAUNCHER_CHILD_EXIT:'0'});assert.equal(result.status,0,result.stderr)
 assert.deepEqual(readFileSync(capture,'utf8').trim().split('\n'),[realpathSync(portal),realpathSync(repositoryRoot),'run','test:e2e:local','--','--workers=1'])
 assert.match(result.stdout,/launcher-child-output/)
}))
test('propagates the external runner failure without turning it into a successful gate',()=>launcherFixture(({launch})=>{
 const result=launch({LAUNCHER_CHILD_EXIT:'27'});assert.equal(result.status,27);assert.match(result.stdout,/launcher-child-output/)
}))
test('requires an explicit portal checkout before invoking npm',()=>launcherFixture(({capture,launch})=>{
 const result=launch({PORTAL_PROJECT_ROOT:''});assert.equal(result.status,2);assert.match(result.stderr,/PORTAL_PROJECT_ROOT/);assert.equal(existsSync(capture),false)
}))
test('rejects a different gateway checkout instead of substituting another branch',()=>launcherFixture(({portal,capture,launch})=>{
 const result=launch({VET_GW_PROJECT_ROOT:portal});assert.equal(result.status,2);assert.match(result.stderr,/checkout|gateway|VET_GW_PROJECT_ROOT/i);assert.equal(existsSync(capture),false)
}))

test('refuses an older Node runtime before invoking the runner',()=>launcherFixture(({commands,capture,launch})=>{
 writeFileSync(path.join(commands,'node'),'#!/bin/sh\nif [ "$1" = "--version" ]; then printf "v24.0.0\\n"; exit 0; fi\nexec "$ACTUAL_NODE_BINARY" "$@"\n',{mode:0o700})
 const result=launch({ACTUAL_NODE_BINARY:process.execPath});assert.equal(result.status,2);assert.match(result.stderr,/26\.13\.0/);assert.equal(existsSync(capture),false)
}))
test('rejects filter or worker arguments rather than weakening the complete gate',()=>launcherFixture(({capture,launch})=>{
 const result=launch({},['--workers=8']);assert.equal(result.status,2);assert.match(result.stderr,/complete|filter/i);assert.equal(existsSync(capture),false)
}))
