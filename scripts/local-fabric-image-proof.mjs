// Local QA orchestration only. The explicitly selected external SDK driver is
// an interoperability test consumer, never an application/runtime dependency.
import { execFileSync, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync, realpathSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createLocalFabricFixtureIssuer } from './local-fabric-fixture-issuer.mjs';
import { startLocalFabricFixtureStatusServer } from './local-fabric-fixture-status.mjs';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { toJwkThumbprintSha256Urn } from 'antifraud-data-utils-ts/jwk-thumbprints';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';

export function validateImageProofConfig(config) {
  for (const key of ['image', 'envFile', 'dockerNetwork', 'redisImage', 'driverModule', 'driverConfig']) {
    if (typeof config[key] !== 'string' || !config[key].trim()) throw new Error(`Local image gate requires explicit ${key}.`);
  }
}
export function validateRequiredStageReceipts(stages) {
  for (const stage of ['consentAccess', 'smartIps', 'roleLicense']) {
    if (stages?.[stage]?.status !== 'passed') throw new Error(`Missing complete ${stage} image proof.`);
  }
  if (stages.consentAccess.readbackVerified !== true || stages.roleLicense.readbackVerified !== true
    || stages.smartIps.allowed !== true || stages.smartIps.denied !== true) throw new Error('The image gate requires actual ledger readback and SMART allowed/denied results.');
}
/** The fixture controller is an explicit local reviewer, independently trusted from the ICA. */
export function validateFixtureReviewerTrust(trust, icaIssuer) {
  const keys = new Set(['issuer', 'actorDid', 'role', 'status', 'jwk', 'jwkThumbprints']);
  if (!trust || Object.keys(trust).some(key => !keys.has(key)) || typeof trust.issuer !== 'string' || !trust.issuer.startsWith('did:web:')
    || trust.issuer === icaIssuer || typeof trust.actorDid !== 'string' || !trust.actorDid.startsWith(`${trust.issuer}:employee:`)
    || trust.role !== HealthcareActorRoles.Controller || trust.status !== 'active'
    || trust.jwk?.kty !== 'AKP' || trust.jwk?.alg !== 'ML-DSA-65' || typeof trust.jwk?.kid !== 'string' || !trust.jwk.kid
    || typeof trust.jwk?.pub !== 'string' || !trust.jwk.pub
    || Object.keys(trust.jwk).some(key => !['kty', 'alg', 'kid', 'pub', 'use', 'key_ops'].includes(key))
    || (trust.jwk.use !== undefined && trust.jwk.use !== 'sig')
    || (trust.jwk.key_ops !== undefined && (!Array.isArray(trust.jwk.key_ops) || trust.jwk.key_ops.some(operation => operation !== 'verify')))) {
    throw new Error('The local reviewer requires separate, public-only ML-DSA-65 trust metadata.');
  }
}
const execute = (cmd, args, options = {}) => execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options });
function parseEnv(path) {
  const entries = new Map();
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line); if (match) entries.set(match[1], match[2]);
  }
  return entries;
}
async function freePort() {
  const listener = createServer(); await new Promise((yes, no) => { listener.once('error', no); listener.listen(0, '127.0.0.1', yes); });
  const port = listener.address().port; await new Promise((yes, no) => listener.close(error => error ? no(error) : yes())); return port;
}
async function waitReady(baseUrl) {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${baseUrl}/host/ping`, { signal: AbortSignal.timeout(1500) })).ok) return; } catch { /* bounded startup polling */ }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('The selected local image did not become ready.');
}

export async function runLocalFabricImageProof(config) {
  validateImageProofConfig(config);
  const driverModule = await import(pathToFileURL(realpathSync(config.driverModule)).href);
  if (typeof driverModule.prepareStrictSdkDriver !== 'function' || typeof driverModule.prepareNativeFixtureReview !== 'function') throw new Error('Select the reviewed external SDK interoperability driver.');
  const driverConfig = JSON.parse(readFileSync(config.driverConfig, 'utf8'));
  if (!driverConfig.ctx?.tenantId || !driverConfig.ctx?.jurisdiction || !driverConfig.ctx?.sector || !driverConfig.hostCtx?.jurisdiction) throw new Error('The driver must supply canonical local route contexts.');
  const evidenceRoot = process.env.LOCAL_FABRIC_EVIDENCE_DIR;
  if (!evidenceRoot) throw new Error('Select a private LOCAL_FABRIC_EVIDENCE_DIR for receipts and redacted operational review.');
  mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });
  const runDir = mkdtempSync(join(resolve(evidenceRoot), 'image-proof-'));
  const privateDir = mkdtempSync(join(runDir, 'custody-'));
  const runId = randomUUID(); const containers = [];
  let oracle; let prepared; let imageId; let fixtureReview;
  const receipt = { runId, scope: 'local-image-with-real-fabric', completed: false, cloudMutations: false };
  try {
    const image = JSON.parse(execute('docker', ['image', 'inspect', config.image]))[0];
    if (image.Os !== 'linux' || image.Architecture !== 'amd64') throw new Error('The release image must be linux/amd64.');
    imageId = image.Id; receipt.imageId = imageId;
    execute('docker', ['network', 'inspect', config.dockerNetwork]);
    const env = parseEnv(config.envFile);
    const channels = new Set(String(env.get('HLF_BOOTSTRAP_CHANNELS') || '').split(',').filter(Boolean));
    const identityChannel = env.get('HLF_IDENTITY_CHANNEL_NAME'); const dataChannel = env.get('HLF_DATA_CHANNEL_NAME');
    if (!identityChannel || !dataChannel || !channels.has(identityChannel) || !channels.has(dataChannel)) throw new Error('Select the actual prepared local Fabric channels.');
    const msp = env.get('LEDGER_FABRIC_MSP_ID'); const orgDomain = config.orgDomain || 'host1.example.com';
    if (!msp || !/^[A-Za-z0-9.-]+$/.test(orgDomain)) throw new Error('The prepared local Fabric identity is required.');
    const permitted = new Set(['org.hyperledger.fabric:GetMetadata', 'ReadRoleLicense', 'GetRoleLicenseHistory', 'ReadConsentAccess', 'GetConsentAccessHistory', 'readConsentAccess', 'getConsentAccessHistory', 'GetKey', 'GetProfessionalAssignment']);
    const evaluateFabric = async ({ channel, chaincode, functionName, args = [] }) => {
      if (!channels.has(channel) || !/^[a-z0-9-]+$/.test(chaincode) || !permitted.has(functionName)
        || !Array.isArray(args) || !args.every(value => typeof value === 'string' && value.length <= 4096)) throw new Error('Read-only local Fabric query is outside the reviewed contract.');
      const raw = execute('docker', ['exec', config.fabricToolsContainer || 'gdc-fabric-tools', 'env',
        `CORE_PEER_LOCALMSPID=${msp}`, `CORE_PEER_MSPCONFIGPATH=/workspace/organizations/peerOrganizations/${orgDomain}/users/Admin@${orgDomain}/msp`,
        'CORE_PEER_ADDRESS=peer0-host1:7051', 'CORE_PEER_TLS_ENABLED=true',
        `CORE_PEER_TLS_ROOTCERT_FILE=/workspace/organizations/peerOrganizations/${orgDomain}/peers/peer0.${orgDomain}/tls/ca.crt`,
        'peer', 'chaincode', 'query', '-C', channel, '-n', chaincode, '-c', JSON.stringify({ Args: [functionName, ...args] })]);
      return JSON.parse(raw);
    };
    receipt.contractMetadata = [];
    for (const [channel, chaincode, required] of [
      [identityChannel, 'rolelicense-sc', ['EnsureRoleLicense', 'UpsertSectorPolicy', 'ReadRoleLicense']],
      [identityChannel, 'employee-sc', ['UpsertProfessionalAssignment']],
      [identityChannel, 'cryptographickey-sc', ['EnsureKey', 'GetKey']],
      [dataChannel, 'consentaccess-sc', ['UpsertConsentAccess', 'ReadConsentAccess']],
    ]) {
      const metadata = await evaluateFabric({ channel, chaincode, functionName: 'org.hyperledger.fabric:GetMetadata' });
      const methods = Object.values(metadata.contracts || {}).flatMap(contract => (contract.transactions || []).map(value => value.name));
      if (!required.every(name => methods.includes(name))) throw new Error(`The actual local ${chaincode} definition lacks required methods.`);
      receipt.contractMetadata.push({ channel, chaincode, requiredMethodsConfirmed: required });
    }
    const tlsKey = join(privateDir, 'tls-key.pem'); const tlsCert = join(privateDir, 'tls-cert.pem');
    execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1', '-keyout', tlsKey, '-out', tlsCert], { stdio: 'ignore' });
    const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', deferIssuance: true });
    const hostPort = await freePort(); const baseUrl = `http://127.0.0.1:${hostPort}`; const audience = driverConfig.oidcAudience || 'local-image-gateway';
    fixtureReview = await driverModule.prepareNativeFixtureReview({ ...driverConfig, baseUrl, networkMode: 'test-network', securityMode: 'strict', clearingHouseMode: 'local', replayBackend: 'redis' });
    validateFixtureReviewerTrust(fixtureReview.publicTrust, issuer.issuerDid);
    const statusIssuer = { issuerDid: issuer.issuerDid, jwks: issuer.jwks,
      get credentials() { return [...issuer.credentials, ...fixtureReview.credentials]; },
      status(id) { const reviewed = fixtureReview.status(id); return reviewed === 'unknown' ? issuer.status(id) : reviewed; } };
    oracle = await startLocalFabricFixtureStatusServer({ profile: 'local-fabric', issuer: statusIssuer, key: readFileSync(tlsKey), cert: readFileSync(tlsCert), advertisedHostname: 'host.docker.internal' });
    const startContainer = args => {
      const name = args[args.indexOf('--name') + 1]; containers.push(name);
      return execute('docker', ['run', '-d', '--label', `soschain.local-image-proof=${runId}`, ...args]).trim();
    };
    const redisName = `sos-proof-replay-${runId}`;
    startContainer(['--name', redisName, '--network', config.dockerNetwork, config.redisImage, 'redis-server', '--appendonly', 'yes']);
    let redisReady = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { if (execute('docker', ['exec', redisName, 'redis-cli', 'ping']).trim() === 'PONG') { redisReady = true; break; } } catch { /* owned startup only */ }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (!redisReady) throw new Error('The owned durable replay service did not become ready.');
    const overrides = { NODE_ENV: 'test', DEPLOYMENT_ENV: 'dev', NETWORK_MODE: 'test-network', SECURITY_MODE: 'strict',
      DB_PROVIDER: 'mem', STORAGE_PROVIDER: 'mem', KMS_PROVIDER: 'memory', QUEUE_PROVIDER: 'mem', CLEARING_HOUSE_MODE: 'local',
      SMART_TOKEN_LEGACY: 'true', LEGACY_SIGN_ALG: 'ES384',
      REPLAY_PROTECTION_PROVIDER: 'redis', REDIS_URL: `redis://${redisName}:6379`,
      AUTH_TOKEN_VERIFIER: 'trusted-oidc', OIDC_TRUSTED_PROVIDERS_JSON: JSON.stringify([{ iss: oracle.advertisedOrigin, aud: audience }]),
      CREDENTIAL_TRUSTED_ISSUERS_JSON: JSON.stringify({ [issuer.issuerDid]: { status: 'active', jwks: issuer.jwks, statusEndpointTemplate: oracle.statusEndpointTemplate, statusRequestType: oracle.statusRequestType }, [fixtureReview.publicTrust.issuer]: { status: 'active', jwks: { keys: [fixtureReview.publicTrust.jwk] }, statusEndpointTemplate: oracle.statusEndpointTemplate, statusRequestType: oracle.statusRequestType } }),
      HOST_ORGANIZATION_AUTHORIZATION_ISSUERS: fixtureReview.publicTrust.issuer,
      HOST_ORGANIZATION_AUTHORIZATION_SIGNERS: JSON.stringify([{ issuer: fixtureReview.publicTrust.issuer, actorDid: fixtureReview.publicTrust.actorDid, role: fixtureReview.publicTrust.role, status: fixtureReview.publicTrust.status, jwkThumbprints: [toJwkThumbprintSha256Urn(fixtureReview.publicTrust.jwk)] }]),
      CLEARING_HOUSE_REQUESTERS_JSON: '{}', GXDCH_TENANTS_JSON: '{}', DEV_SEED: 'true',
      ICA_MODE: 'external', ICA_URL_EXTERNAL: oracle.advertisedOrigin, ICA_DID_WEB: issuer.issuerDid, ICA_JURISDICTION: driverConfig.hostCtx.jurisdiction,
      JSON_LEGACY: 'false', FHIR_LEGACY: 'false', DIDCOMM_PLAIN: 'false', DEMO_ALLOW_INSECURE_BEARER: 'false',
      HOST_PUBLIC_URL: baseUrl, HOST_EXTERNAL_DOMAIN: `127.0.0.1:${hostPort}`, HOST_INTERNAL_PORT: '3000', PORT: '3000',
      HOST_LEGAL_NAME: e.organizationLegalName, HOST_ID_TYPE: e.organizationIdentifierType, HOST_ID_VALUE: e.organizationBusinessNumber,
      HOST_ADMIN_EMAIL: e.firstContactEmail, HOST_ADMIN_UID: e.resourceUuid, HOST_ADMIN_ROLE: HealthcareActorRoles.Controller, HOST_JURISDICTION: driverConfig.hostCtx.jurisdiction,
      NODE_EXTRA_CA_CERTS: '/run/local-fabric-fixture/tls-cert.pem',
    };
    for (const [key, value] of Object.entries(overrides)) env.set(key, value);
    const runtimeEnv = join(privateDir, 'runtime.env'); writeFileSync(runtimeEnv, [...env].map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600 });
    const gateway = startContainer(['--name', `sos-image-proof-${runId}`, '--network', config.dockerNetwork,
      '--env-file', runtimeEnv, '-p', `127.0.0.1:${hostPort}:3000`, '-v', `${tlsCert}:/run/local-fabric-fixture/tls-cert.pem:ro`, imageId]);
    await waitReady(baseUrl);
    prepared = await driverModule.prepareStrictSdkDriver({ ...driverConfig, baseUrl, fixtureReview,
      hostDidDocumentUrl: `${baseUrl}/host/cds-${driverConfig.hostCtx.jurisdiction}/v1/test-network/.well-known/did.json`,
      tenantDidDocumentUrl: `${baseUrl}/${encodeURIComponent(driverConfig.ctx.tenantId)}/cds-${encodeURIComponent(driverConfig.ctx.jurisdiction)}/v1/${encodeURIComponent(driverConfig.ctx.sector)}/.well-known/did.json`,
      identityChannel, dataChannel, gatewayBuildRoot: driverConfig.gatewayBuildRoot || resolve(fileURLToPath(new URL('../build', import.meta.url))),
      hostCtx: { ...driverConfig.hostCtx, hostNetwork: 'test-network' }, networkMode: 'test-network', securityMode: 'strict', clearingHouseMode: 'local', replayBackend: 'redis' });
    await issuer.issueOrganizationSet({ controllerJwk: prepared.controllerJwk, organizationDid: prepared.organizationDid });
    if (typeof prepared.runRequiredStages !== 'function') throw new Error('The external SDK driver has not completed the required Fabric image stages.');
    const mintOidc = options => issuer.mintOidc({ ...options, issuer: oracle.advertisedOrigin, audience });
    const idToken = await mintOidc({ subject: 'fixture-controller-account', email: driverConfig.controllerEmail || e.firstContactEmail });
    const results = await prepared.runRequiredStages({ issuer, idToken, mintOidc, service: { ...driverConfig.service, url: baseUrl }, audience: prepared.hostDidDocument.id,
      evaluateFabric, readRoleLicense: id => evaluateFabric({ channel: identityChannel, chaincode: 'rolelicense-sc', functionName: 'ReadRoleLicense', args: [id] }) });
    validateRequiredStageReceipts(results.stages);
    receipt.results = results;
    receipt.effectiveImageId = JSON.parse(execute('docker', ['inspect', gateway]))[0].Image;
    if (receipt.effectiveImageId !== imageId) throw new Error('The tested container image differs from the selected immutable image.');
    receipt.completed = true;
    return receipt;
  } finally {
    try { if (prepared?.destroy) await prepared.destroy(); } catch { receipt.fixtureCleanupFailure = true; }
    for (const id of containers.reverse()) {
      try {
        const info = JSON.parse(execute('docker', ['inspect', id]))[0];
        if (info.Config?.Labels?.['soschain.local-image-proof'] !== runId) throw new Error('Owned container label changed.');
        try {
          const logs = spawnSync('docker', ['logs', id], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
          writeFileSync(join(runDir, `${info.Name.replaceAll('/', '')}.log`), (logs.stdout || '') + (logs.stderr || ''), { mode: 0o600 });
        } catch { receipt.logCaptureFailure = true; }
        execute('docker', ['rm', '-f', '-v', id]);
      } catch { receipt.cleanupFailure = true; }
    }
    try { if (oracle) await oracle.close(); } catch { receipt.fixtureCleanupFailure = true; }
    rmSync(privateDir, { recursive: true, force: true });
    if (receipt.cleanupFailure || receipt.fixtureCleanupFailure) receipt.completed = false;
    writeFileSync(join(runDir, 'receipt.json'), JSON.stringify(receipt, null, 2), { mode: 0o600 });
    if (receipt.cleanupFailure || receipt.fixtureCleanupFailure) throw new Error('The local image gate requires owned-resource cleanup review.');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runLocalFabricImageProof({ image: process.env.IMAGE_NAME || '', envFile: process.env.ENV_FILE || '',
    dockerNetwork: process.env.DOCKER_NETWORK || '', redisImage: process.env.LOCAL_REDIS_IMAGE || '',
    driverModule: process.env.STRICT_FABRIC_DRIVER_MODULE || '', driverConfig: process.env.STRICT_FABRIC_DRIVER_CONFIG || '' })
    .then(() => console.log('Local image ConsentAccess/SMART IPS/role-licence proof completed.'))
    .catch(error => { console.error(`Local image gate failed: ${error.message}`); process.exitCode = 1; });
}
