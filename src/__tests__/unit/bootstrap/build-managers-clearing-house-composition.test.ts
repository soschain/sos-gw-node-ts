// Flow contract: assemble the existing SOS manager graph with separate native enrolled and ICA activation verifiers, current consent checks, real configured ledger providers and one shared replay store; remote receipt mode must not turn the tenant verification endpoint into a remote loop. These are composition checks, not portal/Fabric E2E claims.
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { jest } from '@jest/globals';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { StorageMemAdapter } from '../../../database/storage/mem.storage.adapter';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';
import { KmsService } from '../../../services/KmsService';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { ReplayProtectionStoreMem, ReplayProtectionStoreNoop } from '../../../adapters/replay-protection-store';

import { EU_ORGANIZATION_IDENTITY_CHANNEL } from '../../../blockchain/fabric/v3/ledger-channel-name';
import { ReplayProtectionStoreFirestore } from '../../../adapters/replay-protection-store-firestore';
import { CredentialLedgerAdapterMem } from '../../../adapters/CredentialLedgerAdapterMem';
import { LedgerPresentationVerifier } from '../../../services/LedgerPresentationVerifier';
import { IcaActivationVerifier } from '../../../services/IcaActivationVerifier';

// This unit assembles provider objects; it must never establish a Fabric connection.
// Native cryptography, registry managers and the actual credential adapter remain real.
const unexpectedFabric = () => { throw new Error('Unexpected Fabric transport call in composition unit.'); };
jest.unstable_mockModule('@hyperledger/fabric-gateway', () => ({
  connect: unexpectedFabric,
  signers: { newPrivateKeySigner: unexpectedFabric },
  checkpointers: { inMemory: unexpectedFabric, file: unexpectedFabric },
}));
const { buildManagers } = await import('../../../bootstrap/build-managers');
const { CredentialLedgerAdapterFabric } = await import('../../../adapters/CredentialLedgerAdapterFabric');

const saved = { ...process.env };
const created: Array<{ kms: KmsService; vault: VaultMemRepository }> = [];
beforeEach(() => {
  process.env.NODE_ENV = 'test'; process.env.NETWORK_MODE = 'test'; process.env.SECURITY_MODE = 'strict';
  process.env.DEPLOYMENT_ENV = 'local'; process.env.AUTH_TOKEN_VERIFIER = 'firebase';
  process.env.REPLAY_PROTECTION_PROVIDER = 'mem'; process.env.LEDGER_PROVIDER_DEFAULT = 'mem';
  process.env.LEDGER_PROVIDER_MAP = 'test=mem,test-network=multi,network=fabric';
  process.env.SUBJECT_IDENTIFIER_LEDGER_ENABLED = 'false';
  process.env.LEDGER_ORGANIZATION_IDENTITY_CHANNEL_DEFAULT = EU_ORGANIZATION_IDENTITY_CHANNEL;
  delete process.env.REDIS_URL;
});
afterEach(() => { for (const item of created.splice(0)) { item.kms.destroy(); item.vault.clear(); } process.env = { ...saved }; jest.restoreAllMocks(); });
function registry(networkMode: 'test' | 'test-network' = 'test', replay?: ReplayProtectionStoreMem | ReplayProtectionStoreFirestore) {
  process.env.NETWORK_MODE = networkMode;
  const vault = new VaultMemRepository(); let kms: KmsService;
  const tenants = new TenantsCacheManager(vault, () => kms, e.tenantId);
  const crypto = new CryptographyService(new AdapterCryptoSdkNode());
  kms = new KmsService(crypto, tenants); created.push({ kms, vault });
  return buildManagers({ config: { networkMode, nodeEnv: 'test', securityMode: process.env.SECURITY_MODE, namespace: 'test', apiBaseUrl: e.httpsBaseUrl, hostExternalDomain: e.domain, host: { adminUid: e.resourceUuid, jurisdiction: e.countryIso2 }, sectorsAllowed: [] } as any,
    vaultRepository: vault, kmsService: kms, tenantManager: tenants as any, hostCollectionName: e.tenantId,
    storageAdapter: new StorageMemAdapter(), logger: { debug() {}, info() {}, warn() {}, error() {}, fatal() {} }, cryptographyService: crypto,
    ...(replay ? { replayProtectionStore: replay } : {}) } as any) as any;
}

it('returns the native verifier separately and gives hosting the ICA first-controller verifier', () => {
  const result = registry();
  expect(result.localClearingHouseVerifier).toBeInstanceOf(LedgerPresentationVerifier);
  expect(result.hostingManager.clearingHouseService).toBeInstanceOf(IcaActivationVerifier);
  expect(result.localClearingHouseVerifier.options.ledger).toBeInstanceOf(CredentialLedgerAdapterMem);
  for (const manager of ['taskManager', 'subjectIdentityManager', 'appointmentManager', 'researchStudyManager', 'groupManager']) expect(result[manager]).toBeDefined();
});
it('selects the actual Fabric verifier adapter for a multi route, without a memory-first fallback', () => {
  process.env.REPLAY_PROTECTION_PROVIDER = 'redis'; process.env.REDIS_URL = `redis://${e.domain}:6379`;
  const result = registry('test-network');
  expect(result.localClearingHouseVerifier.options.ledger).toBeInstanceOf(CredentialLedgerAdapterFabric);
  expect(result.localClearingHouseVerifier.options.ledgerKind).toBe('fabric');
});
it('keeps the native endpoint local even when outgoing Clearing House mode is remote', async () => {
  process.env.CLEARING_HOUSE_MODE = 'remote';
  const fetchSpy = jest.spyOn(globalThis, 'fetch');
  const result = registry();
  await expect(result.localClearingHouseVerifier.verifyVpToken({ tenantDid: e.didWeb, vpToken: 'not-a-jwt', acrValues: [] })).rejects.toThrow();
  expect(fetchSpy).not.toHaveBeenCalled();
});
it('shares the injected real replay store with SMART and preserves its duplicate rejection', async () => {
  const replay = new ReplayProtectionStoreMem(); const result = registry('test', replay);
  expect(result.replayProtectionStore).toBe(replay);
  expect(result.openIdAuthManager.assertionReplay).toBe(replay);
  expect(await replay.reserveIfNotExists(e.resourceUuid, 60)).toBe(true);
  expect(await replay.reserveIfNotExists(e.resourceUuid, 60)).toBe(false);
});
it('binds native authorization to the current manager consent evaluator', async () => {
  const result = registry();
  const evaluate = jest.spyOn(result.openIdAuthManager, 'verifyCurrentConsentContext');
  const request = { tenantDid: e.didWeb, vpToken: e.resourceUuid, acrValues: [] };
  await expect(result.localClearingHouseVerifier.options.authorize(request)).rejects.toThrow(/authorization|issuer|scope/i);
  expect(evaluate).toHaveBeenCalledWith(request, undefined);
});
it('requires each active ICA issuer to configure its exact status request protocol identifier', async () => {
  const result = registry();
  process.env.CREDENTIAL_TRUSTED_ISSUERS_JSON = JSON.stringify({ [e.didWeb]: { status: 'active', jwks: { keys: [] }, statusEndpointTemplate: `${e.httpsBaseUrl}/credentials/{credentialType}/_status` } });
  await expect(result.hostingManager.clearingHouseService.options.resolveIssuer(e.didWeb)).rejects.toThrow(/status|configured|issuer/i);
});


it.each(['mem', 'none', '', 'unknown'])('rejects non-durable replay provider %s for an enrolled network', provider => {
  process.env.REPLAY_PROTECTION_PROVIDER = provider;
  expect(() => registry('test-network')).toThrow(/replay|redis|durable/i);
});
it('requires an explicit Redis URL for a durable replay provider', () => {
  process.env.REPLAY_PROTECTION_PROVIDER = 'redis'; delete process.env.REDIS_URL;
  expect(() => registry('test-network')).toThrow(/redis|replay|URL/i);
});
it('retains the explicit local demo no-op profile without selecting it for strict tests', () => {
  process.env.SECURITY_MODE = 'demo'; process.env.REPLAY_PROTECTION_PROVIDER = 'none';
  expect(registry().replayProtectionStore).toBeInstanceOf(ReplayProtectionStoreNoop);
});

it('accepts only the infrastructure-owned Firestore adapter for an explicitly durable Firestore profile', () => {
  process.env.REPLAY_PROTECTION_PROVIDER='firestore';
  const firestore = new ReplayProtectionStoreFirestore({collection:()=>{throw new Error('Unexpected unit IO');},runTransaction:()=>{throw new Error('Unexpected unit IO');}} as any, {collectionName:`${e.tenantId}_replay`});
  expect(registry('test-network',firestore).replayProtectionStore).toBe(firestore);
});
it('rejects a Firestore profile without the infrastructure-owned adapter', () => {
  process.env.REPLAY_PROTECTION_PROVIDER='firestore';
  expect(()=>registry('test-network')).toThrow(/firestore|replay/i);
  expect(()=>registry('test-network',new ReplayProtectionStoreMem())).toThrow(/firestore|replay/i);
});
