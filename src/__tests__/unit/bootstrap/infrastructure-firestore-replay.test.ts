// Flow contract: reuse the exact Firestore instance already selected for vault custody when explicitly enabling durable replay, keep its reservation collection separate, and refuse a Firestore profile for a different database provider. No cloud connection, credentials or persisted writes are exercised by this composition test.
import { jest } from '@jest/globals';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { ReplayProtectionStoreFirestore } from '../../../adapters/replay-protection-store-firestore';
const database={collection:jest.fn(),runTransaction:jest.fn()};
const getFirestore=jest.fn(()=>database);
jest.unstable_mockModule('firebase-admin/firestore',()=>({getFirestore}));
const {buildInfrastructure}=await import('../../../bootstrap/build-infrastructure');
const saved={...process.env};
afterEach(()=>{process.env={...saved};jest.clearAllMocks();});
const config={nodeEnv:'test',networkMode:'test',storageProvider:'mem',dbProvider:'firestore',kms:{provider:'memory'}} as any;
it('shares the existing database and chooses a dedicated replay collection without IO',async()=>{
 process.env.REPLAY_PROTECTION_PROVIDER='firestore';delete process.env.REPLAY_FIRESTORE_COLLECTION;
 const infrastructure=await buildInfrastructure({config,hostCollectionName:e.tenantId,initializeKms:false});
 try{
  expect(getFirestore).toHaveBeenCalledTimes(1);
  const replay=(infrastructure as any).infrastructureReplayProtectionStore;
  expect(replay).toBeInstanceOf(ReplayProtectionStoreFirestore);
  expect(replay.db).toBe((infrastructure.vaultRepository as any).db);
  expect(replay.collectionName).toBe(`${e.tenantId}_replay`);
  expect(database.runTransaction).not.toHaveBeenCalled();
 }finally{infrastructure.kmsService.destroy?.();}
});
it('rejects Firestore replay when the configured vault uses memory',async()=>{
 process.env.REPLAY_PROTECTION_PROVIDER='firestore';
 await expect(buildInfrastructure({config:{...config,dbProvider:'mem'},hostCollectionName:e.tenantId,initializeKms:false})).rejects.toThrow(/firestore|database/i);
 expect(getFirestore).not.toHaveBeenCalled();
});
it('rejects a replay collection that aliases the host vault',async()=>{
 process.env.REPLAY_PROTECTION_PROVIDER='firestore';process.env.REPLAY_FIRESTORE_COLLECTION=e.tenantId;
 await expect(buildInfrastructure({config,hostCollectionName:e.tenantId,initializeKms:false})).rejects.toThrow(/collection|separate|vault/i);
});
