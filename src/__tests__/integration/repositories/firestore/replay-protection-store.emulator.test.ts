// Flow contract: (1) connect only to an explicitly leased loopback Firestore emulator and synthetic project; (2) atomically admit exactly one concurrent reservation; (3) recreate the client and adapter and reject the already-used key; (4) admit an expired key from durable state; (5) delete only this suite's fresh replay collection. No live project, vault, ICA record, JWT or personal identifier is accessed or persisted.
import { jest } from '@jest/globals';
import { initializeApp, deleteApp, type App } from 'firebase-admin/app';
import { getFirestore, type Firestore } from 'firebase-admin/firestore';
import { createHash, randomBytes } from 'node:crypto';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { ReplayProtectionStoreFirestore } from '../../../../adapters/replay-protection-store-firestore';

jest.setTimeout(30000);
const host=process.env.FIRESTORE_EMULATOR_HOST;
const projectId=process.env.REPLAY_EMULATOR_PROJECT_ID;
if(process.env.NODE_ENV!=='test'||!host||!/^(?:127\.0\.0\.1|localhost|\[::1\]):[1-9][0-9]{1,4}$/.test(host))throw new Error('This suite requires an explicitly leased loopback Firestore emulator in NODE_ENV=test.');
if(!projectId||!/^demo-[a-z0-9][a-z0-9-]{3,55}$/.test(projectId))throw new Error('This suite requires an explicit synthetic demo emulator project.');
const collectionName=`replay_emulator_${randomBytes(12).toString('hex')}`;
const applications:App[]=[];let database:Firestore;
function client(){const app=initializeApp({projectId},`replay-${randomBytes(8).toString('hex')}`);applications.push(app);return getFirestore(app);}
beforeAll(()=>{database=client();});
afterAll(async()=>{if(database)await database.recursiveDelete(database.collection(collectionName));for(const app of applications)await deleteApp(app);});
const options={collectionName,keyPrefix:'replay:jti'};
const docId=(key:string)=>createHash('sha256').update(`${options.keyPrefix}:${key}`).digest('hex');
it('atomically admits exactly one concurrent reservation in the emulator',async()=>{
 const key=`${e.resourceUuid}:concurrent`;const store=new ReplayProtectionStoreFirestore(database,options);
 const results=await Promise.all(Array.from({length:8},()=>store.reserveIfNotExists(key,60)));
 expect(results.filter(Boolean)).toHaveLength(1);
 const stored=await database.collection(collectionName).doc(docId(key)).get();
 expect(stored.exists).toBe(true);expect(Object.keys(stored.data()!)).toEqual(['expiresAt']);
 expect(stored.data()!.expiresAt.toDate()).toBeInstanceOf(Date);
 expect(JSON.stringify(stored.data())).not.toContain(key);
});
it('retains the reservation after recreating the Firestore client and adapter',async()=>{
 const key=`${e.resourceUuid}:restart`;
 expect(await new ReplayProtectionStoreFirestore(database,options).reserveIfNotExists(key,60)).toBe(true);
 expect(await new ReplayProtectionStoreFirestore(client(),options).reserveIfNotExists(key,60)).toBe(false);
});
it('replaces an expired reservation after authoritative persisted-state read',async()=>{
 const key=`${e.resourceUuid}:expired`;
 await database.collection(collectionName).doc(docId(key)).set({expiresAt:new Date(Date.now()-1000)});
 const store=new ReplayProtectionStoreFirestore(database,options);
 expect(await store.reserveIfNotExists(key,60)).toBe(true);
 const stored=await database.collection(collectionName).doc(docId(key)).get();
 expect(stored.data()!.expiresAt.toMillis()).toBeGreaterThan(Date.now());
 expect(await store.reserveIfNotExists(key,60)).toBe(false);
});
