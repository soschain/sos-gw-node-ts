// Flow contract: reserve opaque replay keys atomically in a dedicated durable collection, hash every namespaced identifier, retain reservations across adapter instances and expiry, and reject invalid inputs or storage failures without permitting access. The typed unit port is not emulator or cloud evidence.
import { jest } from '@jest/globals';
import { createHash } from 'node:crypto';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { ReplayProtectionStoreFirestore } from '../../../adapters/replay-protection-store-firestore';

function database() {
 const rows = new Map<string, any>(); const writes: any[] = []; let queue=Promise.resolve();
 const port={collection:jest.fn((name:string)=>({doc:(id:string)=>({path:`${name}/${id}`})})),
  runTransaction:jest.fn(async (work:any)=>{
   const result=queue.then(()=>work({get:async (ref:any)=>({exists:rows.has(ref.path),data:()=>rows.get(ref.path)}),set:(ref:any,value:any)=>{rows.set(ref.path,value);writes.push({path:ref.path,value});}}));
   queue=result.then(()=>undefined,()=>undefined);return result;
  })};
 return {port,rows,writes};
}
const options={collectionName:`${e.tenantId}_replay`,keyPrefix:'replay:jti'};
it('atomically admits one concurrent reservation and stores only the full namespaced digest and expiry',async()=>{
 const db=database();const store=new ReplayProtectionStoreFirestore(db.port as any,options);
 const results=await Promise.all(Array.from({length:12},()=>store.reserveIfNotExists(e.firstContactEmail,60)));
 expect(results.filter(Boolean)).toHaveLength(1);expect(db.writes).toHaveLength(1);
 expect(db.writes[0].path).toBe(`${options.collectionName}/${createHash('sha256').update(`${options.keyPrefix}:${e.firstContactEmail}`).digest('hex')}`);
 expect(Object.keys(db.writes[0].value)).toEqual(['expiresAt']);expect(db.writes[0].value.expiresAt).toBeInstanceOf(Date);
 expect(JSON.stringify(db.writes)).not.toContain(e.firstContactEmail);
});
it('retains a reservation for a recreated adapter and admits it only after expiry',async()=>{
 const db=database();const clock=jest.spyOn(Date,'now').mockReturnValue(1000000);
 try{
  expect(await new ReplayProtectionStoreFirestore(db.port as any,options).reserveIfNotExists(e.resourceUuid,2)).toBe(true);
  expect(await new ReplayProtectionStoreFirestore(db.port as any,options).reserveIfNotExists(e.resourceUuid,2)).toBe(false);
  clock.mockReturnValue(1002001);
  expect(await new ReplayProtectionStoreFirestore(db.port as any,options).reserveIfNotExists(e.resourceUuid,2)).toBe(true);
 }finally{clock.mockRestore();}
});
it.each([0,-1,NaN,Infinity,1.5,Number.MAX_SAFE_INTEGER])('rejects invalid TTL %s before storage',async ttl=>{
 const db=database();await expect(new ReplayProtectionStoreFirestore(db.port as any,options).reserveIfNotExists(e.resourceUuid,ttl)).rejects.toThrow(/ttl|expiry/i);expect(db.port.runTransaction).not.toHaveBeenCalled();
});
it.each(['','   ', 'x'.repeat(4097)])('rejects invalid replay keys before storage',async key=>{
 const db=database();await expect(new ReplayProtectionStoreFirestore(db.port as any,options).reserveIfNotExists(key,60)).rejects.toThrow(/key/i);expect(db.port.runTransaction).not.toHaveBeenCalled();
});
it('fails closed on storage errors and corrupt persisted expiry',async()=>{
 const db=database();const store=new ReplayProtectionStoreFirestore(db.port as any,options);
 db.port.runTransaction.mockRejectedValueOnce(new Error('storage unavailable') as never);
 await expect(store.reserveIfNotExists(e.resourceUuid,60)).rejects.toThrow(/storage/i);
 const id=createHash('sha256').update(`${options.keyPrefix}:${e.resourceUuid}`).digest('hex');db.rows.set(`${options.collectionName}/${id}`,{expiresAt:'invalid'});
 await expect(store.reserveIfNotExists(e.resourceUuid,60)).rejects.toThrow(/expiry/i);
});
it.each(['', '../other', 'group/doc', '__reserved__'])('rejects unsafe collection %s',collectionName=>{
 expect(()=>new ReplayProtectionStoreFirestore(database().port as any,{...options,collectionName})).toThrow(/collection/i);
});
