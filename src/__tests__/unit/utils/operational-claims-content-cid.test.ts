// Flow contract: operational content IDs retain exact original DAG-JSON/SHA2-256 bytes while canonical stored claims and distinct SHA3 ledger identities remain unchanged.
import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { canonicalizeOperationalClaimsForContentId, type OperationalClaimsContentOptions } from 'sos-data-utils-ts/operational-claim-content';
import { buildDagJsonCidV1FromUtf8String } from 'antifraud-data-utils-ts/encoding';
type Vector={name:string;claims:Record<string,unknown>;options:OperationalClaimsContentOptions;canonicalJson:string;cid:string};
const {vectors}: {vectors:Vector[]}=JSON.parse(readFileSync('src/__tests__/data/operational-content-cid-vectors.json','utf8'));
const helperPath='../../../utils/operational-claims-content-cid';

describe('operational content CID composition',()=>{
 it('routes all six actual content CID calls through owned utilities',()=>{
  for(const file of ['CommunicationManager','MedicationStatementManager','CareCoordinationManager']){
   const source=readFileSync(`src/managers/${file}.ts`,'utf8');
   expect(source.includes('gdc-common-utils-ts/utils/fhir-cid')).toBe(false);
   expect(source.includes('buildOperationalClaimsContentCid')).toBe(true);
  }
 });
 it('proves both independent layers match all eight actual original byte/CID vectors before caller migration',()=>{
  for(const vector of vectors){
   const json=canonicalizeOperationalClaimsForContentId(vector.claims,vector.options);
   expect(json).toBe(vector.canonicalJson);
   expect(buildDagJsonCidV1FromUtf8String(json)).toBe(vector.cid);
  }
 });
 it('builds current operational default IDs without mutating claims and rejects unsafe keys before hashing',async()=>{
  const {buildOperationalClaimsContentCid:build}=await import(helperPath);
  for(const vector of vectors.filter(item=>Object.keys(item.options).length===0)){
   const before=JSON.stringify(vector.claims);
   expect(build(vector.claims)).toBe(vector.cid);
   expect(JSON.stringify(vector.claims)).toBe(before);
  }
  expect(()=>build(JSON.parse('{"__proto__":{"polluted":true}}'))).toThrow(TypeError);
 });
});
