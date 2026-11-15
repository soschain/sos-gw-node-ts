// Flow contract: derived clinical search indexes retain established CSV/audit/uniqueness semantics without modifying signed claims or new FHIR fields.
import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { CompositionClaim } from 'fhir-data-utils-ts';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
const helperPath='../../../utils/clinical-document-search-attributes';
const load=()=>import(helperPath);
const first=`${SAFE.didWeb}:one`,second=`${SAFE.didWeb}:two`;

describe('clinical document derived search attributes',()=>{
 it('uses the owning projection at all four actual manager call sites',()=>{
  for(const path of ['src/managers/CommunicationManager.ts','src/managers/MedicationStatementManager.ts']){
   const source=readFileSync(path,'utf8');
   expect(source.includes('gdc-common-utils-ts/utils/confidential-document-provenance')).toBe(false);
   expect(source.includes('buildClinicalDocumentSearchAttributes')).toBe(true);
  }
 });
 it('preserves audit order, qualified author aliases and qualified Status passthrough',async()=>{
  const {buildClinicalDocumentSearchAttributes:build}=await load();
  const author=`org.hl7.fhir.r4.${CompositionClaim.Author}`,status=`org.hl7.fhir.r4.${CompositionClaim.Status}`;
  expect(build({sector:SAFE.sector,audit:{creatorDid:first,submitterDid:second,signingKeyId:`${first}#key`},claims:{[author]:`${first}, ${second}`,[status]:'final'}})).toEqual([
   {name:'sector',value:SAFE.sector},{name:'audit.creatorDid',value:first},{name:'audit.submitterDid',value:second},{name:'audit.signingKeyId',value:`${first}#key`},
   {name:CompositionClaim.Author,value:first},{name:CompositionClaim.Author,value:second},{name:CompositionClaim.Author,value:`${first}, ${second}`},{name:author,value:`${first}, ${second}`},{name:status,value:'final'},
  ]);
 });
 it('splits each established CSV claim and retains its whole-value alias once',async()=>{
  const {buildClinicalDocumentSearchAttributes:build}=await load();
  for(const key of [CompositionClaim.Author,CompositionClaim.Attester,CompositionClaim.AttesterMode,CompositionClaim.AttesterTime,CompositionClaim.Section,CompositionClaim.Entry]){
   expect(build({claims:{[key]:`${first},${second},${first}`}})).toEqual([{name:key,value:first},{name:key,value:second},{name:key,value:`${first},${second},${first}`}]);
  }
 });
 it('keeps arbitrary commas intact, marks only resource identifiers unique and never mutates input',async()=>{
  const {buildClinicalDocumentSearchAttributes:build}=await load();
  const claims=Object.freeze({'@context':'org.hl7.fhir.r4','@type':'Composition',[CompositionClaim.Title]:'one, two',[CompositionClaim.Identifier]:SAFE.resourceUuid,'MedicationStatement.identifier.value':SAFE.resourceUuid,ignored:[first,second],empty:null});
  const before=JSON.stringify(claims);
  expect(build({claims})).toEqual([{name:CompositionClaim.Title,value:'one, two'},{name:CompositionClaim.Identifier,value:SAFE.resourceUuid},{name:'MedicationStatement.identifier.value',value:SAFE.resourceUuid,unique:true}]);
  expect(JSON.stringify(claims)).toBe(before);
 });
});
