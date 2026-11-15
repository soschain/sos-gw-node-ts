// Flow contract: generic ResearchStudy standards use FHIR owners with complete catalogs, strict claims-only normalization and unchanged projection semantics.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as owner from 'fhir-data-utils-ts/research-study-r5';
const expected=JSON.parse(readFileSync('src/__tests__/data/research-study-standard-wire.json','utf8'));
const paths=['src/managers/ResearchStudyManager.ts','src/__tests__/unit/managers/ResearchStudyManager.test.ts'];
const names=new Set(['ResearchStudyFlatClaimCatalog','ResearchStudyR5PartyRoleCodes','ResearchStudyR5PartyRoleSystem','normalizeResearchStudyR5FlatClaimsResource','projectResearchStudyR5SearchClaims']);

test('all existing generic ResearchStudy imports use the FHIR owner',()=>{
 for(const path of paths){const sf=ts.createSourceFile(path,readFileSync(path,'utf8'),99,true);for(const s of sf.statements)if(ts.isImportDeclaration(s)&&s.importClause?.namedBindings&&ts.isNamedImports(s.importClause.namedBindings))for(const e of s.importClause.namedBindings.elements)if(names.has(e.propertyName?.text??e.name.text))assert.equal(s.moduleSpecifier.text,'fhir-data-utils-ts/research-study-r5',path)}
});
test('retains every catalog member, standard search definition, party role code and system',()=>{
 assert.equal(owner.ResearchStudyFlatClaimCatalog.all.length,31);
 assert.deepEqual(owner.ResearchStudyFlatClaimCatalog,expected.catalog);
 assert.deepEqual(owner.ResearchStudyR5PartyRoleCodes,expected.partyRoleCodes);
 assert.equal(owner.ResearchStudyR5PartyRoleSystem,expected.partyRoleSystem);
 assert.deepEqual(owner.ResearchStudyR5SearchParameterCatalog,expected.searchParameters);
});
test('retains all accepted and rejected normalization vectors without mutating claims',()=>{
 for(const vector of expected.normalized){const before=JSON.stringify(vector.input);if(vector.error)assert.throws(()=>owner.normalizeResearchStudyR5FlatClaimsResource(vector.input),{name:'TypeError',message:vector.error});else{const result=owner.normalizeResearchStudyR5FlatClaimsResource(vector.input);assert.deepEqual(result,vector.output);assert.equal(Object.isFrozen(result.meta.claims),true)}assert.equal(JSON.stringify(vector.input),before)}
});
test('preserves native-study projection and the official period-based date search expression',()=>{
 assert.deepEqual(owner.projectResearchStudyR5SearchClaims(expected.projection.input),expected.projection.output);
 assert.equal(owner.ResearchStudyR5SearchParameterCatalog.find(item=>item.code==='date').expression,'ResearchStudy.period');
});
