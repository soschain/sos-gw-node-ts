// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// The gateway selects explicit owned indexed profiles while preserving its independent metadata and identity policy.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
for(const [path,binding] of [
 ['src/utils/fhir-resource-rehydration.ts','convertClaimsToFhirResource'],
 ['src/managers/CommunicationManager.ts','normalizeClaimsFromFhirResource'],
])test(`${path} no longer loads the frozen ${binding} boundary`,()=>{
 const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);
 const violations=[];
 for(const node of source.statements){
  if(!ts.isImportDeclaration(node)||!ts.isStringLiteralLike(node.moduleSpecifier))continue;
  const names=node.importClause?.namedBindings;
  if(node.moduleSpecifier.text.startsWith('gdc-')&&names&&ts.isNamedImports(names)&&names.elements.some(item=>(item.propertyName?.text??item.name.text)===binding))violations.push(binding);
 }
 assert.deepEqual(violations,[]);
});
test('the exact candidate exposes the fixed semantic and structural profiles',async()=>{
 const profile=await import('fhir-data-utils-ts/indexed-r4');
 assert.equal(profile.IndexedR4SemanticInputTypes.length,14);
 assert.equal(profile.IndexedR4SemanticOutputTypes.length,13);
 assert.equal(profile.IndexedStructuralCompatibilityTypes.length,5);
});
