// Flow contract: DID catalog advertisements retain complete fragment/type/path wire catalogs while their existing service builders, discovery scope and endpoint authorization stay unchanged.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as owned from 'sos-data-utils-ts/gateway-did-profile';
const expected=JSON.parse(readFileSync('src/__tests__/data/discovery-wire.json','utf8'));
const paths=['src/routes/discovery.ts','src/utils/services.ts','src/__tests__/unit/utils/dataspace.did-services.compliance.test.ts','src/__tests__/unit/utils/services.test.ts'];
test('all four existing discovery catalog consumers use the SOS gateway DID profile owner',()=>{
 for(const path of paths){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);let found=0;
  for(const s of source.statements){
   const bindings=s.importClause?.namedBindings;
   if(!ts.isImportDeclaration(s)||!bindings||!ts.isNamedImports(bindings))continue;
   for(const e of bindings.elements)if(Object.hasOwn(expected,e.propertyName?.text??e.name.text)){
    found++;assert.equal(s.moduleSpecifier.text,'sos-data-utils-ts/gateway-did-profile',path);
   }
  }
  assert.ok(found>0,`missing inventoried ${path}`);
 }
});
test('retains all seventeen advertisement members, including the precise SMART fragment and relative DSP path',()=>{
 let count=0;for(const[name,catalog]of Object.entries(expected)){
  assert.deepEqual(owned[name],catalog,name);assert.equal(Object.isFrozen(owned[name]),true);count+=Object.keys(catalog).length;
 }
 assert.equal(count,17);assert.equal(owned.DidServiceIds.SmartToken,'#identity:openid:smart:token');
 assert.equal(owned.DataspaceWellKnownPaths.VersionMetadata,'/.well-known/dspace-version');
 assert.equal(owned.DidServiceTypes.CatalogService,'CatalogService');
});
