// Flow contract: real Communication search, RelatedPerson purge and DSP discovery consumers use the published SOS operational wire owner with identical discriminators and metadata; selecting these values does not grant authorization or change lifecycle policy.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as response from 'sos-data-utils-ts/gateway-response-contract';
import * as dataspace from 'sos-data-utils-ts/gateway-dataspace-routing';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';

const targets=[
 {path:'src/managers/CommunicationManager.ts',old:'SearchBundleTypes',name:'GatewaySearchBundleTypes',owner:'sos-data-utils-ts/gateway-response-contract'},
 {path:'src/managers/RelatedPersonManager.ts',old:'InteroperableLifecycleStatuses',name:'GatewayResourceLifecycleStatuses',owner:'sos-data-utils-ts/gateway-response-contract'},
 {path:'src/routes/discovery.ts',old:'buildDspaceVersionMetadata',name:'buildGatewayDataspaceVersionMetadata',owner:'sos-data-utils-ts/gateway-dataspace-routing'},
];
test('operational consumers import their actual SOS owners without a legacy binding or alias',()=>{
 for(const target of targets){
  const source=ts.createSourceFile(target.path,readFileSync(target.path,'utf8'),ts.ScriptTarget.Latest,true);let found=0;
  for(const statement of source.statements){
   const bindings=statement.importClause?.namedBindings;
   if(!ts.isImportDeclaration(statement)||!bindings||!ts.isNamedImports(bindings))continue;
   for(const item of bindings.elements){
    const name=item.propertyName?.text??item.name.text;if(name!==target.old&&name!==target.name)continue;
    found++;assert.equal(statement.moduleSpecifier.text,target.owner,target.path);assert.equal(name,target.name,target.path);assert.equal(item.name.text,target.name,target.path);
   }
  }
  assert.equal(found,1,target.path);
 }
});
test('keeps both search and all six lifecycle wire values immutable and separate from authorization',()=>{
 // Exact serialization literals are the compatibility boundary under test.
 assert.deepEqual(response.GatewaySearchBundleTypes,{Search:'search',SearchResponse:'search-response'});
 assert.deepEqual(response.GatewayResourceLifecycleStatuses,{Pending:'pending',Active:'active',Inactive:'inactive',Purged:'purged',Suspended:'suspended',Revoked:'revoked'});
 assert.equal(Object.isFrozen(response.GatewaySearchBundleTypes),true);assert.equal(Object.isFrozen(response.GatewayResourceLifecycleStatuses),true);
});
test('DSP metadata retains its existing supplied path and version bytes without shared mutable results',()=>{
 // Exact existing protocol serialization, not an invented endpoint or authority.
 const path=`/${safe.tenantId}/dsp`;
 const first=dataspace.buildGatewayDataspaceVersionMetadata(path),second=dataspace.buildGatewayDataspaceVersionMetadata(path);
 assert.deepEqual(first,{protocolVersions:[{version:'2025-1',path}]});assert.deepEqual(second,first);
 first.protocolVersions[0].path='changed';assert.equal(second.protocolVersions[0].path,path);
 assert.deepEqual(dataspace.buildGatewayDataspaceVersionMetadata('', 'synthetic-version'),{protocolVersions:[{version:'synthetic-version',path:''}]});
});
