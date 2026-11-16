// Flow contract: encrypted gateway parameters, response discriminators and logical collection fan-out use their owned SOS Data contracts, preserving complete historical wire values and frozen public identities without changing authorization or indexing policy.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync,readdirSync} from 'node:fs';
import ts from 'typescript';
import * as root from 'sos-data-utils-ts';
import * as collections from 'sos-data-utils-ts/gateway-data-collections';
import * as responses from 'sos-data-utils-ts/gateway-response-contract';
const fixture=JSON.parse(readFileSync('src/__tests__/data/gateway-data-collections-wire.json','utf8'));
const symbols={
 ParameterData:['GatewayParameterData','gateway-parameter-contract'],
 GatewayParameterData:['GatewayParameterData','gateway-parameter-contract'],
 ParamAttribute:['GatewayParamAttribute','gateway-parameter-contract'],
 GatewayParamAttribute:['GatewayParamAttribute','gateway-parameter-contract'],
 GatewayEnvelopeTypes:['GatewayEnvelopeTypes','gateway-response-contract'],
 DataCollectionIds:['DataCollectionIds','gateway-data-collections'],
 FhirResourceTypeDataCollections:['FhirResourceTypeDataCollections','gateway-data-collections'],
 HealthcareSummarySectionDataCollections:['HealthcareSummarySectionDataCollections','gateway-data-collections'],
};

test('all production parameter, response and collection bindings use canonical owners without legacy aliases',()=>{
 const found=new Set();
 for(const relative of readdirSync('src',{recursive:true}).filter(path=>path.endsWith('.ts')&&!path.replaceAll('\\','/').startsWith('__tests__/'))){
  const path='src/'+relative,source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);
  for(const statement of source.statements){
   if(!ts.isImportDeclaration(statement)&&!ts.isExportDeclaration(statement))continue;
   const bindings=statement.importClause?.namedBindings??statement.exportClause;
   if(!bindings||(!ts.isNamedImports(bindings)&&!ts.isNamedExports(bindings)))continue;
   const module=statement.moduleSpecifier?.text;if(!module)continue;
   for(const item of bindings.elements){
    const imported=item.propertyName?.text??item.name.text,expected=symbols[imported];if(!expected)continue;
    // Local shared facades retain public names; their own exports are checked separately.
    if(!module.startsWith('gdc-')&&!module.startsWith('sos-data-utils-ts/'))continue;
    assert.equal(module,'sos-data-utils-ts/'+expected[1],path);
    assert.equal(imported,expected[0],path);assert.equal(item.name.text,expected[0],path);found.add(expected[0]);
   }
  }
 }
 for(const name of ['GatewayParameterData','GatewayEnvelopeTypes','DataCollectionIds','FhirResourceTypeDataCollections','HealthcareSummarySectionDataCollections'])assert.ok(found.has(name),name);
});

test('complete owned collection tables retain all original values, public identity and immutable fan-out',()=>{
 for(const [name,expected] of Object.entries(fixture.tables)){
  assert.deepEqual(collections[name],expected,name);assert.equal(root[name],collections[name],name);
  assert.equal(Object.isFrozen(collections[name]),true,name);
 }
 assert.equal(Object.keys(collections.DataCollectionIds).length,18);
 assert.equal(Object.keys(collections.FhirResourceTypeDataCollections).length,15);
 assert.equal(Object.keys(collections.HealthcareSummarySectionDataCollections).length,16);
 for(const values of Object.values(collections.HealthcareSummarySectionDataCollections))assert.equal(Object.isFrozen(values),true);
});

test('response envelope wire values remain distinct from response-entry discriminators',()=>{
 assert.deepEqual(responses.GatewayEnvelopeTypes,{BatchResponse:'batch-response',MessagingResponse:'messaging-response',TransactionResponse:'transaction-response'});
 assert.equal(root.GatewayEnvelopeTypes,responses.GatewayEnvelopeTypes);
 assert.equal(Object.isFrozen(responses.GatewayEnvelopeTypes),true);
 assert.notEqual(responses.GatewayEnvelopeTypes.MessagingResponse,responses.GatewayResponseEntryTypes.MessagingResponse);
});
