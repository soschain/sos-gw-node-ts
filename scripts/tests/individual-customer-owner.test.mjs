// Flow contract: an Individual creation response uses the owned SOS application discriminator with exact recorded wire spelling, independently of canonical Person resource type and without changing authorization or persistence.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import {GatewayResponseEntryTypes} from 'sos-data-utils-ts/gateway-response-contract';
import {ResourceTypesFhirR4} from 'fhir-data-utils-ts';
const fixture=JSON.parse(readFileSync('scripts/tests/fixtures/individual-customer-discriminator.json','utf8'));
test('the active Individual creation response selects its SOS discriminator owner',()=>{
 const path='src/managers/IndividualManager.ts',text=readFileSync(path,'utf8'),source=ts.createSourceFile(path,text,ts.ScriptTarget.Latest,true);
 const owners=[];
 for(const node of source.statements){
  if(!ts.isImportDeclaration(node)||!ts.isStringLiteralLike(node.moduleSpecifier))continue;
  const bindings=node.importClause?.namedBindings;
  if(!bindings||!ts.isNamedImports(bindings))continue;
  for(const item of bindings.elements){
   assert.ok(!(node.moduleSpecifier.text.startsWith('gdc-')&&(item.propertyName?.text??item.name.text)==='SchemaOrgTypes'));
   if((item.propertyName?.text??item.name.text)==='GatewayResponseEntryTypes')owners.push(node.moduleSpecifier.text);
  }
 }
 assert.deepEqual(owners,['sos-data-utils-ts/gateway-response-contract']);
 assert.match(text,/type:\s*GatewayResponseEntryTypes\.IndividualCustomer\b/);
});
test('the exact recorded Customer tag stays independent from the FHIR Person resource',()=>{
 assert.equal(GatewayResponseEntryTypes.IndividualCustomer,fixture.individualCustomer);
 assert.equal(GatewayResponseEntryTypes.IndividualCustomer,'Customer'); // Exact application wire value under test.
 assert.equal(ResourceTypesFhirR4.Person,'Person');
 assert.notEqual(GatewayResponseEntryTypes.IndividualCustomer,ResourceTypesFhirR4.Person);
});
