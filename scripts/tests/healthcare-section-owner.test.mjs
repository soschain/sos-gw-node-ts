// Flow contract: existing IPS operational consumers use the exact published SOS Core/PermissionSummary profiles, preserving every descriptor and non-enumerable compatibility key while keeping native URI summary tokens separate and granting no access.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as owned from 'sos-data-utils-ts/healthcare-sections';
import * as publicApi from 'sos-data-utils-ts';
const fixture=JSON.parse(readFileSync('src/__tests__/data/healthcare-operational-wire.json','utf8'));
const pairs={HealthcareBasicSections:'HealthcareCoreSections',HealthcareSummarySections:'HealthcarePermissionSummarySections'};
const paths=[
 'src/api-examples/communication.examples.ts','src/managers/CommunicationManager.ts',
 'src/managers/CompositionManager.ts','src/managers/TwinCompositionManager.ts',
 'src/shared/healthcare-constants.ts','src/utils/ips-bundle.ts',
];
test('operational section consumers import exact canonical owners without re-exporting a legacy alias',()=>{
 for(const path of paths){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);let found=0;
  for(const statement of source.statements){
   if(!ts.isImportDeclaration(statement)&&!ts.isExportDeclaration(statement))continue;
   const bindings=statement.importClause?.namedBindings??statement.exportClause;
   if(!bindings||(!ts.isNamedImports(bindings)&&!ts.isNamedExports(bindings)))continue;
   for(const item of bindings.elements){
    const name=item.propertyName?.text??item.name.text;
    const canonical=pairs[name]??(Object.values(pairs).includes(name)?name:undefined);if(!canonical)continue;
    found++;assert.equal(statement.moduleSpecifier.text,'sos-data-utils-ts/healthcare-sections',path);
    assert.equal(name,canonical,path);assert.equal(item.name.text,canonical,path);
   }
  }
  assert.ok(found>0,path);
 }
});
test('all original Core and permission-summary descriptors and enumerability remain exactly equal',()=>{
 assert.equal(fixture.profiles.length,2);
 for(const profile of fixture.profiles){
  const value=owned[profile.owner];assert.ok(value,profile.owner);assert.equal(publicApi[profile.owner],value);
  const actual=Object.fromEntries(Object.getOwnPropertyNames(value).map(name=>[name,{value:value[name],enumerable:Object.getOwnPropertyDescriptor(value,name).enumerable}]));
  assert.deepEqual(actual,profile.entries,profile.owner);assert.equal(Object.isFrozen(value),true);
 }
 assert.equal(Object.keys(owned.HealthcareCoreSections).length,22);
 assert.equal(Object.getOwnPropertyNames(owned.HealthcareCoreSections).length,24);
 assert.equal(Object.keys(owned.HealthcarePermissionSummarySections).length,16);
});
test('operational LOINC tokens remain separate from the unchanged native URI summary profile',()=>{
 const code=owned.HealthcarePermissionSummarySections.ProblemList.code;
 assert.equal(owned.HealthcarePermissionSummarySections.ProblemList.attributeValue,`LOINC|${code}`);
 assert.equal(owned.HealthcareSummarySections.ProblemList.attributeValue,`${owned.HealthcarePermissionSummarySections.ProblemList.system}|${code}`);
 assert.notEqual(owned.HealthcareSummarySections.ProblemList.attributeValue,owned.HealthcarePermissionSummarySections.ProblemList.attributeValue);
 assert.equal(Object.keys(owned.HealthcareCoreSections).includes('PatientSummaryDocument'),false);
 assert.equal(owned.HealthcareCoreSections.PlanOfTreatment,owned.HealthcareCoreSections.PlanOfCare);
});
