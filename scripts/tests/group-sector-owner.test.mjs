// Flow contract: Group normalization uses canonical FHIR and existing route-sector values use SOS; catalog membership never grants access or changes tenant routing.
import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync,readdirSync} from 'node:fs'
import {resolve} from 'node:path'
import {createRequire} from 'node:module'
import {pathToFileURL} from 'node:url'
import ts from 'typescript'
const require=createRequire(import.meta.url)
const fhir=await import(pathToFileURL(require.resolve('fhir-data-utils-ts/group-r5')).href)
const data=await import(pathToFileURL(require.resolve('sos-data-utils-ts/gateway-sector-contract')).href)
const walk=directory=>readdirSync(directory,{withFileTypes:true}).flatMap(entry=>entry.isDirectory()?walk(resolve(directory,entry.name)):entry.name.endsWith('.ts')?[resolve(directory,entry.name)]:[])

test('Group manager imports its exact catalog and normalizer from FHIR',()=>{
 const source=readFileSync('src/managers/GroupManager.ts','utf8')
 assert.ok(/import\s*\{\s*GroupFlatClaimCatalog,\s*normalizeGroupR5FlatClaimsResource\s*\}\s*from\s*['"]fhir-data-utils-ts\/group-r5['"]/u.test(source),'Group catalog/normalizer must use their FHIR owner')
})
test('all existing Sector bindings use their SOS owner without a local alias',()=>{
 for(const path of walk('src')){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true)
  for(const node of source.statements)if(ts.isImportDeclaration(node)&&ts.isStringLiteral(node.moduleSpecifier)&&node.moduleSpecifier.text==='gdc-common-utils-ts/models/urlPath'){
   const bindings=node.importClause?.namedBindings
   if(bindings&&ts.isNamedImports(bindings))assert.ok(!bindings.elements.some(item=>(item.propertyName??item.name).text==='Sector'),path)
  }
 }
})
test('the seven existing route-sector wire values remain exact and frozen',()=>{
 assert.deepEqual(data.GatewaySector,{TEST:'test',SYSTEM:'system',ANTIFRAUD:'antifraud',HEALTH_CARE:'health-care',HEALTH_INSURANCE:'health-insurance',EMERGENCY:'emergency',RESEARCH:'research'})
 assert.ok(Object.isFrozen(data.GatewaySector))
})
test('FHIR Group flat claims normalize without synthesizing authority and reject native content',()=>{
 const input={resourceType:'Group',id:'group-one',meta:{claims:{'Group.name':['Review team'],'Group.type':['person'],'Group.membership':['enumerated']}}}
 assert.deepEqual(fhir.normalizeGroupR5FlatClaimsResource(input),input)
 assert.throws(()=>fhir.normalizeGroupR5FlatClaimsResource({...input,member:[{entity:{reference:'Person/other'}}]}))
 assert.ok(fhir.GroupFlatClaimCatalog.standardSearch.includes('Group.name'))
})
