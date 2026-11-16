// Flow contract: the existing versioned R5 subscription boundary consumes public FHIR matching/notification owners, not a frozen utility or an aliased wrapper.
import test from 'node:test'
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import ts from 'typescript'

test('SubscriptionManager imports and calls both canonical FHIR subscription APIs',async()=>{
 const text=await readFile(new URL('../../src/managers/SubscriptionManager.ts',import.meta.url),'utf8')
 const source=ts.createSourceFile('SubscriptionManager.ts',text,ts.ScriptTarget.Latest,true)
 const owned=new Set(['buildSubscriptionNotificationR5','matchesSubscriptionEventR5'])
 const imported=new Set()
 for(const statement of source.statements){
  if(!ts.isImportDeclaration(statement)||!ts.isStringLiteralLike(statement.moduleSpecifier))continue
  const bindings=statement.importClause?.namedBindings
  if(!bindings||!ts.isNamedImports(bindings))continue
  for(const binding of bindings.elements){
   const original=binding.propertyName?.text??binding.name.text
   if(owned.has(original)){
    assert.equal(statement.moduleSpecifier.text,'fhir-data-utils-ts/subscription-r5')
    assert.equal(binding.name.text,original)
    imported.add(original)
   }
  }
 }
 assert.deepEqual([...imported].sort(),[...owned].sort())
 assert.doesNotMatch(text,/gdc-common-utils-ts\/models\/fhir-r5-subscription/u)
 for(const name of owned)assert.match(text,new RegExp(name+'\\('))
})
