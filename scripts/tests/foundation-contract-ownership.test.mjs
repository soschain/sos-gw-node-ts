// Flow contract: neutral contact identity, SOS routing taxonomy and clinical vocabulary use their independent owners, including re-exports.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'
const owned = new Set(['buildStableActorIdentifier', 'StableActorContactKind', 'StableActorContactKinds', 'buildOrganizationAuthorizationUrnCds', 'buildOrganizationEmployeeAuthorizationUrnCds', 'DataspaceSectors', 'ServiceCapability', 'HealthcareConsentPurposes', 'CommunicationCategoryCodes', 'HL7_CODING_SYSTEM_V3_ROLE_CODE'])
test('imports and re-exports do not obtain migrated foundation contracts from a frozen package', async()=>{
 const root=new URL('../../src/',import.meta.url), violations=[]
 for(const path of (await readdir(root,{recursive:true})).filter(path=>path.endsWith('.ts'))){
  const source=ts.createSourceFile(path,await readFile(new URL(path.replaceAll('\\','/'),root),'utf8'),ts.ScriptTarget.Latest,true)
  for(const node of source.statements){
   const importing=ts.isImportDeclaration(node)
   if(!(importing||ts.isExportDeclaration(node))||!node.moduleSpecifier||!ts.isStringLiteralLike(node.moduleSpecifier)||!node.moduleSpecifier.text.startsWith('gdc-'))continue
   const bindings=importing?node.importClause?.namedBindings:node.exportClause
   if(bindings&&(ts.isNamedImports(bindings)||ts.isNamedExports(bindings)))for(const binding of bindings.elements){
    const name=binding.propertyName?.text??binding.name.text
    if(owned.has(name))violations.push(`${path}: ${name}`)
   }
  }
 }
 assert.equal(violations.length,0,violations.join('\n'))
})
