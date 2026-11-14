// Flow contract: storage records, jobs, batch entries, routing selectors and HTTP vocabulary use independent SOS contracts; encoded JWS shapes use Antifraud.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'
const owned=new Set(['RecordBase','VaultConfig','ClaimsRecord','ConfidentialStorageDoc','ConfidentialBlobInfo','IndexedAttribute','IndexedData','AuditInfo','PublicInfo','ResearchInfo','MetaTagCoding','UnprotectedStorageDoc','BundleEntry','BundleJsonApi','BundleEntryRequest','BundleEntryResponse','ErrorEntry','BundleRequest','BundleResponse','JobStatus','JobRequest','JobRequestInfo','DidCommDecodedMetadata','IDecodedDidcommPayload','ServiceEndpointSelector','SecureServiceEndpointSelector','JwsHeader','JwsMultiSign','JwsDetachedSignParts','HttpRequestMethods','HttpStatusCodes','HttpHeaderNames','HttpAuthorizationSchemes','HttpMediaTypes'])
test('migrated protocol and record imports/re-exports never use a frozen package',async()=>{
 const root=new URL('../../src/',import.meta.url),violations=[]
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
