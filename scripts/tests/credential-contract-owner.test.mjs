// Flow contract: gateway credential subjects, proof projections and the W3C V2 context use the neutral published Antifraud owner, preserving wire fields and signing behavior without claiming EBSI authority or introducing a legacy alias.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync,readdirSync} from 'node:fs';
import ts from 'typescript';
import {VC_CONTEXT_V2,W3cCredentialContexts,W3cCredentialTypes} from 'antifraud-data-utils-ts/credential-contracts';
const symbols={VerifiableCredentialV2:'VerifiableCredentialV2',ProofEBSIv2:'CredentialProof',CredentialProof:'CredentialProof',VC_CONTEXT_V2:'VC_CONTEXT_V2'};

test('production credential models resolve the canonical neutral owner and proof name',()=>{
 const found=new Set();
 for(const relative of readdirSync('src',{recursive:true}).filter(path=>path.endsWith('.ts')&&!path.replaceAll('\\','/').startsWith('__tests__/'))){
  const path='src/'+relative,source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);
  for(const statement of source.statements){
   if(!ts.isImportDeclaration(statement)&&!ts.isExportDeclaration(statement))continue;
   const bindings=statement.importClause?.namedBindings??statement.exportClause;if(!bindings||(!ts.isNamedImports(bindings)&&!ts.isNamedExports(bindings)))continue;
   const module=statement.moduleSpecifier?.text;
   for(const item of bindings.elements){
    const imported=item.propertyName?.text??item.name.text,canonical=symbols[imported];if(!canonical)continue;
    assert.equal(module,'antifraud-data-utils-ts/credential-contracts',path);
    assert.equal(imported,canonical,path);assert.equal(item.name.text,canonical,path);found.add(canonical);
   }
  }
 }
 assert.deepEqual([...found].sort(),['CredentialProof','VC_CONTEXT_V2','VerifiableCredentialV2']);
});

test('the canonical V2 context and credential type preserve the existing W3C wire values',()=>{
 assert.equal(VC_CONTEXT_V2,'https://www.w3.org/ns/credentials/v2');
 assert.equal(VC_CONTEXT_V2,W3cCredentialContexts.V2);
 assert.equal(W3cCredentialTypes.VerifiableCredential,'VerifiableCredential');
 assert.equal(W3cCredentialTypes.VerifiablePresentation,'VerifiablePresentation');
});


test('organization review transcripts and credential markers use the same owned neutral runtime',()=>{
 const path='src/managers/hosting/organization-test-network-credential.ts';
 const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true),found=new Set();
 const required=new Set(['canonicalizeOrganizationTestNetworkCredential','canonicalizeTestNetworkOrganizationCredential','ReviewedOrganizationCredentialTypes']);
 for(const statement of source.statements){
  if(!ts.isImportDeclaration(statement))continue;
  const module=statement.moduleSpecifier.text;
  assert.equal(module.startsWith('gdc-'),false,'organization review must not load legacy credential algorithms or catalogs');
  const bindings=statement.importClause?.namedBindings;if(!bindings||!ts.isNamedImports(bindings))continue;
  for(const item of bindings.elements){const name=item.propertyName?.text??item.name.text;if(!required.has(name))continue;assert.equal(module,'antifraud-data-utils-ts/organization-credentials');assert.equal(item.name.text,name);found.add(name)}
 }
 assert.deepEqual([...found].sort(),[...required].sort());
});
