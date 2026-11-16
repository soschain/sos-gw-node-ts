// Flow contract: ledger, DID and controller credential paths retain public-member SHA256 thumbprint identities through the neutral AF owner; key aliases and ordering cannot change identity, while changed public key material does.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,createHash} from 'node:crypto';
import ts from 'typescript';
import {toJwkThumbprintSha256Urn} from 'antifraud-data-utils-ts/jwk-thumbprints';
const paths=['src/managers/HostingManager.ts','src/managers/hosting/ica-did-registration.ts','src/utils/ledger-organization-registration-helpers.ts','src/managers/hosting/organization-test-network-credential.ts','src/managers/hosting/persist-existing-tenant-controller-binding.ts'];
test('all five production thumbprint consumers use the neutral public-key owner',()=>{
 for(const path of paths){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);
  let count=0;
  for(const statement of source.statements){
   if(!ts.isImportDeclaration(statement))continue;
   const named=statement.importClause?.namedBindings;
   if(!named||!ts.isNamedImports(named))continue;
   for(const entry of named.elements)if((entry.propertyName?.text??entry.name.text)==='toJwkThumbprintSha256Urn'){
    count++;assert.equal(statement.moduleSpecifier.text,'antifraud-data-utils-ts/jwk-thumbprints',path);
   }
  }
  assert.equal(count,1,path);
 }
});
test('actual public EC material retains exact RFC9278 identity independently of aliases and object ordering',()=>{
 const key=generateKeyPairSync('ec',{namedCurve:'P-384'}).publicKey.export({format:'jwk'});
 const transcript=JSON.stringify({crv:key.crv,kty:key.kty,x:key.x,y:key.y});
 const expected='urn:ietf:params:oauth:jwk-thumbprint:sha-256:'+createHash('sha256').update(transcript).digest('base64url');
 assert.equal(toJwkThumbprintSha256Urn({...key,kid:'urn:example:alias'}),expected);
 assert.equal(toJwkThumbprintSha256Urn(Object.fromEntries(Object.entries(key).reverse())),expected);
 assert.notEqual(toJwkThumbprintSha256Urn({...key,x:key.y}),expected);
 assert.throws(()=>toJwkThumbprintSha256Urn({kty:'EC',crv:key.crv,x:key.x}));
});
