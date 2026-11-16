// Flow contract: existing identity/auth requests, registered-device routes and SMART polls retain all exact wire literals while sourcing their reusable catalogs from SOS Data; authorization remains in the actual managers.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as owned from 'sos-data-utils-ts/identity-auth-wire-contract';
import * as root from 'sos-data-utils-ts';

const expected=JSON.parse(readFileSync('src/__tests__/data/identity-auth-wire.json','utf8'));
const paths=[
 'src/routes/api.ts','src/managers/DeviceRegistrationManager.ts','src/managers/IdentityTokenManager.ts',
 'src/utils/services.ts','src/utils/secure-route-bearer-binding.ts',
 'src/__tests__/managers/OpenIdAuthManager.test.ts','src/__tests__/managers/IdentityTokenManager.test.ts',
 'src/__tests__/managers/DeviceRegistrationManager.test.ts','src/__tests__/integration/security-mode-gates.test.ts',
 'src/__tests__/integration/device.dcr-replacement.api.test.ts','src/__tests__/unit/utils/secure-route-bearer-binding.test.ts',
];
test('all eleven existing identity/auth catalog consumers use the owning SOS Data leaf',()=>{
 for(const path of paths){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);
  let found=0;
  for(const statement of source.statements){
   const bindings=statement.importClause?.namedBindings;
   if(!ts.isImportDeclaration(statement)||!bindings||!ts.isNamedImports(bindings))continue;
   for(const element of bindings.elements)if(Object.hasOwn(expected,element.propertyName?.text??element.name.text)){
    found++;assert.equal(statement.moduleSpecifier.text,'sos-data-utils-ts/identity-auth-wire-contract',path);
   }
  }
  assert.ok(found>0,`missing inventoried consumer ${path}`);
 }
});
test('preserves the complete thirty-member operational profile and public literal objects',()=>{
 let count=0;
 for(const[name,catalog]of Object.entries(expected)){
  assert.deepEqual(owned[name],catalog,name);assert.equal(root[name],owned[name]);
  assert.equal(Object.isFrozen(owned[name]),true);count+=Object.keys(catalog).length;
 }
 assert.equal(count,30);
});
test('keeps SMART compatibility polling distinct from underscored registration and token actions',()=>{
 assert.equal(owned.IdentityAuthActions.Dcr,'_dcr');
 assert.equal(owned.SmartPostDcrActions.Token,'token');
 assert.equal(owned.SmartPostDcrActions.TokenResponse,'token-response');
 assert.equal(owned.SmartPostDcrActions.LegacyBatchResponse,'_batch-response');
 assert.equal(Object.values(owned.SmartPostDcrActions).includes('_token'),false);
 assert.equal('LicenseIssued' in owned.IdentityAuthResponseTypes,false);
});
