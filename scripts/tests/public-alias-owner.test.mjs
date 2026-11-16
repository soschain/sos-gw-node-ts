// Flow contract: existing employee, controller, licence and SMART alias consumers retain opaque public identifiers and exact contact-hash wire profiles while using neutral AF-owned operations; normalization never supplies possession or authorization.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import {normalizePublicAliasList, normalizeControllerAlias, normalizeTelephoneAlias} from 'antifraud-data-utils-ts/public-aliases';
import {buildStableActorIdentifier, normalizeActorContact} from 'antifraud-data-utils-ts/organization-identity';
import {SyntheticConfidentialDocumentFixture} from 'antifraud-data-utils-ts/identity-assurance';

const paths = [
 'src/managers/AppAuthorizationManager.ts', 'src/managers/EmployeeManager.ts',
 'src/managers/hosting/controller-entity-config.ts',
 'src/managers/hosting/persist-existing-tenant-controller-binding.ts',
 'src/managers/LicenseManager.ts', 'src/managers/OpenIdAuthManager.ts',
 'src/managers/TenantsCacheManager.ts',
];
const names = new Set(['normalizePublicAliasList', 'normalizeControllerAlias', 'normalizeTelephoneAlias', 'normalizeSameAsHash', 'normalizeTelephoneHash']);
test('seven production alias consumers use the owning AF leaf without hiding legacy names behind aliases', () => {
 for (const path of paths) {
  const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true);
  let count = 0;
  for (const statement of source.statements) {
   if (!ts.isImportDeclaration(statement)) continue;
   const bindings = statement.importClause?.namedBindings;
   if (!bindings || !ts.isNamedImports(bindings)) continue;
   for (const entry of bindings.elements) if (names.has(entry.propertyName?.text ?? entry.name.text)) {
    count++;
    assert.equal(statement.moduleSpecifier.text, 'antifraud-data-utils-ts/public-aliases', path);
    assert.equal(entry.propertyName, undefined, `${path}: no imported rename`);
    assert.ok(!entry.name.text.endsWith('Hash'), `${path}: use owned operation name`);
   }
  }
  assert.ok(count > 0, path);
 }
});
test('opaque public aliases preserve a bare content CID and exact case while retaining stable CSV order', () => {
 const cid = SyntheticConfidentialDocumentFixture.attachment.contentId;
 assert.deepEqual(normalizePublicAliasList([` ${cid},urn:example:subject `, 'urn:example:subject', ' urn:example:OTHER ']), [cid, 'urn:example:subject', 'urn:example:OTHER']);
 assert.notEqual(normalizeControllerAlias(cid), cid);
});
test('email and formatted phone aliases retain strict actor hash bytes without making tolerant phone input valid', () => {
 const email = 'controller@example.invalid';
 const phone = '+12025550123';
 const emailActor = buildStableActorIdentifier({contactKind: 'email', contact: email});
 const phoneActor = buildStableActorIdentifier({contactKind: 'phone', contact: phone});
 assert.equal(normalizeControllerAlias(` ${email.toUpperCase()} `), emailActor);
 assert.equal(normalizeTelephoneAlias('tel:+1 (202) 555-0123'), phoneActor);
 assert.equal(normalizeControllerAlias(emailActor), emailActor);
 assert.equal(normalizeTelephoneAlias(phoneActor), phoneActor);
 assert.notEqual(normalizeControllerAlias(`mailto:${email}`), emailActor);
 assert.throws(() => normalizeActorContact({contactKind: 'phone', contact: 'not-a-number123'}));
});
