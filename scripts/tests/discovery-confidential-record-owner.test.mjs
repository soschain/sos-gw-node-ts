// Flow contract: discovery reads the same protected records through the public SOS-owned record contract; native route output and authority do not change.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import ts from 'typescript';
test('discovery resolves both protected section reads through the SOS-owned type',()=>{
 const text=readFileSync(new URL('../../src/routes/discovery.ts',import.meta.url),'utf8');
 assert.equal(/import\(['"]gdc-common-utils-ts\/models\/confidential-storage['"]\)/u.test(text),false,'Discovery still loads the frozen record type');
 const source=ts.createSourceFile('discovery.ts',text,ts.ScriptTarget.Latest,true);
 const owned=source.statements.filter(statement=>ts.isImportDeclaration(statement)&&statement.moduleSpecifier.text==='sos-data-utils-ts/confidential-storage');
 assert.equal(owned.length,1);assert.equal(owned[0].importClause.isTypeOnly,true);
 assert.match(text,/listContainersInSection<ConfidentialStorageDoc>\(collectionName, 'care-communication-requests'\)/u);
 assert.match(text,/listContainersInSection<ConfidentialStorageDoc>\(collectionName, 'organization-document-references'\)/u);
});
test('public protected-record contract accepts real envelopes and rejects wrong identity or revision shapes',()=>{
 execFileSync(process.execPath,['node_modules/typescript/bin/tsc','--noEmit','--strict','--skipLibCheck','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2022','scripts/tests/fixtures/discovery-confidential-record.ts'],{encoding:'utf8',stdio:'pipe'});
});
