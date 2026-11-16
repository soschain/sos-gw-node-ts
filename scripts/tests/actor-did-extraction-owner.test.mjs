// Flow contract: the real queued-actor verifier resolves its stable actor DID extraction from the neutral AF owner; actual authentication/role semantics remain covered by manager and HTTP tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
const filename=new URL('../../src/utils/authenticated-job-actor.ts',import.meta.url);
test('queued actor binding imports the actual extraction operation from its neutral owner',()=>{
 const source=ts.createSourceFile(filename.pathname,readFileSync(filename,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 const owners=[];
 for(const statement of source.statements){
  if(!ts.isImportDeclaration(statement)||!ts.isStringLiteral(statement.moduleSpecifier))continue;
  const bindings=statement.importClause?.namedBindings;
  if(!bindings||!ts.isNamedImports(bindings))continue;
  for(const binding of bindings.elements){
   if((binding.propertyName??binding.name).text==='stableActorIdentifierFromDidWeb'){
    assert.equal(binding.name.text,'stableActorIdentifierFromDidWeb','do not hide extraction behind an alias');
    owners.push(statement.moduleSpecifier.text);
   }
  }
 }
 assert.deepEqual(owners,['antifraud-data-utils-ts/organization-identity']);
 let actualCalls=0;
 const visit=node=>{if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='stableActorIdentifierFromDidWeb')actualCalls++;ts.forEachChild(node,visit)};
 visit(source);assert.ok(actualCalls>0,'the actual actor binding must use its owned operation');
});
