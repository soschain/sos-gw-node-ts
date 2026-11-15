// Flow contract: GW persisted seats and installation bindings consume the SOS-owned contract, preserve exact wire statuses and optional owner/contact fields, and reject incompatible typed records without granting runtime authority.
import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync,readdirSync} from 'node:fs'
import {resolve} from 'node:path'
import {createRequire} from 'node:module'
import {pathToFileURL,fileURLToPath} from 'node:url'
import {execFileSync} from 'node:child_process'
import ts from 'typescript'
const require=createRequire(import.meta.url)
const walk=directory=>readdirSync(directory,{withFileTypes:true}).flatMap(entry=>entry.isDirectory()?walk(resolve(directory,entry.name)):entry.name.endsWith('.ts')?[resolve(directory,entry.name)]:[])
test('GW seat and binding imports use SOS Data without a legacy alias',()=>{
 const violations=[]
 for(const path of walk('src')){
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true)
  const visit=node=>{
   if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier&&ts.isStringLiteral(node.moduleSpecifier)&&['gdc-common-utils-ts/models/device-license','gdc-common-utils-ts/constants/device'].includes(node.moduleSpecifier.text))violations.push(path)
   ts.forEachChild(node,visit)
  };visit(source)
 }
 assert.deepEqual(violations,[],'all exact seat/model/catalog consumers must use the owned contract')
})
test('installed owned catalogs preserve seat lifecycle separately from installation revocation',async()=>{
 const contract=await import(pathToFileURL(require.resolve('sos-data-utils-ts/device-license-contract')).href)
 for(const [name,expected]of Object.entries({DeviceUserClasses:{Employee:'employee',Individual:'individual'},DeviceAppTypes:{Mobile:'mobile',Web:'web'},DeviceBindingStatuses:{Active:'active',Revoked:'revoked'},LicenseStatuses:{Available:'available',Issued:'issued',Active:'active',Inactive:'inactive'}})){
  assert.deepEqual(contract[name],expected);assert.ok(Object.isFrozen(contract[name]))
 }
 assert.equal(Object.hasOwn(contract.DeviceBindingStatuses,'Inactive'),false)
 assert.equal(Object.hasOwn(contract.LicenseStatuses,'Revoked'),false)
})
test('actual public consumer types retain stored phone/owner/device fields and reject serialized timestamps and OIDC shape',()=>{
 execFileSync(process.execPath,[require.resolve('typescript/bin/tsc'),'--noEmit','--strict','--exactOptionalPropertyTypes','--skipLibCheck','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext',fileURLToPath(new URL('./fixtures/device-license-owner-consumer.ts',import.meta.url))],{stdio:'pipe'})
})
