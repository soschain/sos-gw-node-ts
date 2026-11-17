// Flow contract: patch only relative ESM runtime paths while preserving package exports, and direct release operators to the approved private inventory instead of a baked-in cloud destination or another gateway checkout. This suite performs no infrastructure call or publication.
import assert from 'node:assert/strict'
import test from 'node:test'
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {execFileSync} from 'node:child_process'
const root=fileURLToPath(new URL('../../',import.meta.url))
function fixture(run){const cwd=mkdtempSync(path.join(tmpdir(),'sos-esm-contract-'));try{mkdirSync(path.join(cwd,'build'));return run(cwd)}finally{rmSync(cwd,{recursive:true,force:true})}}
function patch(cwd){execFileSync(process.execPath,[path.join(root,'scripts/patch-esm-imports.mjs')],{cwd,env:{...process.env,EXTRA_TS_PATCH_DIRS:''},stdio:'pipe'})}
test('patches existing relative files and directory indexes for ESM execution',()=>fixture(cwd=>{
 mkdirSync(path.join(cwd,'build/nested'));writeFileSync(path.join(cwd,'build/leaf.js'),'export const value=1;');writeFileSync(path.join(cwd,'build/nested/index.js'),'export const value=2;')
 const file=path.join(cwd,'build/main.js');writeFileSync(file,"import {value} from './leaf'; const nested=import('./nested');")
 patch(cwd);assert.equal(readFileSync(file,'utf8'),"import {value} from './leaf.js'; const nested=import('./nested/index.js');")
}))
test('never bypasses package exports to select a private TypeScript source',()=>fixture(cwd=>{
 const name=['gdc','common','utils','ts'].join('-')
 const directory=path.join(cwd,'node_modules',name);mkdirSync(directory,{recursive:true})
 writeFileSync(path.join(directory,'package.json'),JSON.stringify({name,exports:{'./contract':'./dist/contract.js'}}));writeFileSync(path.join(directory,'contract.ts'),'export const privateSource=true;')
 const file=path.join(cwd,'build/main.js');const source=`import {value} from '${name}/contract'; const module=import('${name}/contract');`;writeFileSync(file,source)
 patch(cwd);assert.equal(readFileSync(file,'utf8'),source)
}))
test('release guidance resolves its target from private inventory and uses this SOS checkout',()=>{
 const reference=readFileSync(path.join(root,'.codex/skills/gw-unid-local-image-release/references/unid-staging.md'),'utf8')
 const skill=readFileSync(path.join(root,'.codex/skills/gw-unid-local-image-release/SKILL.md'),'utf8')
 assert.match(reference,/approved private inventory/i)
 assert.doesNotMatch(reference,/GCP project:\s*`[^`]+`|Expected context:\s*`[^`]+`|\b(?:\d{1,3}\.){3}\d{1,3}\b/u)
 assert.match(skill,/deploy\/profiles\/soschain\/staging/u)
 assert.match(skill,/cloud_deploy\.sh gke soschain/u)
 assert.doesNotMatch(skill,/Run this from\s+the UHC GW repository|\.\.\/gwtemplate-node-ts\/chaincode/u)
})
