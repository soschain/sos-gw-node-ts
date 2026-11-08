// Flow contract: the host bootstrap and its sourced payload helper retain Bash-compatible LF endings on Windows and Unix; the actual bootstrap prologue must execute before any authority/network side effect.
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {spawnSync} from 'node:child_process'
import test from 'node:test'

for(const file of ['scripts/bootstrap-single-tenant.sh','scripts/payload-helpers.sh']){
  test(`${file} is a portable Bash entry point`,()=>{
    const source=readFileSync(file,'utf8')
    assert.equal(source.includes('\r'),false,'Bash scripts must be checked out with LF endings')
    const result=file.endsWith('bootstrap-single-tenant.sh')
      ?spawnSync('bash',['--noprofile','--norc','-c',source.split('\n').slice(0,2).join('\n')],{encoding:'utf8',windowsHide:true})
      :spawnSync('bash',['--noprofile','--norc','-n',file],{encoding:'utf8',windowsHide:true})
    assert.equal(result.status,0,result.stderr||String(result.error||''))
  })
}
