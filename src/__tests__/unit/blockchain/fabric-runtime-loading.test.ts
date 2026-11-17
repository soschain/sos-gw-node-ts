// Flow contract: importing the memory-capable ledger boundary never initializes the optional Fabric client. An explicit Fabric connection still uses the installed authoritative client and its real EC signer under Node 26; synthetic identity bytes and an unused loopback channel do not prove network membership or a committed transaction.
import {describe,expect,it} from '@jest/globals';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,readFileSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import ts from 'typescript';
import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';

describe('Fabric runtime initialization boundary',()=>{
 it('loads the ledger adapters without initializing the Fabric runtime in a memory profile',async()=>{
  await expect(import('../../../blockchain/fabric/v3/manageAsset')).resolves.toHaveProperty('ManageAsset');
  await expect(import('../../../blockchain/fabric/v3/listen')).resolves.toHaveProperty('main');
  await expect(import('../../../blockchain/fabric/v3/network')).resolves.toHaveProperty('getNetwork');
  await expect(import('../../../blockchain/fabric/v3/contract')).resolves.toHaveProperty('getContractByItemType');
  await expect(import('../../../blockchain/fabric/v3/wallets-v3')).resolves.toHaveProperty('getFabricIdentityFromMemoryWallet');
  await expect(import('../../../blockchain/fabric/v3/transaction.utils')).resolves.toHaveProperty('getBlockHeight');
  const {CredentialLedgerAdapterMem}=await import('../../../adapters/CredentialLedgerAdapterMem');
  await expect(new CredentialLedgerAdapterMem().getCredentialStatus(e.resourceUuid,'test')).resolves.toBeUndefined();
 });
 it('initializes the authoritative package only for explicit native Fabric connection/signing',()=>{
  const artifact=mkdtempSync(join(tmpdir(),'sos-fabric-runtime-'));
  // Transpile the exact two transport modules without any package/crypto
  // rewriting. The extensionless companion preserves the source import bytes.
  writeFileSync(join(artifact,'package.json'),JSON.stringify({type:'module'}));
  symlinkSync(join(process.cwd(),'node_modules'),join(artifact,'node_modules'),'dir');
  for(const [name,output] of [['connect.ts','connect.js'],['connection.ts','connection']]){
   const content=readFileSync(join(process.cwd(),'src/blockchain/fabric/v3',name),'utf8');
   writeFileSync(join(artifact,output),ts.transpileModule(content,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText);
  }
  const source=`
   import assert from 'node:assert/strict';
   import {createRequire} from 'node:module';
   import {generateKeyPairSync,randomBytes} from 'node:crypto';
   import * as grpc from '@grpc/grpc-js';
   import {REPOSITORY_SAFE_EXAMPLES as e} from 'sos-data-utils-ts/repository-privacy';
   const require=createRequire(import.meta.url);const packagePath=require.resolve('@hyperledger/fabric-gateway');
   const transport=await import(process.env.SOS_FABRIC_TRANSPORT_PROOF_MODULE);
   assert.equal(Boolean(require.cache[packagePath]),false,'memory-capable import initialized Fabric');
   const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
   process.env.HLF_CERTIFICATE=e.didWeb; // Explicit synthetic bytes for constructor proof, never an issued certificate.
   process.env.HLF_PRIVATE_KEY=pair.privateKey.export({type:'pkcs8',format:'pem'});
   const client=new grpc.Client('127.0.0.1:1',grpc.credentials.createInsecure());
   let gateway;
   try {
    const options=await transport.newConnectOptions(client,e.tenantId);
    assert.ok(require.cache[packagePath],'explicit signer did not load the authoritative package');
    const digest=randomBytes(32);const signature=await options.signer(digest);
    const {p256}=await import('@noble/curves/nist.js');const publicJwk=pair.publicKey.export({format:'jwk'});
    const publicPoint=Buffer.concat([Buffer.from([4]),Buffer.from(publicJwk.x,'base64url'),Buffer.from(publicJwk.y,'base64url')]);
    assert.equal(p256.verify(signature,digest,publicPoint,{format:'der',prehash:false}),true);
    digest[0]^=1;assert.equal(p256.verify(signature,digest,publicPoint,{format:'der',prehash:false}),false);
    gateway=await transport.newGatewayConnection(client,e.tenantId);
    assert.equal(gateway.getIdentity().mspId,e.tenantId);
    assert.deepEqual(Buffer.from(gateway.getIdentity().credentials),Buffer.from(e.didWeb));
    assert.equal(gateway.getNetwork('identity-global').getName(),'identity-global');
   } finally {gateway?.close();client.close();}
   console.log('fabric-runtime-boundary:ok');
  `;
  try{
   const child=spawnSync(process.execPath,['--input-type=module','-e',source],{cwd:process.cwd(),encoding:'utf8',timeout:20000,env:{...process.env,NODE_OPTIONS:'',NETWORK_MODE:'test',NODE_ENV:'test',SOS_FABRIC_TRANSPORT_PROOF_MODULE:pathToFileURL(join(artifact,'connect.js')).href}});
   if(child.status!==0)throw new Error(child.stderr||String(child.error));
   expect(child.stdout).toContain('fabric-runtime-boundary:ok');
  }finally{rmSync(artifact,{recursive:true,force:true});}
 },25000);
});
