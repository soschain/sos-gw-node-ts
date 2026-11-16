// Flow contract: the unsigned ping response uses the existing process-owned crypto port throughout bootstrap and discovery routing, without a frozen serializer import.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('ping serialization receives the existing AF cryptography port through bootstrap and router',()=>{
 const handler=readFileSync(new URL('../../src/routes/handlers/discovery/ping.handler.ts',import.meta.url),'utf8');
 const router=readFileSync(new URL('../../src/routes/discovery.ts',import.meta.url),'utf8');
 const bootstrap=readFileSync(new URL('../../src/server.ts',import.meta.url),'utf8');
 assert.equal(handler.includes('gdc-common-utils-ts/utils/jwt'),false,'Ping still imports the frozen serializer');
 assert.match(handler,/Pick<ICryptography,\s*'jwsToCompact'>/u);
 assert.match(handler,/cryptography\.jwsToCompact\(/u);
 assert.match(router,/pingHandler\(cryptography\)/u);
 assert.match(bootstrap,/createDiscoveryRouter\(tenantManager, discoveryService, kmsService, logger, vaultRepository, cryptographyService\)/u);
});
