// Flow contract: reusing a prepared local Fabric gateway reads its disposable
// profile and checks readiness without provisioning, restarting or resetting services.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

const root = resolve(import.meta.dirname, '../..');
const execute = promisify(execFile);

test('reuse checks only the scoped health endpoint and leaves infrastructure alone', async () => {
  const runtime = resolve(root, 'logs');
  await mkdir(runtime, { recursive: true });
  const directory = await mkdtemp(resolve(runtime, 'fabric-reuse-test-'));
  const requests = [];
  const server = createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200).end();
  });

  try {
    await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
    const origin = 'http://127.0.0.1:' + server.address().port;
    const profile = resolve(directory, 'fabric.env');
    await writeFile(profile, 'NETWORK_MODE=local-network\nDB_PROVIDER=mem\nHOST_JURISDICTION=ES\n');
    const args = ['scripts/bootstrap-local-fabric-stack.mjs', '--reuse-fabric',
      '--env-file', profile, '--base-url', origin];
    const options = {
      cwd: root,
      timeout: 5_000,
      env: { ...process.env, FABRIC_DEVNET_ROOT: resolve(directory, 'absent-devnet') },
    };
    const result = await execute(process.execPath, args, options);
    assert.match(result.stdout, /existing local Fabric gateway reachable/i);
    assert.deepEqual(requests, ['/host/cds-es/v1/local-network/.well-known/ping']);

    await assert.rejects(execute(process.execPath, [...args, '--reset-fabric'], options),
      /cannot be combined/i);
    await writeFile(profile, 'NETWORK_MODE=test\n');
    await assert.rejects(execute(process.execPath, args, options),
      /NETWORK_MODE=local-network/);
    assert.equal(requests.length, 1);
  } finally {
    await new Promise(resolveClose => server.close(resolveClose));
    await rm(directory, { recursive: true, force: true });
  }
});
