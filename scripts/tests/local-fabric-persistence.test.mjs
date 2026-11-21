// Flow contract: prepare a private PostgreSQL/IPFS overlay for local Fabric,
// preserve its encryption and database secrets across reuse, and leave the base
// Fabric profile untouched.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { parseEnv, promisify } from 'node:util';

const root = resolve(import.meta.dirname, '../..');
const execute = promisify(execFile);

test('prepares and reuses the local Fabric persistence overlay', async () => {
  const logs = resolve(root, 'logs');
  await mkdir(logs, { recursive: true });
  const directory = await mkdtemp(resolve(logs, 'fabric-persistence-contract-'));
  try {
    const base = resolve(directory, 'fabric.env');
    const overlay = resolve(directory, 'durable.env');
    const fabricProfile = 'NETWORK_MODE=local-network\nNODE_ENV=test\nDB_PROVIDER=mem\n';
    await writeFile(base, fabricProfile);
    const args = ['scripts/prepare-local-fabric-persistence.mjs', base, overlay];
    const prepared = await execute(process.execPath, args, { cwd: root });
    const original = await readFile(overlay, 'utf8');
    const env = parseEnv(original);
    assert.equal(env.DB_PROVIDER, 'postgres');
    assert.equal(env.STORAGE_PROVIDER, 'ipfs');
    assert.equal(env.KMS_PROVIDER, 'local');
    assert.equal(Buffer.from(env.KEK_SECRET, 'base64').length, 32);
    assert.equal(env.POSTGRES_HOST, '127.0.0.1');
    assert.equal(new URL(env.IPFS_API_URL).hostname, '127.0.0.1');
    assert.equal((await stat(overlay)).mode & 0o777, 0o600);
    assert.ok(!prepared.stdout.includes(env.KEK_SECRET));
    assert.ok(!prepared.stdout.includes(env.POSTGRES_PASSWORD));
    await execute(process.execPath, args, { cwd: root });
    assert.equal(await readFile(overlay, 'utf8'), original);
    assert.equal(await readFile(base, 'utf8'), fabricProfile);
    await writeFile(base, 'NETWORK_MODE=test-network\n');
    await assert.rejects(execute(process.execPath, args, { cwd: root }), /NETWORK_MODE=local-network/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
