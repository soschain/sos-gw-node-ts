// Flow contract: a process seals a synthetic document through the real vault;
// a separate process reopens it and compares decrypted bytes, then cleans up
// its own record and blob. The services can be restarted between invocations.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { FlattenedEncrypt, flattenedDecrypt } from 'jose';
import pg from 'pg';
import { buildExampleConfidentialStorageDoc } from 'sos-data-utils-ts/gateway-resource-flow-examples';
import { PostgresVaultRepository } from '../../build/database/repositories/postgres/postgres.vault.repository.js';
import { ensurePostgresVaultSchema } from '../../build/database/repositories/postgres/postgres.schema.js';
import { IpfsStorageAdapter } from '../../build/database/storage/ipfs.storage.adapter.js';
import { StorageAdapterConfidentialBlobStore } from '../../build/database/storage/storage-adapter-confidential-blob.store.js';
import { AesGcmEnvelopeAdapter } from '../../build/services/kms-envelope-adapter.js';

const [action, fixtureId] = process.argv.slice(2);
assert.ok(['write', 'read'].includes(action) && /^[a-f0-9]{32}$/.test(fixtureId ?? ''), 'Pass write or read and the same 32-hex fixture identifier.');
const env = process.env;
assert.equal(env.DB_PROVIDER, 'postgres');
assert.equal(env.STORAGE_PROVIDER, 'ipfs');
assert.equal(env.KMS_PROVIDER, 'local');
assert.equal(env.POSTGRES_HOST, '127.0.0.1');
assert.equal(env.POSTGRES_DB, 'vault');
assert.equal(env.POSTGRES_USER, 'vault');
assert.equal(env.IPFS_MFS_ROOT, '/gateway/blobs');
for (const value of [env.IPFS_API_URL, env.IPFS_GATEWAY_URL]) assert.equal(new URL(value).hostname, '127.0.0.1');

const schema = 'storage_probe_' + fixtureId;
const documentId = fixtureId;
const payload = Buffer.from(JSON.stringify({ localStorageProbe: fixtureId }));
const pool = new pg.Pool({
  host: env.POSTGRES_HOST, port: Number(env.POSTGRES_PORT), database: env.POSTGRES_DB,
  user: env.POSTGRES_USER, password: env.POSTGRES_PASSWORD, connectionTimeoutMillis: 5000,
});
const blobStore = new StorageAdapterConfidentialBlobStore(new IpfsStorageAdapter({
  apiUrl: env.IPFS_API_URL, gatewayUrl: env.IPFS_GATEWAY_URL, mfsRoot: env.IPFS_MFS_ROOT,
}), 'ipfs');
const envelope = new AesGcmEnvelopeAdapter(env.KEK_SECRET);
const repository = new PostgresVaultRepository(pool, schema, schema, blobStore);

try {
  if (action === 'write') {
    await ensurePostgresVaultSchema(pool, schema);
    const key = randomBytes(32);
    try {
      const jwe = await new FlattenedEncrypt(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(key);
      const wrappedProbeKey = await envelope.wrapKeyMaterial(key);
      assert.ok(await repository.put(schema, [buildExampleConfidentialStorageDoc({ id: documentId, jwe, wrappedProbeKey })]));
    } finally {
      key.fill(0);
    }
  }

  const result = await pool.query(`SELECT payload_json FROM "${schema}".vault_documents WHERE document_id = $1`, [documentId]);
  assert.equal(result.rowCount, 1);
  const stored = result.rows[0].payload_json;
  assert.equal(stored.jwe, undefined);
  assert.equal(stored.blob?.provider, 'ipfs');
  assert.ok(stored.blob.blobRef);
  assert.ok(!JSON.stringify(stored).includes(payload.toString()));

  if (action === 'read') {
    const document = await repository.get(schema, documentId);
    const key = await envelope.unwrapKeyMaterial(document.wrappedProbeKey);
    try {
      const { plaintext } = await flattenedDecrypt(document.jwe, key);
      assert.deepEqual(Buffer.from(plaintext), payload);
    } finally {
      key.fill(0);
    }
    assert.ok(await repository.delete(schema, documentId));
    assert.ok(await repository.purge(schema));
    assert.equal(await repository.get(schema, documentId), undefined);
    await blobStore.delete(stored.blob.blobRef);
    await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
    console.log('Recovered and decrypted the document byte-for-byte, then removed its isolated fixture.');
  } else {
    console.log('Stored the encrypted document in IPFS and its reference in PostgreSQL.');
  }
} finally {
  await pool.end();
}
