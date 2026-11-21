// Prepare a storage-only overlay. The original Fabric and trust profile stays in place.
import { randomBytes } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';

async function prepare() {
  const [basePath, outputPath] = process.argv.slice(2);
  if (process.argv.length !== 4 || !basePath || !outputPath || resolve(basePath) === resolve(outputPath)) {
    throw new Error('Usage: prepare-local-fabric-persistence.mjs <existing Fabric profile> <private storage overlay>');
  }
  const base = parseEnv(await readFile(basePath, 'utf8'));
  if (base.NETWORK_MODE !== 'local-network' || base.NODE_ENV === 'production') {
    throw new Error('The base profile must use NETWORK_MODE=local-network and local custody.');
  }

  const postgresPort = port('LOCAL_FABRIC_POSTGRES_PORT', 15432);
  const ipfsApiPort = port('LOCAL_FABRIC_IPFS_API_PORT', 15001);
  const ipfsGatewayPort = port('LOCAL_FABRIC_IPFS_GATEWAY_PORT', 18080);
  if (new Set([postgresPort, ipfsApiPort, ipfsGatewayPort]).size !== 3) {
    throw new Error('The PostgreSQL, IPFS API and IPFS gateway ports must be distinct.');
  }
  const settings = {
    DB_PROVIDER: 'postgres',
    STORAGE_PROVIDER: 'ipfs',
    KMS_PROVIDER: 'local',
    POSTGRES_HOST: '127.0.0.1',
    POSTGRES_PORT: postgresPort,
    POSTGRES_DB: 'vault',
    POSTGRES_USER: 'vault',
    POSTGRES_SSL: 'false',
    IPFS_API_URL: `http://127.0.0.1:${ipfsApiPort}`,
    IPFS_GATEWAY_URL: `http://127.0.0.1:${ipfsGatewayPort}`,
    IPFS_MFS_ROOT: '/gateway/blobs',
    LOCAL_FABRIC_IPFS_API_PORT: ipfsApiPort,
    LOCAL_FABRIC_IPFS_GATEWAY_PORT: ipfsGatewayPort,
    CONFIDENTIAL_JWE_INLINE_MAX_BYTES: 1,
  };
  const secrets = {
    KEK_SECRET: randomBytes(32).toString('base64'),
    POSTGRES_PASSWORD: randomBytes(32).toString('hex'),
  };
  const contents = Object.entries({ ...settings, ...secrets }).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
  try {
    await writeFile(outputPath, contents, { flag: 'wx', mode: 0o600 });
    console.log('Created the private local PostgreSQL/IPFS overlay.');
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const metadata = await lstat(outputPath);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
      throw new Error('The existing storage overlay must be a private regular file.');
    }
    const existing = parseEnv(await readFile(outputPath, 'utf8'));
    if (Object.entries(settings).some(([key, value]) => existing[key] !== String(value))
      || !/^[A-Za-z0-9+/]{43}=$/.test(existing.KEK_SECRET ?? '')
      || !/^[a-f0-9]{64}$/.test(existing.POSTGRES_PASSWORD ?? '')) {
      throw new Error('The existing storage overlay does not match this configuration. It was preserved.');
    }
    console.log('Reusing the private local PostgreSQL/IPFS overlay.');
  }
}

function port(key, fallback) {
  const value = Number(process.env[key] ?? fallback);
  if (!Number.isInteger(value) || value < 1024 || value > 65535) throw new Error(`${key} is not a valid local port.`);
  return value;
}

prepare().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
