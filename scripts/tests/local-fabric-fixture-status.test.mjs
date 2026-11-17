// Flow contract: the synthetic local ICA uses real TLS and exact read-only
// status threads; unknown credentials are unknown and revocation wins. No live
// ICA, production certificate, credential store or cloud service is accessed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { request } from 'node:https';
import { generateKeyPair, exportJWK } from 'jose';
import { createLocalFabricFixtureIssuer } from '../local-fabric-fixture-issuer.mjs';

function post(url, body, ca) {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: body === undefined ? 'GET' : 'POST', ca, headers: { 'content-type': 'application/didcomm-plain+json' } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location,
        body: Buffer.concat(chunks).length ? JSON.parse(Buffer.concat(chunks)) : undefined }));
    }); req.on('error', reject); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

test('real TLS status lookup binds the exact thread, type list and credential ID', async () => {
  const { startLocalFabricFixtureStatusServer } = await import('../local-fabric-fixture-status.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'sos-local-ica-status-'));
  let server;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
    const pair = await generateKeyPair('ES384');
    const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk: { ...await exportJWK(pair.publicKey), alg: 'ES384' } });
    const ca = readFileSync(join(dir, 'cert.pem'));
    server = await startLocalFabricFixtureStatusServer({ profile: 'local-fabric', issuer,
      key: readFileSync(join(dir, 'key.pem')), cert: ca });
    const discovery = await post(`${server.origin}/.well-known/openid-configuration`, undefined, ca);
    assert.equal(discovery.status, 200); assert.equal(discovery.body.issuer, server.origin);
    assert.equal(discovery.body.jwks_uri, `${server.origin}/.well-known/jwks.json`);
    assert.equal((await post(discovery.body.jwks_uri, undefined, ca)).body.keys[0].alg, 'ES384');
    const credential = issuer.credentials[0];
    const url = `${server.origin}/credentials/${credential.type.join(',')}/_status`;
    const accepted = await post(url, { type: server.statusRequestType, thid: 'local-status-thread', body: { data: [{ credentialId: credential.id }] } }, ca);
    assert.equal(accepted.status, 202);
    assert.match(accepted.location, /^\/credentials\//, 'The same status origin must work from the container without a loopback redirect.');
    const poll = await post(new URL(accepted.location, server.origin), {}, ca);
    const result = poll.body.body.data[0].resource;
    assert.equal(result.thid, 'local-status-thread'); assert.equal(result.credentialType, credential.type.join(','));
    assert.equal(result.content[0].credentialId, credential.id); assert.equal(result.content[0].status, 'good');
    issuer.revoke(credential.id);
    const revoked = await post(url, { type: server.statusRequestType, thid: 'local-revoked-thread', body: { data: [{ credentialId: credential.id }] } }, ca);
    assert.equal((await post(new URL(revoked.location, server.origin), {}, ca)).body.body.data[0].resource.content[0].status, 'revoked');
    const unknown = await post(url, { type: server.statusRequestType, thid: 'local-unknown-thread', body: { data: [{ credentialId: `${credential.id}:unknown` }] } }, ca);
    assert.equal((await post(new URL(unknown.location, server.origin), {}, ca)).body.body.data[0].resource.content[0].status, 'unknown');
    assert.equal((await post(url, { type: 'invalid', thid: 'hostile', body: { data: [{ credentialId: credential.id }] } }, ca)).status, 400);
  } finally { if (server) await server.close(); rmSync(dir, { recursive: true, force: true }); }
});
