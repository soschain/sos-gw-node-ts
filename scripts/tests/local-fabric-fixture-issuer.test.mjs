// Flow contract: the local Fabric image harness uses explicitly synthetic,
// asymmetric ICA credentials bound to its real controller key. Current status
// is checked for the exact issued identifier; unknown and revoked never pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';
import canonicalize from 'canonicalize';
import { verifyPinnedDetachedJws } from 'antifraud-data-utils-ts/clearing-house';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';

const load = () => import('../local-fabric-fixture-issuer.mjs');
async function fixture() {
  const { createLocalFabricFixtureIssuer } = await load();
  const pair = await generateKeyPair('ES384');
  const controllerJwk = { ...await exportJWK(pair.publicKey), alg: 'ES384', kid: 'fixture-controller', use: 'sig' };
  const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk });
  return { issuer, controllerJwk };
}

test('issues the canonical three-credential set with genuine asymmetric signatures', async () => {
  const { issuer } = await fixture();
  assert.equal(issuer.credentials.length, 3);
  for (const credential of issuer.credentials) {
    assert.equal(credential.issuer, `${e.didWeb}:ica`);
    const unsigned = { ...credential }; delete unsigned.proof;
    await verifyPinnedDetachedJws(new TextEncoder().encode(canonicalize(unsigned)), credential.proof.jws, issuer.jwks.keys[0]);
    await assert.rejects(verifyPinnedDetachedJws(new TextEncoder().encode(canonicalize({ ...unsigned, id: `${unsigned.id}:altered` })), credential.proof.jws, issuer.jwks.keys[0]));
  }
});

test('fixture credential status is exact and revocation cannot become good', async () => {
  const { issuer } = await fixture();
  const id = issuer.credentials[0].id;
  assert.equal(issuer.status(id), 'good');
  assert.equal(issuer.status(`${id}:unknown`), 'unknown');
  issuer.revoke(id);
  assert.equal(issuer.status(id), 'revoked');
});

test('refuses creation for a deployed profile or private controller key', async () => {
  const { createLocalFabricFixtureIssuer } = await load();
  await assert.rejects(createLocalFabricFixtureIssuer({ profile: 'test-network', controllerJwk: {} }), /local/i);
  await assert.rejects(createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk: { kty: 'EC', d: 'private' } }), /public/i);
});

test('local OIDC proof is signed, audience-bound and contains no tenant authority', async () => {
  const { issuer } = await fixture();
  const { jwtVerify, createLocalJWKSet } = await import('jose');
  const origin = 'https://127.0.0.1:3210';
  const compact = await issuer.mintOidc({ issuer: origin, subject: 'fixture-controller-account', email: e.firstContactEmail, audience: 'local-image-gateway' });
  const { payload } = await jwtVerify(compact, createLocalJWKSet(issuer.jwks), { issuer: origin, audience: 'local-image-gateway' });
  assert.equal(payload.email, e.firstContactEmail); assert.equal(payload.email_verified, true);
  for (const claim of ['role', 'tenant_id', 'permissions']) assert.equal(payload[claim], undefined);
  await assert.rejects(jwtVerify(compact, createLocalJWKSet(issuer.jwks), { audience: 'another-recipient' }));
  await assert.rejects(issuer.mintOidc({ issuer: 'https://example.invalid', subject: 'fixture', email: e.firstContactEmail, audience: 'local-image-gateway' }), /local/i);
});

test('canonical fixture credentials bind a real post-quantum controller public key', async () => {
  const { createLocalFabricFixtureIssuer } = await load();
  const { CryptographyService } = await import('antifraud-data-utils-ts/cryptography');
  const { randomBytes, createHash, randomUUID } = await import('node:crypto');
  const { toJwkThumbprintSha256Urn } = await import('antifraud-data-utils-ts/jwk-thumbprints');
  const crypto = new CryptographyService({ getRandomBytes: async size => randomBytes(size), randomUUID,
    digestString: async (value, algorithm) => createHash(algorithm.replaceAll('-', '').toLowerCase()).update(value).digest('hex') });
  const pair = await crypto.generateKeyPairMlDsa(undefined, 'ML-DSA-65');
  const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk: pair.publicJWKey });
  assert.equal(issuer.credentials[2].credentialSubject.owner.hasCredential.material, toJwkThumbprintSha256Urn(pair.publicJWKey));
});

test('preserves the SDK-derived organization DID without substituting fixture authority', async () => {
  const { createLocalFabricFixtureIssuer } = await load();
  const pair = await generateKeyPair('ES384');
  const controllerJwk = { ...await exportJWK(pair.publicKey), alg: 'ES384' };
  const organizationDid = `${e.didWeb}:issued-organization`;
  const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk, organizationDid });
  assert.equal(issuer.credentials[0].credentialSubject.id, organizationDid);
  await assert.rejects(createLocalFabricFixtureIssuer({ profile: 'local-fabric', controllerJwk, organizationDid: 'javascript:invalid' }), /DID/i);
});

test('deferred fixture keeps its signing identity while issuing after actual host readback', async () => {
  const { createLocalFabricFixtureIssuer } = await load();
  const issuer = await createLocalFabricFixtureIssuer({ profile: 'local-fabric', deferIssuance: true });
  assert.equal(issuer.credentials.length, 0);
  const key = issuer.jwks.keys[0];
  const pair = await generateKeyPair('ES384');
  const organizationDid = `${e.didWeb}:post-readback-organization`;
  await issuer.issueOrganizationSet({ controllerJwk: { ...await exportJWK(pair.publicKey), alg: 'ES384' }, organizationDid });
  assert.equal(issuer.credentials.length, 3); assert.deepEqual(issuer.jwks.keys[0], key);
  assert.equal(issuer.credentials[0].credentialSubject.id, organizationDid);
  assert.equal(issuer.status(issuer.credentials[0].id), 'good');
});
