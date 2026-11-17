// Flow contract: native Node runtime loads the public PKI module and derived P-384 keys verify genuine signatures while rejecting tampering, without a Jest loader or a dependency downgrade.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { deriveKeyPair } from '../../src/utils/pki.ts';

test('native loader preserves usable PKI P-384 key derivation', async () => {
  const pair = await deriveKeyPair(randomBytes(32), 'P-384');
  const privateKey = createPrivateKey({ key: pair.jwk, format: 'jwk' });
  const publicKey = createPublicKey(privateKey);
  const payload = randomBytes(32);
  const signature = sign('sha384', payload, privateKey);
  assert.equal(verify('sha384', payload, publicKey, signature), true);
  const altered = Buffer.from(payload); altered[0] ^= 1;
  assert.equal(verify('sha384', altered, publicKey, signature), false);
});
