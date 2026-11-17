// Flow contract: controller bearer proofs verify real ML-DSA signatures with the tenant's stored key; altered bytes or caller-supplied keys never replace that authority. Repository/KMS reads are bounded state fixtures, not signature-engine doubles.
import { AppAuthorizationManager } from '../../../managers/AppAuthorizationManager';
import { CryptographyService, Content, type MldsaAlg } from 'antifraud-data-utils-ts/cryptography';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { REPOSITORY_SAFE_EXAMPLES as examples } from 'sos-data-utils-ts/repository-privacy';

const cryptography = new CryptographyService(new AdapterCryptoSdkNode());
const issuer = `${examples.didWeb}:controller`;
const vaultId = examples.tenantId;
type Pair = Awaited<ReturnType<typeof cryptography.generateKeyPairMlDsa>>;
let trusted: Record<string, Pair>;
let attacker: Pair;
beforeAll(async () => {
  trusted = {};
  for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as MldsaAlg[]) trusted[alg] = await cryptography.generateKeyPairMlDsa(undefined, alg);
  attacker = await cryptography.generateKeyPairMlDsa(undefined, 'ML-DSA-44');
});
const claims = () => ({ iss: issuer, vp: { holder: issuer }, exp: Math.floor(Date.now() / 1000) + 120 });
async function token(pair: Pair, header: Record<string, unknown> = {}, payload = claims()) {
  return cryptography.jwsToCompact(await cryptography.signDataJws(payload, { alg: pair.publicJWKey.alg, kid: pair.publicJWKey.kid, ...header }, pair.secretKeyBytes));
}
function manager(pair: Pair) {
  const employee = { didDocument: { id: issuer, verificationMethod: [{ id: `${issuer}#${pair.publicJWKey.kid}`, publicKeyJwk: pair.publicJWKey }] } };
  const repository = { query: jest.fn(async () => [{ id: examples.resourceUuid }]) };
  const kms = { getHmacBase64Url: jest.fn(async (value: string) => value), unprotectConfidentialData: jest.fn(async () => employee) };
  return new AppAuthorizationManager(repository as any, { verify: async () => ({ valid: false, error: 'No external identity supplied.' }) }, kms as any, cryptography);
}
for (const algorithm of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  test(`${algorithm} genuine registered proof verifies without mandatory JWT iat/jti`, async () => {
    const pair = trusted[algorithm];
    await expect(manager(pair).verifyBearerToken(await token(pair), undefined, { vaultId })).resolves.toMatchObject({ valid: true, payload: { iss: issuer, vp: { holder: issuer } } });
  });
  test(`${algorithm} changed payload is rejected`, async () => {
    const pair = trusted[algorithm]; const parts = (await token(pair)).split('.');
    parts[1] = Content.objectToRawBase64UrlSafe({ ...claims(), vp: { holder: `${issuer}:attacker` } });
    await expect(manager(pair).verifyBearerToken(parts.join('.'), undefined, { vaultId })).rejects.toThrow(/signature/i);
  });
  test(`${algorithm} corrupted signature is rejected`, async () => {
    const pair = trusted[algorithm]; const parts = (await token(pair)).split('.');
    const bytes = Content.base64ToBytes(parts[2]); bytes[0] ^= 1;
    parts[2] = Content.bytesToRawBase64UrlSafe(bytes);
    await expect(manager(pair).verifyBearerToken(parts.join('.'), undefined, { vaultId })).rejects.toThrow(/signature/i);
  });
}
test('attacker embedded JWK cannot replace the registered controller key', async () => {
  const pair = trusted['ML-DSA-44'];
  const compact = await token(attacker, { kid: pair.publicJWKey.kid, jwk: { ...attacker.publicJWKey, kid: pair.publicJWKey.kid } });
  await expect(manager(pair).verifyBearerToken(compact, undefined, { vaultId })).rejects.toThrow(/signature/i);
});
test('PQC proof without any public verification key is rejected', async () => {
  await expect(manager(trusted['ML-DSA-44']).verifyBearerToken(await token(trusted['ML-DSA-44']))).rejects.toThrow(/key|JWK/i);
});
test('a critical JWT extension is rejected even with a genuine PQ signature', async () => {
  const pair = trusted['ML-DSA-44'];
  const compact = await token(pair, { crit: ['unrecognized'], unrecognized: true });
  await expect(manager(pair).verifyBearerToken(compact, undefined, { vaultId })).rejects.toThrow(/critical|extension/i);
});
