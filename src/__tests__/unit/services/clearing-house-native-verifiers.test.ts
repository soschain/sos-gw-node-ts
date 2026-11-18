// Flow contract: verify real credential and presentation signatures, re-read current key/status/permission evidence, reject the same token after revocation, and keep first-controller ICA authority separate from enrolled Fabric evidence. Synthetic data comes from the governed repository examples.
import { createServer, type Server } from 'node:http';
import canonicalize from 'canonicalize';
import { exportJWK, generateKeyPair, SignJWT, FlattenedSign, type JWK, type KeyLike } from 'jose';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { buildProfessionalEmployeeCredential } from 'sos-data-utils-ts/professional-smart';
import { toJwkThumbprintSha256Urn } from 'antifraud-data-utils-ts/jwk-thumbprints';
import { CredentialLedgerAdapterMem } from '../../../adapters/CredentialLedgerAdapterMem';
import { LedgerPresentationVerifier } from '../../../services/LedgerPresentationVerifier';
import { IcaActivationVerifier } from '../../../services/IcaActivationVerifier';
import { IcaCredentialStatusClient } from '../../../services/IcaCredentialStatusClient';

const acr = 'urn:antifraud:acr:openid4vp:employee';
const actorDid = `${e.didWeb}:employee`;
const issuerDid = `${e.didWeb}:ica`;
const holder = e.resourceUuid;
const now = Math.floor(Date.now() / 1000);
let holderPrivate: KeyLike;
let issuerPrivate: KeyLike;
let holderKey: JWK;
let issuerKey: JWK;
const listeners: Server[] = [];
const sign = (payload: Record<string, unknown>, key: KeyLike, jwk: JWK, embedded = false) => new SignJWT(payload)
  .setProtectedHeader({ alg: 'ES384', kid: jwk.kid, ...(embedded ? { jwk } : {}) }).sign(key);

beforeAll(async () => {
  const first = await generateKeyPair('ES384'); const second = await generateKeyPair('ES384');
  holderPrivate = first.privateKey; issuerPrivate = second.privateKey;
  holderKey = { ...await exportJWK(first.publicKey), kid: `${e.resourceUuid}-holder`, alg: 'ES384', use: 'sig' };
  issuerKey = { ...await exportJWK(second.publicKey), kid: `${e.resourceUuid}-issuer`, alg: 'ES384', use: 'sig' };
});
afterEach(async () => { while (listeners.length) await new Promise<void>(resolve => listeners.pop()!.close(() => resolve())); });

async function ledgerFixture(detached = false) {
  const identity = buildProfessionalEmployeeCredential({ actorDid, role: HealthcareActorRoles.GeneralistMedicalPractitioner, credentialMaterial: toJwkThumbprintSha256Urn(holderKey as any) });
  const credential = { ...identity, id: e.resourceUuid, issuer: issuerDid, validFrom: new Date((now - 60) * 1000).toISOString() };
  let input: unknown = await sign({ ...credential, iss: issuerDid }, issuerPrivate, issuerKey);
  if (detached) {
    const verificationMethod = `${issuerDid}#${issuerKey.kid}`;
    const proof = await new FlattenedSign(new TextEncoder().encode(canonicalize(credential)!))
      .setProtectedHeader({ alg: 'ES384', kid: verificationMethod, b64: false, crit: ['b64'] }).sign(issuerPrivate);
    input = { ...credential, proof: { verificationMethod, proofPurpose: 'assertionMethod', jws: `${proof.protected}..${proof.signature}` } };
  }
  const token = await sign({ iss: holder, aud: e.didWeb, iat: now, exp: now + 120, jti: e.resourceUuid, acr,
    vp: { holder, verifiableCredential: [input] } }, holderPrivate, holderKey);
  const ledger = new CredentialLedgerAdapterMem();
  ledger.seedStatus('test', { id: e.resourceUuid, issuer: issuerDid, status: 'active', updatedAt: now });
  let activeKey = true; let permitted = true;
  const options = { network: 'test', ledgerKind: 'memory' as const, ledger, now: () => now,
    resolveHolderKeys: async () => ({ keys: [holderKey] }), resolveIssuerKeys: async () => ({ keys: [issuerKey] }),
    assertActiveKey: async () => { if (!activeKey) throw new Error('Current signing key revoked.'); },
    authorize: async () => { if (!permitted) throw new Error('Current consent denied.'); } };
  return { verifier: new LedgerPresentationVerifier(options), options, ledger,
    request: { tenantDid: e.didWeb, vpToken: token, acrValues: [acr], tokenSubject: actorDid, tokenScope: 'subject-scoped-read' },
    revokeKey: () => { activeKey = false; }, deny: () => { permitted = false; } };
}

describe('native current-state presentation verifier', () => {
  it('checks real signatures and reports memory evidence without claiming Fabric', async () => {
    const f = await ledgerFixture();
    await expect(f.verifier.verifyVpToken(f.request)).resolves.toMatchObject({ ledgerVerified: true, trustChecks: { onChainChecked: false, revocationChecked: true } });
  });
  it('rejects a previously accepted credential after revocation', async () => {
    const f = await ledgerFixture(); await f.verifier.verifyVpToken(f.request);
    f.ledger.seedStatus('test', { id: e.resourceUuid, issuer: issuerDid, status: 'revoked', updatedAt: now });
    await expect(f.verifier.verifyVpToken(f.request)).rejects.toThrow(/active|revok/i);
  });
  it('rechecks current signing-key status and permissions', async () => {
    const first = await ledgerFixture(); first.revokeKey();
    await expect(first.verifier.verifyVpToken(first.request)).rejects.toThrow(/key|revok/i);
    const second = await ledgerFixture(); second.deny();
    await expect(second.verifier.verifyVpToken(second.request)).rejects.toThrow(/consent|denied/i);
  });
  it('verifies detached issuer proofs using their full verification-method identifier', async () => {
    const f = await ledgerFixture(true);
    await expect(f.verifier.verifyVpToken(f.request)).resolves.toMatchObject({ acr });
  });
  it('does not turn a network label into proof from a memory ledger', async () => {
    const f = await ledgerFixture();
    const verifier = new LedgerPresentationVerifier({ ...f.options, network: 'test-network' });
    await expect(verifier.verifyVpToken(f.request)).rejects.toThrow(/Fabric|authoritative/i);
  });
});

async function activationFixture(wrongBinding = false, missingController = false) {
  const issued = { issuer: issuerDid, validFrom: new Date((now - 60) * 1000).toISOString() };
  const credentials = [
    { ...issued, id: `${e.resourceUuid}-organization`, type: ['VerifiableCredential', 'OrganizationCredential'], credentialSubject: { taxID: e.organizationBusinessNumber } },
    { ...issued, id: `${e.resourceUuid}-representative`, type: ['VerifiableCredential', 'LegalRepresentativeCredential'], credentialSubject: { id: actorDid, hasOccupation: HealthcareActorRoles.GeneralistMedicalPractitioner, memberOf: { taxID: e.organizationBusinessNumber } } },
    { ...issued, id: `${e.resourceUuid}-controller`, type: ['VerifiableCredential', 'ServiceControllerCredential'], credentialSubject: { provider: { taxID: e.organizationBusinessNumber }, owner: { additionalType: HealthcareActorRoles.Controller, hasCredential: { material: toJwkThumbprintSha256Urn((wrongBinding ? issuerKey : holderKey) as any) } } } },
  ];
  if (missingController) credentials.pop();
  const signed = await Promise.all(credentials.map(credential => sign({ ...credential, iss: issuerDid }, issuerPrivate, issuerKey)));
  const vpToken = await sign({ iss: actorDid, aud: e.didWeb, iat: now, exp: now + 120, jti: e.resourceUuid, vp: { holder: actorDid, verifiableCredential: signed } }, holderPrivate, holderKey, true);
  let status = 'good'; let issuerStatus = 'active';
  const verifier = new IcaActivationVerifier({ hostDid: e.didWeb, resolveIssuer: async () => ({ jwks: { keys: [issuerKey] }, status: issuerStatus }), checkCredentialStatus: async () => ({ status }) });
  return { verifier, request: { tenantDid: e.didWeb, vpToken, acrValues: [acr] }, revoke: () => { status = 'revoked'; }, suspendIssuer: () => { issuerStatus = 'inactive'; } };
}
describe('native first-controller ICA authority', () => {
  it('accepts the signed ICA credential set and explicitly reports no Fabric check', async () => {
    const f = await activationFixture();
    await expect(f.verifier.verifyVpToken(f.request)).resolves.toMatchObject({ activationEvidenceSource: 'ica', ledgerVerified: false, trustChecks: { onChainChecked: false, revocationChecked: true } });
  });
  it('rejects current ICA revocation and an inactive issuer', async () => {
    const f = await activationFixture(); await f.verifier.verifyVpToken(f.request); f.revoke();
    await expect(f.verifier.verifyVpToken(f.request)).rejects.toThrow(/status|active/i);
    const other = await activationFixture(); other.suspendIssuer();
    await expect(other.verifier.verifyVpToken(other.request)).rejects.toThrow(/issuer|active/i);
  });
  it('requires the controller credential and the presentation signing-key binding', async () => {
    const f = await activationFixture(true); await expect(f.verifier.verifyVpToken(f.request)).rejects.toThrow(/key|binding/i);
    const other = await activationFixture(false, true); await expect(other.verifier.verifyVpToken(other.request)).rejects.toThrow(/incomplete|credential/i);
  });
});

it('uses a real read-only status listener and binds the full type list, thread and credential identifier', async () => {
  const credential = { id: e.resourceUuid, issuer: issuerDid, type: ['VerifiableCredential', 'OrganizationCredential'] };
  let origin = ''; let observedType = ''; let stale = false;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, origin);
    if (url.pathname.endsWith('/_status')) {
      const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const input = JSON.parse(Buffer.concat(chunks).toString()); observedType = input.type;
      const poll = new URL(url.pathname.replace(/_status$/, '_status-response'), origin);
      poll.searchParams.set('thid', input.thid);
      res.writeHead(202, { location: poll.href }); res.end();
    } else {
      res.setHeader('content-type', 'application/didcomm-plain+json');
      res.end(JSON.stringify({ body: { data: [{ response: { status: '200' }, resource: { status: 'resolved', thid: url.searchParams.get('thid'), credentialType: credential.type.join(','), content: [{ credentialId: credential.id, status: 'good', checkedAt: new Date(stale ? Date.now() - 60_000 : Date.now()).toISOString() }] } }] } }));
    }
  });
  listeners.push(server); server.listen(0, '127.0.0.1'); await new Promise<void>(resolve => server.once('listening', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('Owned listener did not start.');
  origin = `http://127.0.0.1:${address.port}`;
  const requestType = `${e.httpsBaseUrl}/credential-status-request`;
  const client = new IcaCredentialStatusClient({ resolveRequestType: () => requestType, allowLocalTestEndpoint: true, resolveEndpoint: () => `${origin}/${e.tenantId}/credentials/{credentialType}/_status` });
  await expect(client.check(credential)).resolves.toMatchObject({ status: 'good' });
  expect(observedType).toBe(requestType);
  stale = true;
  await expect(client.check(credential)).rejects.toThrow(/fresh/i);
});
