import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import canonicalize from 'canonicalize';
import { verifyPinnedDetachedJws } from 'antifraud-data-utils-ts/clearing-house';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';

const context = 'https://www.w3.org/ns/credentials/v2';
const jwtPrefix = 'data:application/vc+jwt,';
const crypto = new CryptographyService({
  getRandomBytes: async size => randomBytes(size),
  randomUUID,
  digestString: async (value, algorithm) => createHash(algorithm.replaceAll('-', '').toLowerCase()).update(value).digest('hex'),
});

function checkUrl(url) {
  assert.ok(!url.username && !url.password, 'URLs must not contain credentials');
  assert.ok(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)),
    'HTTPS is required except on localhost or 127.0.0.1');
  return url;
}

function didUrl(did) {
  assert.ok(typeof did === 'string' && did.startsWith('did:web:'), 'Expected a did:web signer');
  const [authority, ...path] = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  const url = new URL(`https://${authority}`);
  assert.equal(url.host, authority, 'Invalid did:web authority');
  if (['localhost', '127.0.0.1'].includes(url.hostname)) url.protocol = 'http:';
  url.pathname = path.length ? `/${path.map(encodeURIComponent).join('/')}/did.json` : '/.well-known/did.json';
  return checkUrl(url);
}

function decode(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

export async function verifyOrganizationPublication(base, kind, fetchDocument = fetch) {
  const url = checkUrl(new URL(base));
  url.pathname = `${url.pathname.replace(/\/$/, '')}/.well-known/`;
  assert.ok(!url.search && !url.hash, 'Pass a scoped base URL without a query or fragment');
  async function read(address) {
    const response = await fetchDocument(address, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200, `${address.href} returned HTTP ${response.status}`);
    const body = Buffer.from(await response.arrayBuffer());
    return { body, json: JSON.parse(body.toString('utf8')) };
  }

  async function assertionKey(did, kid) {
    assert.ok(typeof kid === 'string' && kid.length, 'Missing signing key ID');
    const { json: document } = await read(didUrl(did));
    assert.equal(document.id, did, 'Unexpected DID document');
    const methodId = kid.includes('#') ? kid : `${did}#${kid}`;
    const assertions = document.assertionMethod ?? [];
    assert.ok(assertions.some(method => (typeof method === 'string' ? method : method.id) === methodId),
      `Key ${methodId} is not authorized for assertion`);
    const method = [...(document.verificationMethod ?? []), ...assertions.filter(entry => typeof entry === 'object')]
      .find(entry => entry.id === methodId);
    assert.ok(method?.publicKeyJwk, `Missing public JWK for ${methodId}`);
    return { ...method.publicKeyJwk, kid: method.publicKeyJwk.kid ?? kid };
  }

  const participant = await read(new URL('legal-participant.vc.json', url));
  assert.deepEqual(Object.keys(participant.json).sort(), ['@context', 'id', 'type'], 'Unexpected JWT envelope fields');
  assert.equal(participant.json['@context'], context);
  assert.equal(participant.json.type, 'EnvelopedVerifiableCredential');
  assert.ok(participant.json.id.startsWith(jwtPrefix), 'Missing JWT in the top-level id');
  const token = participant.json.id.slice(jwtPrefix.length);
  const [protectedHeader, encodedClaims, signature] = token.split('.');
  assert.ok(protectedHeader && encodedClaims && signature && token.split('.').length === 3, 'Invalid compact JWS');
  const claims = decode(encodedClaims);
  assert.equal(claims.credentialSubject?.type ?? claims.credentialSubject?.['@type'], 'gx:LegalPerson');
  assert.equal(claims.issuer, claims.credentialSubject.id, 'The participant declaration must be signed by the participant');
  assert.ok(await crypto.verifyJws(token, await assertionKey(claims.issuer, decode(protectedHeader).kid)),
    'Participant JWT signature verification failed');

  const organizationUrl = new URL('organization.json', url);
  const { body, json: credential } = await read(organizationUrl);
  const { proof, ...unsigned } = credential;
  assert.ok(credential.type?.includes('OrganizationCredential'), 'Missing OrganizationCredential type');
  assert.equal(credential.credentialSubject?.['@type'], 'Organization');
  const identifier = credential.credentialSubject.taxID ?? credential.credentialSubject.identifier?.value;
  assert.ok(typeof identifier === 'string' && identifier.trim(), 'Missing organization identifier');
  const selfSigned = credential.issuer === credential.credentialSubject.id;
  if (selfSigned) {
    assert.equal(kind, 'host', 'Tenant credential must have an independent issuer');
    assert.equal(credential.issuer, claims.issuer, 'Self-signed organization must identify the host');
  }
  const proofs = Array.isArray(proof) ? proof : [proof];
  assert.ok(proofs.length && proofs.some(entry => entry?.verificationMethod?.startsWith(`${credential.issuer}#`)),
    'Organization credential issuer proof is missing');
  for (const entry of proofs) {
    const [signer, keyId] = entry?.verificationMethod?.split('#') ?? [];
    const key = await assertionKey(signer, keyId);
    const detached = entry.jws ?? entry.proofValue;
    assert.ok(typeof detached === 'string' && detached.split('.').length === 3, 'Unsupported organization proof');
    const [header, payload, value] = detached.split('.');
    assert.equal(payload, '', 'Expected a detached organization proof');
    if (decode(header).b64 === false) {
      await verifyPinnedDetachedJws(new TextEncoder().encode(canonicalize(unsigned)), detached, key, crypto);
    } else {
      const encoded = Buffer.from(JSON.stringify(unsigned)).toString('base64url');
      assert.ok(await crypto.verifyJws(`${header}.${encoded}.${value}`, key), 'Organization signature verification failed');
    }
  }

  const related = claims.relatedResource?.find(resource => resource.id?.endsWith('/organization.json'));
  if (related) {
    assert.equal(related.id, organizationUrl.href, 'Unexpected organization evidence URL');
    assert.equal(related.digestSRI, `sha256-${createHash('sha256').update(body).digest('base64')}`, 'Organization credential digest differs');
    assert.equal(claims.credentialSubject['https://schema.org/taxID'], credential.credentialSubject.taxID, 'Fiscal identifiers differ');
    assert.ok(!selfSigned && credential.evidence?.length, 'The signed evidence link must refer to an ICA credential with evidence');
  }
  return { kind, url: base, issuer: credential.issuer, selfSigned, proofs: proofs.length, linkedEvidence: Boolean(related) };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] ?? '.')).href) {
  const { values } = parseArgs({ options: {
    host: { type: 'string', multiple: true },
    tenant: { type: 'string', multiple: true },
  } });
  const scopes = [['host', values.host ?? []], ['tenant', values.tenant ?? []]];
  if (!scopes.some(([, urls]) => urls.length)) {
    console.error('Usage: node scripts/verify-organization-publications.mjs --host <scoped-base-url> --tenant <scoped-base-url>');
    process.exitCode = 1;
  }
  for (const [kind, urls] of scopes) {
    for (const url of urls) {
      try {
        console.log(JSON.stringify(await verifyOrganizationPublication(url, kind)));
      } catch (error) {
        console.error(`${kind} ${url}: ${error.message}`);
        process.exitCode = 1;
      }
    }
  }
}
