import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import canonicalize from 'canonicalize';
import { calculateJwkThumbprint } from 'jose';
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

function createReader(fetchDocument) {
  return async address => {
    const response = await fetchDocument(address, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200, `${address.href} returned HTTP ${response.status}`);
    const body = Buffer.from(await response.arrayBuffer());
    return { body, json: JSON.parse(body.toString('utf8')) };
  };
}

function authorizedKey(document, kid) {
  const methodId = kid.includes('#') ? kid : `${document.id}#${kid}`;
  const assertions = document.assertionMethod ?? [];
  if (!assertions.some(method => (typeof method === 'string' ? method : method.id) === methodId)) return undefined;
  return [...(document.verificationMethod ?? []), ...assertions.filter(entry => typeof entry === 'object')]
    .find(entry => entry.id === methodId)?.publicKeyJwk;
}

async function assertionKey(read, did, kid, icaOrigins) {
  assert.ok(typeof kid === 'string' && kid.length, 'Missing signing key ID');
  if (did.startsWith('did:jwt:')) {
    for (const origin of icaOrigins) {
      const { json: document } = await read(checkUrl(new URL('/.well-known/did.json', origin)));
      const key = authorizedKey(document, kid);
      if ((document.alsoKnownAs ?? []).includes(did) && key && `did:jwt:${await calculateJwkThumbprint(key)}` === did) return key;
    }
    throw new Error(`No trusted ICA assertion key for ${did}`);
  }
  const { json: document } = await read(didUrl(did));
  assert.equal(document.id, did, 'Unexpected DID document');
  const key = authorizedKey(document, kid);
  assert.ok(key, `Key ${kid} is not authorized for assertion`);
  return key;
}

async function verifyCredentialProofs(credential, read, icaOrigins) {
  const { proof, ...unsigned } = credential;
  const proofs = Array.isArray(proof) ? proof : [proof];
  assert.ok(proofs.length && proofs.some(entry => entry?.verificationMethod?.startsWith(`${credential.issuer}#`)),
    'Credential issuer proof is missing');
  for (const entry of proofs) {
    const [did, kid] = entry?.verificationMethod?.split('#') ?? [];
    assert.ok(did && kid, 'Proof is missing its DID verification method');
    const key = await assertionKey(read, did, kid, icaOrigins);
    const detached = entry.jws ?? entry.proofValue;
    assert.ok(typeof detached === 'string' && detached.split('.').length === 3, 'Unsupported credential proof');
    const [header, payload, signature] = detached.split('.');
    assert.equal(payload, '', 'Expected a detached credential proof');
    const headerKey = decode(header).kid;
    assert.ok(headerKey === undefined || headerKey === kid || headerKey === entry.verificationMethod, 'Proof key ID differs from its verification method');
    if (decode(header).b64 === false || did.startsWith('did:jwt:')) {
      await verifyPinnedDetachedJws(Buffer.from(canonicalize(unsigned)), detached, { ...key, kid: headerKey }, crypto);
    } else {
      const encoded = Buffer.from(JSON.stringify(unsigned)).toString('base64url');
      assert.ok(await crypto.verifyJws(`${header}.${encoded}.${signature}`, key), 'Credential signature verification failed');
    }
  }
  return proofs.length;
}

async function verifyOrganizationDocument(credential, read, icaOrigins) {
  assert.ok(credential.type?.includes('OrganizationCredential'), 'Missing OrganizationCredential type');
  assert.equal(credential.credentialSubject?.['@type'], 'Organization');
  const identifier = credential.credentialSubject.taxID ?? credential.credentialSubject.identifier?.value;
  assert.ok(typeof identifier === 'string' && identifier.trim(), 'Missing organization identifier');
  const proofCount = await verifyCredentialProofs(credential, read, icaOrigins);
  return { issuer: credential.issuer, identifier, evidence: Boolean(credential.evidence?.length),
    selfSigned: credential.issuer === credential.credentialSubject.id, proofs: proofCount };
}

export async function verifyOrganizationArtifact(address, { icaOrigins = [], fetchDocument = fetch } = {}) {
  const read = createReader(fetchDocument);
  const { json: credential } = await read(checkUrl(new URL(address)));
  return verifyOrganizationDocument(credential, read, icaOrigins);
}

export async function verifyOrganizationPublication(base, kind, fetchDocument = fetch, icaOrigins = []) {
  const url = checkUrl(new URL(base));
  url.pathname = `${url.pathname.replace(/\/$/, '')}/.well-known/`;
  assert.ok(!url.search && !url.hash, 'Pass a scoped base URL without a query or fragment');
  const read = createReader(fetchDocument);
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
  assert.ok(await crypto.verifyJws(token, await assertionKey(read, claims.issuer, decode(protectedHeader).kid, icaOrigins)),
    'Participant JWT signature verification failed');

  const verifiedJson = ['vc.json', 'self-description.json'];
  for (const filename of verifiedJson) {
    const { json } = await read(new URL(filename, url));
    assert.equal(json.credentialSubject?.type ?? json.credentialSubject?.['@type'], 'gx:LegalPerson', `${filename} must describe a Gaia-X LegalPerson`);
    assert.equal(json.issuer, claims.issuer, `${filename} issuer differs from the JWT participant`);
    assert.equal(json.credentialSubject.id, claims.credentialSubject.id, `${filename} describes a different participant`);
    await verifyCredentialProofs(json, read, icaOrigins);
  }

  const organizationUrl = new URL('organization.json', url);
  const { body, json: credential } = await read(organizationUrl);
  const { selfSigned, proofs } = await verifyOrganizationDocument(credential, read, icaOrigins);
  if (selfSigned) {
    assert.equal(kind, 'host', 'Tenant credential must have an independent issuer');
    assert.equal(credential.issuer, claims.issuer, 'Self-signed organization must identify the host');
  }

  const related = claims.relatedResource?.find(resource => resource.id?.endsWith('/organization.json'));
  if (related) {
    assert.equal(related.id, organizationUrl.href, 'Unexpected organization evidence URL');
    assert.equal(related.digestSRI, `sha256-${createHash('sha256').update(body).digest('base64')}`, 'Organization credential digest differs');
    assert.equal(claims.credentialSubject['https://schema.org/taxID'], credential.credentialSubject.taxID, 'Fiscal identifiers differ');
    assert.ok(!selfSigned && credential.evidence?.length, 'The signed evidence link must refer to an ICA credential with evidence');
  }
  return { kind, url: base, issuer: credential.issuer, selfSigned, proofs, verifiedJson, linkedEvidence: Boolean(related) };
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] ?? '.')).href) {
  const { values } = parseArgs({ options: {
    host: { type: 'string', multiple: true },
    tenant: { type: 'string', multiple: true },
    organization: { type: 'string', multiple: true },
    ica: { type: 'string', multiple: true },
  } });
  const scopes = [['host', values.host ?? []], ['tenant', values.tenant ?? []]];
  if (!values.organization?.length && !scopes.some(([, urls]) => urls.length)) {
    console.error('Usage: node scripts/verify-organization-publications.mjs --host <base> --tenant <base> or --organization <credential-url> --ica <trusted-ica-origin>');
    process.exitCode = 1;
  }
  for (const [kind, urls] of scopes) {
    for (const url of urls) {
      try {
        console.log(JSON.stringify(await verifyOrganizationPublication(url, kind, fetch, values.ica ?? [])));
      } catch (error) {
        console.error(`${kind} ${url}: ${error.message}`);
        process.exitCode = 1;
      }
    }
  }
  for (const url of values.organization ?? []) {
    try {
      console.log(JSON.stringify({ url, ...await verifyOrganizationArtifact(url, { icaOrigins: values.ica }) }));
    } catch (error) {
      console.error(`organization ${url}: ${error.message}`);
      process.exitCode = 1;
    }
  }

}
