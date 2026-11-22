// Flow contract: verify public JWT and organization proofs for host and tenant without a shell.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { EXAMPLE_GATEWAY_PUBLIC_ORIGIN, EXAMPLE_PROVIDER_LEGAL_NAME } from 'sos-data-utils-ts/gateway-flow-examples';
import { verifyOrganizationPublication } from '../verify-organization-publications.mjs';

const crypto = new CryptographyService({
  getRandomBytes: async size => randomBytes(size), randomUUID,
  digestString: async (value, alg) => createHash(alg.replaceAll('-', '').toLowerCase()).update(value).digest('hex'),
});

test('checks exact JWT envelopes and all organization proofs for host and tenant', async () => {
  const origin = new URL(EXAMPLE_GATEWAY_PUBLIC_ORIGIN);
  const hostDid = `did:web:${origin.hostname}`;
  const icaDid = `${hostDid}:ica`;
  const tenantDid = `${hostDid}:tenant`;
  const context = 'https://www.w3.org/ns/credentials/v2';
  const documents = new Map();
  const signers = new Map();
  const taxID = 'A12345678';
  for (const [did, path] of [[hostDid, '/.well-known/did.json'], [icaDid, '/ica/did.json'], [tenantDid, '/tenant/did.json']]) {
    const signer = await crypto.generateKeyPairMlDsa();
    const id = `${did}#${signer.publicJWKey.kid}`;
    signers.set(did, signer);
    documents.set(path, { id: did, assertionMethod: [id], verificationMethod: [{ id, publicKeyJwk: signer.publicJWKey }] });
  }
  const sign = (claims, did) => {
    const { publicJWKey: { alg, kid }, secretKeyBytes } = signers.get(did);
    return crypto.signDataJws(claims, { alg, kid }, secretKeyBytes);
  };
  const fetchDocument = async url => documents.has(url.pathname)
    ? new Response(JSON.stringify(documents.get(url.pathname))) : new Response(null, { status: 404 });

  for (const [kind, path, did, issuer] of [
    ['host', '/host/cds-EU/v1/test', hostDid, hostDid],
    ['tenant', '/tenant/cds-ES/v1/health-care', tenantDid, icaDid],
  ]) {
    const base = new URL(path, origin).href;
    const organizationPath = `${path}/.well-known/organization.json`;
    const participantPath = `${path}/.well-known/legal-participant.vc.json`;
    const unsigned = {
      '@context': [context, 'https://schema.org'], type: ['VerifiableCredential', 'OrganizationCredential'], issuer,
      credentialSubject: { '@type': 'Organization', id: did, legalName: EXAMPLE_PROVIDER_LEGAL_NAME, taxID },
      ...(kind === 'tenant' ? { evidence: [{ type: 'document' }] } : {}),
    };
    const proofs = [];
    for (const signer of new Set([issuer, did])) {
      const detached = await sign(unsigned, signer);
      proofs.push({ verificationMethod: `${signer}#${signers.get(signer).publicJWKey.kid}`, jws: `${detached.protected}..${detached.signature}` });
    }
    const organization = { ...unsigned, proof: proofs };
    documents.set(organizationPath, organization);
    const claims = {
      issuer: did, credentialSubject: { id: did, type: 'gx:LegalPerson', 'https://schema.org/taxID': taxID },
      ...(kind === 'tenant' ? { relatedResource: [{
        id: new URL(organizationPath, origin).href,
        digestSRI: `sha256-${createHash('sha256').update(JSON.stringify(organization)).digest('base64')}`,
      }] } : {}),
    };
    const jwt = await sign(claims, did);
    const envelope = { '@context': context, type: 'EnvelopedVerifiableCredential', id: `data:application/vc+jwt,${jwt.protected}.${jwt.payload}.${jwt.signature}` };
    documents.set(participantPath, envelope);
    const result = await verifyOrganizationPublication(base, kind, fetchDocument);
    assert.equal(result.selfSigned, kind === 'host');
    assert.equal(result.proofs, kind === 'host' ? 1 : 2);
    assert.equal(result.linkedEvidence, kind === 'tenant');
    documents.set(participantPath, { ...claims, proof: envelope });
    await assert.rejects(verifyOrganizationPublication(base, kind, fetchDocument), /envelope fields/);
    documents.set(participantPath, envelope);
    documents.set(organizationPath, { ...organization, credentialSubject: { ...organization.credentialSubject, taxID: `${taxID}0` } });
    await assert.rejects(verifyOrganizationPublication(base, kind, fetchDocument), /signature verification failed/);
  }
});
