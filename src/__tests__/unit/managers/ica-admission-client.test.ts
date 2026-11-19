// Flow contract: the Gateway requests ICA evidence for the signed application and immutable PDF reference without forwarding the credential or personal claims.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { createIcaAdmissionClient } from '../../../managers/hosting/ica-admission-client';

const config = {
  HOST_ADMISSION_ICA_URL: 'https://ica.example.test/organization-verifications',
  HOST_ADMISSION_ICA_TOKEN: 'example-ica-token',
};
const scope = {
  hostDid: 'did:web:gateway.example.test',
  network: 'test-network', sector: 'health-tech',
  controllerDid: 'did:web:example.test:controller',
  claims: {
    [SchemaOrgOrganizationClaim.IdentifierValue]: 'VATES-B00000001',
    [SchemaOrgOrganizationClaim.IdentifierType]: 'TAX',
    [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
    [SchemaOrgOrganizationClaim.AddressRegion]: 'ES-MD',
  },
  applicationProof: { applicationId: 'case-1', pdfSha256: 'a'.repeat(64) },
};
const evidence = {
  admissionBinding: { hostDid: scope.hostDid, applicationId: 'case-1' },
  network: 'test-network', sector: 'health-tech', jurisdiction: 'ES-MD',
  actorReference: scope.controllerDid,
  proof: { submittedReference: `urn:sha256:${'a'.repeat(64)}`, reference: 'urn:example:verified-proof' },
  checks: ['legal-identifier-match', 'official-registry-active'],
};

describe('ICA admission client', () => {
  it('uses the signed application and organization jurisdiction to request verification', async () => {
    const transport = jest.fn<typeof fetch>(async () => Response.json(evidence));
    const verify = createIcaAdmissionClient(config, transport)!;
    await expect(verify(scope)).resolves.toEqual(evidence);
    const [url, options] = transport.mock.calls[0];
    expect(String(url)).toBe(config.HOST_ADMISSION_ICA_URL);
    expect(options).toMatchObject({
      redirect: 'error', headers: {
        authorization: 'Bearer example-ica-token',
        'x-admission-actor': scope.controllerDid,
        'x-admission-application-id': 'case-1',
      },
    });
    expect(JSON.parse(String(options?.body))).toEqual({
      network: 'test-network', sector: 'health-tech', jurisdiction: 'ES-MD',
      identifier: { scheme: 'NIF', value: 'VATES-B00000001' }, proofReference: `urn:sha256:${'a'.repeat(64)}`,
    });
  });

  it('withholds checks from a response for another signer or submitted proof', async () => {
    const transport = jest.fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ ...evidence, actorReference: 'did:web:example.test:other-controller' }))
      .mockResolvedValueOnce(Response.json({ ...evidence, proof: { ...evidence.proof, submittedReference: `urn:sha256:${'b'.repeat(64)}` } }));
    const verify = createIcaAdmissionClient(config, transport)!;
    await expect(verify(scope)).resolves.toBeUndefined();
    await expect(verify(scope)).resolves.toBeUndefined();
  });

  it('leaves the application in review on an outage, wrong scope or missing signed proof', async () => {
    const transport = jest.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(Response.json({ ...evidence, admissionBinding: { ...evidence.admissionBinding, applicationId: 'other' } }));
    const verify = createIcaAdmissionClient(config, transport)!;
    await expect(verify({ ...scope, applicationProof: undefined })).resolves.toBeUndefined();
    await expect(verify({ ...scope, network: 'network' })).resolves.toBeUndefined();
    expect(transport).not.toHaveBeenCalled();
    await expect(verify(scope)).resolves.toBeUndefined();
    await expect(verify(scope)).resolves.toBeUndefined();
  });
});
