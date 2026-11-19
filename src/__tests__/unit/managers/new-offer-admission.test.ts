// Flow contract: a governed host only issues a new Offer after an affirmative decision bound to its exact verified organization transaction.
import { describe, expect, it, jest } from '@jest/globals';
import { SchemaOrgOrganizationClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { createNewOfferAdmissionAuthorizer } from '../../../managers/hosting/new-offer-admission';

const config = {
  HOST_ADMISSION_DECISION_URL: 'https://decision.example.test/check',
  HOST_ADMISSION_DECISION_TOKEN: 'test-authorizer-bearer',
};
const verified = {
  hostDid: 'did:web:gateway.example.test',
  network: 'test-network',
  sector: 'animal-care',
  claims: {
    [SchemaOrgOrganizationClaim.IdentifierValue]: 'example-organization',
    [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
    [SchemaOrgOrganizationClaim.AddressRegion]: 'ES-MD',
  },
  evidence: { reference: 'urn:example:verified-admission' },
  credentials: [],
};

describe('new Offer admission authorization', () => {
  it('accepts a matching approved decision over the configured transport without sharing claims or proofs', async () => {
    const transport = jest.fn<typeof fetch>(async (_url, init) => {
      const { binding } = JSON.parse(String(init?.body));
      return Response.json({ binding, decision: 'approved', reference: 'urn:example:admission-decision' });
    });
    const authorize = createNewOfferAdmissionAuthorizer(config, transport)!;
    await expect(authorize(verified)).resolves.toBeUndefined();
    expect(transport).toHaveBeenCalledTimes(1);
    const [url, options] = transport.mock.calls[0];
    expect(String(url)).toBe(config.HOST_ADMISSION_DECISION_URL);
    expect(options).toMatchObject({ method: 'POST', redirect: 'error', headers: { authorization: 'Bearer test-authorizer-bearer' } });
    expect(JSON.parse(String(options?.body))).toEqual({
      hostDid: verified.hostDid, network: verified.network, jurisdiction: 'ES-MD', sector: verified.sector,
      binding: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(options?.body).not.toContain('example-organization');
    expect(options?.body).not.toContain('verified-admission');
  });

  it('fails closed without approval, with a stale binding, or when the service is unavailable', async () => {
    for (const decision of ['review', 'rejected', 'approved']) {
      const transport = jest.fn<typeof fetch>(async (_url, init) => Response.json({
        binding: decision === 'approved' ? 'stale' : JSON.parse(String(init?.body)).binding,
        decision,
        reference: 'urn:example:admission-decision',
      }));
      await expect(createNewOfferAdmissionAuthorizer(config, transport)!(verified)).rejects.toThrow('Host admission approval is required');
    }
    const unavailable = jest.fn<typeof fetch>(async () => new Response(null, { status: 503 }));
    await expect(createNewOfferAdmissionAuthorizer(config, unavailable)!(verified)).rejects.toThrow('Host admission decision is unavailable');
  });

  it('binds the approved decision to the exact organization DID and registration controller', async () => {
    const bindings: string[] = [];
    const transport = jest.fn<typeof fetch>(async (_url, init) => {
      const { binding } = JSON.parse(String(init?.body));
      bindings.push(binding);
      return Response.json({ binding, decision: 'approved', reference: 'urn:example:admission-decision' });
    });
    const authorize = createNewOfferAdmissionAuthorizer(config, transport)!;
    const original = {
      ...verified,
      organizationDid: 'did:web:gateway.example.test:example-organization',
      controllerDid: 'did:web:gateway.example.test:example-controller',
    };
    await authorize(original);
    const differentOrganization = { ...original, organizationDid: 'did:web:gateway.example.test:other-organization' };
    const differentController = { ...original, controllerDid: 'did:web:gateway.example.test:other-controller' };
    await authorize(differentOrganization);
    await authorize(differentController);
    expect(new Set(bindings).size).toBe(3);
  });

  it('forwards only scoped decision evidence from the verified ICA path', async () => {
    const transport = jest.fn<typeof fetch>(async (_url, init) => {
      const { binding } = JSON.parse(String(init?.body));
      return Response.json({ binding, decision: 'approved', reference: 'urn:example:admission-decision' });
    });
    const authorize = createNewOfferAdmissionAuthorizer(config, transport)!;
    const icaEvidence = {
      admissionBinding: { hostDid: verified.hostDid, applicationId: 'test-application' },
      network: verified.network,
      jurisdiction: 'ES-MD',
      sector: verified.sector,
      proof: { reference: 'urn:example:ica-evidence', document: 'must remain private' },
      checks: ['legal-identifier-match', 'official-registry-active'],
    };
    const fromIca = { ...verified, evidence: icaEvidence, evidenceSource: 'ica' } as const;
    await authorize(fromIca);
    const submitted = JSON.parse(String(transport.mock.calls[0][1]?.body));
    expect(submitted.evidence).toEqual({
      applicationId: 'test-application', reference: 'urn:example:ica-evidence',
      checks: ['legal-identifier-match', 'official-registry-active'],
    });
    expect(JSON.stringify(submitted)).not.toContain('must remain private');
    await authorize({ ...fromIca, evidenceSource: 'host' } as const);
    expect(JSON.parse(String(transport.mock.calls[1][1]?.body)).evidence).toBeUndefined();
    await authorize({ ...fromIca, evidence: { ...icaEvidence, jurisdiction: 'ES-CL' } });
    expect(JSON.parse(String(transport.mock.calls[2][1]?.body)).evidence).toBeUndefined();
  });

  it('resumes an ICA-reviewed application across observation refreshes while binding a replacement proof separately', async () => {
    const transport = jest.fn<typeof fetch>(async (_url, init) => {
      const { binding } = JSON.parse(String(init?.body));
      return Response.json({ binding, decision: 'approved', reference: 'urn:example:admission-decision' });
    });
    const authorize = createNewOfferAdmissionAuthorizer(config, transport)!;
    const evidence = {
      admissionBinding: { hostDid: verified.hostDid, applicationId: 'case-1' },
      network: verified.network, jurisdiction: 'ES-MD', sector: verified.sector,
      proof: { reference: 'urn:example:immutable-proof' },
      registry: { checkedAt: '2026-01-01T00:00:00Z' },
      checks: ['legal-identifier-match', 'official-registry-active'],
    };
    const input = { ...verified, evidence, evidenceSource: 'ica' } as const;
    await authorize(input);
    await authorize({
      ...input, evidence: { ...evidence, registry: { checkedAt: '2026-01-02T00:00:00Z' } },
      credentials: [{ id: 'urn:example:renewed-credential' }],
    });
    await authorize({ ...input, evidence: { ...evidence, proof: { reference: 'urn:example:replacement-proof' } } });
    const [original, refreshed, replacement] = transport.mock.calls.map(([, init]) => JSON.parse(String(init?.body)).binding);
    expect(refreshed).toBe(original);
    expect(replacement).not.toBe(original);
  });

  it('correlates a signed application across an ICA outage but separates a replacement document', async () => {
    const transport = jest.fn<typeof fetch>(async (_url, init) => {
      const { binding, evidence } = JSON.parse(String(init?.body));
      return Response.json(evidence ? { binding, decision: 'approved', reference: 'urn:example:admission-decision' }
        : { binding, decision: 'review' });
    });
    const authorize = createNewOfferAdmissionAuthorizer(config, transport)!;
    const applicationProof = { applicationId: 'case-1', pdfSha256: 'a'.repeat(64) };
    const evidence = {
      admissionBinding: { hostDid: verified.hostDid, applicationId: 'case-1' },
      network: verified.network, jurisdiction: 'ES-MD', sector: verified.sector,
      proof: { reference: 'urn:example:verified-proof' },
      checks: ['legal-identifier-match', 'official-registry-active'],
    };
    const application = { ...verified, applicationProof };
    await expect(authorize({ ...application, evidenceSource: 'host' })).rejects.toThrow('Host admission approval is required');
    await authorize({ ...application, evidence, evidenceSource: 'ica' });
    const replacement = { ...application, applicationProof: { ...applicationProof, pdfSha256: 'b'.repeat(64) } };
    await authorize({ ...replacement, evidence, evidenceSource: 'ica' });
    const [outage, recovered, replaced] = transport.mock.calls.map(([, init]) => JSON.parse(String(init?.body)));
    expect(outage.applicationId).toBe(applicationProof.applicationId);
    expect(outage.evidence).toBeUndefined();
    expect(recovered.binding).toBe(outage.binding);
    expect(replaced.binding).not.toBe(recovered.binding);
    expect(JSON.stringify(recovered)).not.toContain(applicationProof.pdfSha256);
  });

  it('keeps deployments without an authorizer compatible and rejects partial or insecure configuration', async () => {
    expect(createNewOfferAdmissionAuthorizer({})).toBeUndefined();
    expect(() => createNewOfferAdmissionAuthorizer({ HOST_ADMISSION_DECISION_URL: config.HOST_ADMISSION_DECISION_URL }))
      .toThrow('Host admission decision configuration is invalid');
    expect(() => createNewOfferAdmissionAuthorizer({ ...config, HOST_ADMISSION_DECISION_URL: 'http://decision.example.test/check' }))
      .toThrow('Host admission decision configuration is invalid');
  });
});
