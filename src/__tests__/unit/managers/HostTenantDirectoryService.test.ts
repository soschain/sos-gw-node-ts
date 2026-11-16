// Flow contract: an authenticated host operator searches the protected host Organization registry through a DIDComm request and receives a privacy-minimized, paginated Bundle; tenant controllers and browser-selected authority fail closed.
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { HostTenantDirectoryService } from '../../../managers/hosting/HostTenantDirectoryService';
import { GatewayClaim } from '../../../shared/gateway-claim-contract';

const tenant = (input: Readonly<{
  id: string;
  legalName: string;
  identifier: string;
  jurisdiction: string;
  sector: string;
  status: 'active' | 'suspended';
  secret?: string;
}>) => ({
  id: input.id,
  secret: input.secret,
  claims: {
    [SchemaOrgOrganizationClaim.LegalName]: input.legalName,
    [SchemaOrgOrganizationClaim.Name]: input.legalName,
    [SchemaOrgOrganizationClaim.IdentifierType]: 'TAX',
    [SchemaOrgOrganizationClaim.IdentifierValue]: input.identifier,
    [SchemaOrgOrganizationClaim.AddressCountry]: input.jurisdiction,
    [SchemaOrgServiceClaim.Category]: input.sector,
    [GatewayClaim.TenantAuthorizationStatus]: input.status,
  },
  provider: { service: { sectorCategory: input.sector, privateToken: 'never-return' } },
  meta: { tenantAuthorization: { status: input.status } },
  didDocument: { id: `did:web:${input.id}.example`, privateKeyJwk: { d: 'never-return' } },
});

function request(input: Readonly<{
  sub?: string;
  pageSize?: number;
  cursor?: string;
  filters?: Record<string, string>;
}> = {}): any {
  return {
    action: '_search',
    resourceType: 'Organization',
    content: {
      thid: 'host-directory-search-001',
      iss: 'did:web:host-controller.example',
      meta: { bearer: { jwt: { payload: { sub: input.sub ?? 'host-admin-001' } } } },
      body: {
        resourceType: 'Bundle',
        type: 'searchset',
        data: [{
          type: 'Organization-search-v1.0',
          resource: { resourceType: 'Organization', meta: { claims: input.filters ?? {} } },
          request: { method: 'GET', url: 'Organization/_search' },
        }],
        meta: { pagination: { pageSize: input.pageSize, cursor: input.cursor } },
      },
    },
  };
}

describe('HostTenantDirectoryService', () => {
  const tenants = [
    tenant({ id: 'zeta', legalName: 'Zeta Clinic', identifier: 'Z-3', jurisdiction: 'CA', sector: 'health-care', status: 'active', secret: 'hidden' }),
    tenant({ id: 'alpha', legalName: 'Alpha School', identifier: 'A-1', jurisdiction: 'ES', sector: 'education', status: 'suspended' }),
    tenant({ id: 'beta', legalName: 'Beta Veterinary', identifier: 'B-2', jurisdiction: 'ES', sector: 'animal-care', status: 'active' }),
  ];
  const registry = { listRegisteredTenants: jest.fn(async () => tenants) };
  const service = new HostTenantDirectoryService(registry, {
    hostAdminUid: 'host-admin-001',
    hostDid: 'did:web:host.example',
    defaultPageSize: 2,
    maximumPageSize: 50,
  });

  it('returns a stable first page and a cursor inside the DIDComm Bundle response', async () => {
    const response = await service.search(request({ pageSize: 2 }));

    expect(response).toMatchObject({
      iss: 'did:web:host.example',
      aud: 'did:web:host-controller.example',
      body: { resourceType: 'Bundle', type: 'searchset', total: 3 },
    });
    expect(response.body.data.map((entry: any) => entry.resource.meta.claims[SchemaOrgOrganizationClaim.IdentifierValue]))
      .toEqual(['A-1', 'B-2']);
    expect(response.body.meta.pagination).toMatchObject({ pageSize: 2, returned: 2, hasNext: true });
    expect(response.body.meta.pagination.nextCursor).toEqual(expect.any(String));

    const second = await service.search(request({ pageSize: 2, cursor: response.body.meta.pagination.nextCursor }));
    expect(second.body.data).toHaveLength(1);
    expect(second.body.data[0].resource.meta.claims[SchemaOrgOrganizationClaim.IdentifierValue]).toBe('Z-3');
  });

  it('filters by jurisdiction, sector and lifecycle status without returning tenant internals', async () => {
    const response = await service.search(request({ filters: {
      [SchemaOrgOrganizationClaim.AddressCountry]: 'ES',
      [SchemaOrgServiceClaim.Category]: 'education',
      [GatewayClaim.TenantAuthorizationStatus]: 'suspended',
    } }));

    expect(response.body.total).toBe(1);
    expect(response.body.data[0].resource.meta.claims[SchemaOrgOrganizationClaim.LegalName]).toBe('Alpha School');
    expect(JSON.stringify(response)).not.toContain('privateToken');
    expect(JSON.stringify(response)).not.toContain('privateKeyJwk');
    expect(JSON.stringify(response)).not.toContain('hidden');
  });

  it('filters by the canonical organization legal name used by the host portal', async () => {
    const response = await service.search(request({ filters: {
      [SchemaOrgOrganizationClaim.LegalName]: 'Beta Veterinary',
    } }));

    expect(response.body.total).toBe(1);
    expect(response.body.data[0].resource.id).toBe('beta');
  });

  it('rejects an authenticated tenant controller that is not the configured host operator', async () => {
    await expect(service.search(request({ sub: 'tenant-controller-001' }))).rejects.toThrow(/host operator/i);
    expect(registry.listRegisteredTenants).not.toHaveBeenCalled();
  });

  it('rejects invalid or oversized pagination rather than trusting browser values', async () => {
    await expect(service.search(request({ pageSize: 51 }))).rejects.toThrow(/page size/i);
    await expect(service.search(request({ cursor: 'not-a-valid-cursor' }))).rejects.toThrow(/cursor/i);
  });
});
