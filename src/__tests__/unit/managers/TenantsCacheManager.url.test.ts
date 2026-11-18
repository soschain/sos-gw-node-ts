// Flow contract: tenant endpoint URLs derive from the configured route while tenant key material stays with the configured KMS.
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { KmsService } from '../../../services/KmsService';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { testConfigTenant1, testTenant1IdentifierUrn, testHostDidWeb, testConfigDataHost } from '../../data/organization.data';
import { SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { EntityConfig } from '../../../gdc-backend-utils-node/models/entity';
import { getEnvSectionId } from '../../../utils/section-env';
import { composeHostDidWebId, createHostedDidWeb, populateDidDocumentFromJwks } from '../../../utils/did-backend';
import { createOrganizationUrn } from '../../../utils/urn';
import { DCR_REPLAY_PUBLIC_KEYS } from '../../data/dcr-replay-public-keys';

describe('TenantsCacheManager - tenant urls', () => {
  let tenantsCacheManager: TenantsCacheManager;
  let realKmsService: KmsService;
  let vaultRepository: VaultMemRepository;

  const hostConfig: EntityConfig = {
    id: 'host-id',
    status: 'active',
    claims: { [SchemaOrgOrganizationClaim.AlternateName]: 'host' },
    didDocument: { '@context': 'https://www.w3.org/ns/did/v1', id: testHostDidWeb },
  } as any;

  const tenantConfigWithUrl: EntityConfig = {
    ...testConfigTenant1,
    didDocument: { ...testConfigTenant1.didDocument, id: testTenant1IdentifierUrn },
    claims: {
      ...testConfigTenant1.claims,
      [SchemaOrgOrganizationClaim.Url]: 'acme.example.com',
      [SchemaOrgServiceClaim.Category]: 'health-care',
    }
  } as any;

  const tenantConfigWithoutUrl: EntityConfig = { 
    ...testConfigTenant1,
    didDocument: { ...testConfigTenant1.didDocument, id: testTenant1IdentifierUrn },
    claims: {
      ...testConfigTenant1.claims,
      [SchemaOrgServiceClaim.Category]: 'health-care',
    },
  } as any;
  delete (tenantConfigWithoutUrl.claims as any)[SchemaOrgOrganizationClaim.Url];

  const tenantConfigWithOperationalUrl: EntityConfig = {
    ...tenantConfigWithUrl,
    claims: {
      ...tenantConfigWithUrl.claims,
      'org.schema.Service.url': 'operator.acme.example.com',
    },
  } as any;

  beforeEach(async () => {
    const cryptoService = new CryptographyService(new AdapterCryptoSdkNode());
    vaultRepository = new VaultMemRepository();
    tenantsCacheManager = new TenantsCacheManager(vaultRepository, () => realKmsService, 'test-host-collection');
    realKmsService = new KmsService(cryptoService, tenantsCacheManager);

    // Exercise the public storage-backed cache boundary. Older versions of this
    // test reached into a renamed private Map, so they could pass without proving
    // that a tenant registration was loadable through the real manager path.
    jest.spyOn(realKmsService, 'unprotectConfidentialData').mockImplementation(
      async (record: any) => record.content,
    );
    await vaultRepository.put(
      'test-host-collection',
      [
        { id: 'health-care_acme_with_url', status: 'active', content: tenantConfigWithUrl },
        { id: 'health-care_acme_no_url', status: 'active', content: tenantConfigWithoutUrl },
        { id: 'health-care_acme_with_operational_url', status: 'active', content: tenantConfigWithOperationalUrl },
      ] as any,
      getEnvSectionId('tenants'),
    );

    // Spy on getDidDocument and mock its implementation
    jest.spyOn(tenantsCacheManager, 'getDidDocument').mockImplementation(async (vaultId: string) => {
      if (vaultId === 'host') return hostConfig.didDocument;
      if (vaultId === 'health-care_acme_with_url') return tenantConfigWithUrl.didDocument;
      if (vaultId === 'health-care_acme_no_url') return tenantConfigWithoutUrl.didDocument;
      if (vaultId === 'health-care_acme_with_operational_url') return tenantConfigWithOperationalUrl.didDocument;
      return undefined;
    });

  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should return the external domain URL with https if the claim exists', async () => {
    // ACT
    const url = await tenantsCacheManager.getTenantDomainUrl('health-care_acme_with_url');
    // ASSERT
    expect(url).toBe('https://acme.example.com');
  });

  it('should construct the correct hosted URL if the external domain claim is missing', async () => {
    // ACT
    const url = await tenantsCacheManager.getTenantDomainUrl('health-care_acme_no_url');
    // ASSERT
    const hostDomain = testHostDidWeb.replace('did:web:', '');
    const urnParts = testTenant1IdentifierUrn.split(':');
    const tenantPath = String((testConfigTenant1.claims as any)[SchemaOrgOrganizationClaim.AlternateName]);
    // The jurisdiction (urnParts[3]) must be lower-cased to match the canonical URL format.
    const expectedUrl = `https://${hostDomain}/${tenantPath}/cds-${urnParts[3].toLowerCase()}/${urnParts[4]}/${urnParts[5]}`;
    expect(url).toBe(expectedUrl);
  });
  
  it('should return the host URL for the host vaultId', async () => {
    // ACT
    const url = await tenantsCacheManager.getTenantDomainUrl('host');
    // ASSERT
    const hostDomain = testHostDidWeb.replace('did:web:', '');
    expect(url).toBe(`https://${hostDomain}`);
  });

  it('should return undefined for a non-existent vaultId', async () => {
    // ACT
    const url = await tenantsCacheManager.getTenantDomainUrl('non-existent-vault');
    // ASSERT
    expect(url).toBeUndefined();
  });

  it('should return the operational URL when the service claim exists', async () => {
    const url = await tenantsCacheManager.getTenantOperationalUrl('health-care_acme_with_operational_url');
    expect(url).toBe('https://operator.acme.example.com');
  });

  it('should fall back to the hosted operational URL when no service claim exists', async () => {
    const url = await tenantsCacheManager.getTenantOperationalUrl('health-care_acme_no_url');
    const hostDomain = testHostDidWeb.replace('did:web:', '');
    const urnParts = testTenant1IdentifierUrn.split(':');
    const tenantPath = String((testConfigTenant1.claims as any)[SchemaOrgOrganizationClaim.AlternateName]);
    const expectedUrl = `https://${hostDomain}/${tenantPath}/cds-${urnParts[3].toLowerCase()}/${urnParts[4]}/${urnParts[5]}`;
    expect(url).toBe(expectedUrl);
  });
});

// Flow contract: moving an approved hosted transport never changes the protected
// tenant identity, credential issuer, keys, unrelated domains or stored records.
describe('TenantsCacheManager approved hosted transport projection', () => {
  it.each(['approved', 'approved-without-domain', 'approved-without-domain-http', 'external', 'lookalike'])('projects only an exact approved %s origin without writes', async kind => {
    const canonical = SAFE.httpsBaseUrl;
    const legacy = new URL(canonical); legacy.port = '8443';
    if (kind.endsWith('-http')) { legacy.protocol='http:'; legacy.hostname='localhost'; }
    const external = new URL(canonical); external.port = '9443';
    const lookalike = new URL(legacy); lookalike.hostname += '.invalid';
    const selected = kind.startsWith('approved') ? legacy.origin : kind === 'external' ? external.origin : lookalike.origin;
    const record = structuredClone(testConfigTenant1);
    const alternateName = String(record.claims[SchemaOrgOrganizationClaim.AlternateName]);
    const sector='health-care',jurisdiction='CA-BC';
    const transport = `${selected}/${alternateName}/cds-${jurisdiction}/v1/${sector}`;
    const expected = kind.startsWith('approved') ? transport.replace(legacy.origin, canonical) : transport;
    record.claims = {...record.claims,[SchemaOrgOrganizationClaim.AddressCountry]:'CA',[SchemaOrgOrganizationClaim.AddressRegion]:jurisdiction,[SchemaOrgServiceClaim.Category]:sector,[SchemaOrgOrganizationClaim.Url]:transport,[SchemaOrgServiceClaim.Url]:transport};
    record.claims[SchemaOrgOrganizationClaim.IdentifierReference]=createOrganizationUrn({namespace:'cds',network:'test-network',jurisdiction,sector,idType:String(record.claims[SchemaOrgOrganizationClaim.IdentifierType]),idValue:String(record.claims[SchemaOrgOrganizationClaim.IdentifierValue])});
    if (kind.startsWith('approved-without-domain')) delete record.claims[SchemaOrgOrganizationClaim.Url];
    const identity = createHostedDidWeb(composeHostDidWebId(selected),alternateName,{jurisdiction,version:'v1',sector});
    record.didDocument = populateDidDocumentFromJwks({'@context':'https://www.w3.org/ns/did/v1',id:identity}, {keys:[...structuredClone(DCR_REPLAY_PUBLIC_KEYS)]});
    record.didDocument.service = [{id:`${identity}#did-document`,type:'LinkedDomains',serviceEndpoint:`${transport}/.well-known/did.json`}];
    const original = structuredClone(record);
    const vault = new VaultMemRepository();
    await vault.put('transport-host', [{id:'health-care_legacy',status:'active',content:record}] as any, getEnvSectionId('tenants'));
    const host=structuredClone(testConfigDataHost),hostDid=composeHostDidWebId(selected);
    host.didDocument={'@context':'https://www.w3.org/ns/did/v1',id:hostDid,service:[{id:hostDid+'#did-document',type:'LinkedDomains',serviceEndpoint:selected+'/.well-known/did.json'}]};
    await vault.put('transport-host',[{id:'host',status:'active',content:host}] as any,getEnvSectionId('tenants'));
    const writes = jest.spyOn(vault, 'put');
    const kms = {unprotectConfidentialData: jest.fn(async (doc: any) => structuredClone(doc.content))} as unknown as KmsService;
    const previous = new TenantsCacheManager(vault,()=>kms,'transport-host');
    const previousIssuer = await previous.getTenantDomainUrl('health-care_legacy');
    if(kind.startsWith('approved-without-domain'))expect(previousIssuer).toBe(`${selected}/${alternateName}/cds-ca-bc/v1/${sector}`);
    const manager: TenantsCacheManager = Reflect.construct(TenantsCacheManager, [vault, () => kms, 'transport-host', {apiBaseUrl:canonical,legacyPublicUrls:[legacy.origin]}]);
    expect(await manager.getTenantDomainUrl('health-care_legacy')).toBe(previousIssuer);
    expect(await manager.getTenantOperationalUrl('health-care_legacy')).toBe(expected);
    const projected = await manager.getDidDocument('health-care_legacy');
    expect(projected).toEqual({...original.didDocument,service:[{...original.didDocument!.service![0],serviceEndpoint:`${expected}/.well-known/did.json`}]});
    expect(projected?.id).toBe(original.didDocument!.id);
    projected!.service![0].serviceEndpoint = canonical + '/modified-by-caller';
    expect((await manager.getDidDocument('health-care_legacy'))?.service?.[0].serviceEndpoint).toBe(`${expected}/.well-known/did.json`);
    expect((await vault.get<any>('transport-host','health-care_legacy',getEnvSectionId('tenants')))?.content).toEqual(original);
    expect(writes).not.toHaveBeenCalled();
  });
  it('propagates a host read failure without retrying under a different issuer origin', async () => {
    const canonical=SAFE.httpsBaseUrl,legacy=new URL(canonical);legacy.port='8443';
    const record=structuredClone(testConfigTenant1);
    record.claims={...record.claims,[SchemaOrgServiceClaim.Category]:'health-care'};
    delete record.claims[SchemaOrgOrganizationClaim.Url];
    record.didDocument={'@context':'https://www.w3.org/ns/did/v1',id:createHostedDidWeb(composeHostDidWebId(legacy.origin),String(record.claims[SchemaOrgOrganizationClaim.AlternateName]),{jurisdiction:'CA',version:'v1',sector:'health-care'})};
    const host=structuredClone(testConfigDataHost);host.didDocument={'@context':'https://www.w3.org/ns/did/v1',id:composeHostDidWebId(canonical)};
    const vault=new VaultMemRepository();await vault.put('transport-host',[{id:'health-care_legacy',status:'active',content:record},{id:'host',status:'active',content:host}] as any,getEnvSectionId('tenants'));
    const kms={unprotectConfidentialData:async(doc:any)=>structuredClone(doc.content)} as unknown as KmsService;
    const manager=new TenantsCacheManager(vault,()=>kms,'transport-host',{apiBaseUrl:canonical,legacyPublicUrls:[legacy.origin]});
    expect(await manager.getDidDocument('health-care_legacy')).toBeDefined();
    const read=jest.spyOn(vault,'get').mockRejectedValueOnce(new Error('Host storage unavailable'));
    await expect(manager.getTenantDomainUrl('health-care_legacy')).rejects.toThrow('Host storage unavailable');
    expect(read).toHaveBeenCalledTimes(1);
  });

});
