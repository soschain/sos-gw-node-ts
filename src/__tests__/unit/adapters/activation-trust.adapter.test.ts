// Flow contract: verify signed activation consistency and delegate current trust decisions to the configured verifier; evidence collaborators do not represent a live ICA or Fabric run.
import {REPOSITORY_SAFE_EXAMPLES as SAFE} from 'sos-data-utils-ts/repository-privacy';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  EXAMPLE_ORG_ACTIVATION_LEGAL_REPRESENTATIVE_CREDENTIAL,
  EXAMPLE_ORG_ACTIVATION_CONTROLLER_CREDENTIAL,
  EXAMPLE_ORG_ACTIVATION_ORGANIZATION_CREDENTIAL,
  cloneExample,
} from 'sos-data-utils-ts/gateway-resource-flow-examples';
import { DefaultActivationTrustAdapter } from '../../../adapters/activation-trust.adapter';
import { IClearingHouseService } from '../../../services/ClearingHouseService';
import { ITrustRegistryAdapter } from '../../../adapters/trust-registry.adapter';
import { buildDeterministicVpTokenFixture } from '../../utils/deterministic-jwt-fixtures';

const TEST_ORGANIZATION_DID=SAFE.didWeb;

describe('DefaultActivationTrustAdapter', () => {
  const previousEnv = process.env;
  const vpTokenFor=(...credentials:any[])=>buildDeterministicVpTokenFixture({seed:SAFE.resourceUuid,issuerDid:SAFE.didWeb,audience:SAFE.httpsBaseUrl,credentials});

  beforeEach(()=>{process.env={...previousEnv,SECURITY_MODE:'strict',NETWORK_MODE:'test',NODE_ENV:'test'};});

  afterEach(() => {
    process.env = previousEnv;
  });

  it('marks strict trust checks in test-network/network and delegates VP verification', async () => {
    const clearingHouseService: IClearingHouseService = {
      verifyVpToken: jest.fn(async () => ({
        acr: 'urn:test:acr',
        ledgerVerified: true,
      })),
    };
    const trustRegistryAdapter: ITrustRegistryAdapter = {
      verifyActivationTrust: jest.fn(async () => ({
        revocationChecked: true,
        issuerKeyStatusChecked: true,
        subjectKeyStatusChecked: true,
        onChainChecked: false,
      })),
    };
    const adapter = new DefaultActivationTrustAdapter(clearingHouseService, trustRegistryAdapter);
    const organizationCredential: any = cloneExample(EXAMPLE_ORG_ACTIVATION_ORGANIZATION_CREDENTIAL);
    organizationCredential.credentialSubject.id = TEST_ORGANIZATION_DID;

    const representativeCredential=cloneExample(EXAMPLE_ORG_ACTIVATION_LEGAL_REPRESENTATIVE_CREDENTIAL);
    const controllerCredential=cloneExample(EXAMPLE_ORG_ACTIVATION_CONTROLLER_CREDENTIAL);
    const result = await adapter.evaluate({
      networkMode: 'test-network',
      verifierTenantDid:SAFE.httpsBaseUrl,
      vpToken:(await vpTokenFor(organizationCredential,representativeCredential,controllerCredential)).compactToken,
      organizationCredential,
      representativeCredential,
      controllerCredential,
    });

    expect(result.organizationDid).toBe(TEST_ORGANIZATION_DID);
    expect(result.representativeDid).toBeUndefined();
    expect(result.clearingHouse.acr).toBe('urn:test:acr');
    expect(result.trustPolicy.networkMode).toBe('test-network');
    expect(result.trustPolicy.revocationChecked).toBe(true);
    expect(result.trustPolicy.onChainChecked).toBe(false);
    expect((trustRegistryAdapter.verifyActivationTrust as jest.Mock).mock.calls[0][0]).toMatchObject({
      networkMode: 'test-network',
      organizationDid: TEST_ORGANIZATION_DID,
    });
  });

  it('allows activation consistency evaluation without representative credential', async () => {
    const clearingHouseService: IClearingHouseService = {
      verifyVpToken: jest.fn(async () => ({
        acr: 'urn:test:acr',
        ledgerVerified: true,
      })),
    };
    const trustRegistryAdapter: ITrustRegistryAdapter = {
      verifyActivationTrust: jest.fn(async () => ({
        revocationChecked: true,
        issuerKeyStatusChecked: true,
        subjectKeyStatusChecked: true,
        onChainChecked: true,
      })),
    };
    const adapter = new DefaultActivationTrustAdapter(clearingHouseService, trustRegistryAdapter);
    const organizationCredential: any = cloneExample(EXAMPLE_ORG_ACTIVATION_ORGANIZATION_CREDENTIAL);
    organizationCredential.credentialSubject.id = TEST_ORGANIZATION_DID;

    await expect(adapter.evaluate({
      networkMode: 'network',
      verifierTenantDid:SAFE.httpsBaseUrl,
      vpToken:(await vpTokenFor(organizationCredential)).compactToken,
      organizationCredential,
    })).resolves.toMatchObject({
      organizationDid: TEST_ORGANIZATION_DID,
      trustPolicy: { networkMode: 'network' },
    });
  });

  it('verifies one deterministically signed ES384 vp_token in strict mode when the controller JWK is embedded', async () => {
    process.env = {
      ...previousEnv,
      SECURITY_MODE: 'strict',
      NODE_ENV: 'test',
    };

    const clearingHouseService: IClearingHouseService = {
      verifyVpToken: jest.fn(async () => ({
        acr: 'urn:test:acr',
        ledgerVerified: true,
      })),
    };
    const trustRegistryAdapter: ITrustRegistryAdapter = {
      verifyActivationTrust: jest.fn(async () => ({
        revocationChecked: true,
        issuerKeyStatusChecked: true,
        subjectKeyStatusChecked: true,
        onChainChecked: false,
      })),
    };
    const organizationCredential: any = cloneExample(EXAMPLE_ORG_ACTIVATION_ORGANIZATION_CREDENTIAL);
    organizationCredential.credentialSubject.id = TEST_ORGANIZATION_DID;
    const representativeCredential: any = cloneExample(EXAMPLE_ORG_ACTIVATION_LEGAL_REPRESENTATIVE_CREDENTIAL);
    const controllerCredential: any = cloneExample(EXAMPLE_ORG_ACTIVATION_CONTROLLER_CREDENTIAL);
    const vpFixture = await buildDeterministicVpTokenFixture({
      seed: SAFE.resourceUuid,
      issuerDid: SAFE.didWeb,
      audience: SAFE.httpsBaseUrl,
      credentials: [
        organizationCredential,
        representativeCredential,
        controllerCredential,
      ],
    });
    const adapter = new DefaultActivationTrustAdapter(clearingHouseService, trustRegistryAdapter);

    await expect(adapter.evaluate({
      networkMode: 'test-network',
      verifierTenantDid:SAFE.httpsBaseUrl,
      vpToken: vpFixture.compactToken,
      organizationCredential,
      representativeCredential,
      controllerCredential,
    })).resolves.toMatchObject({
      organizationDid: TEST_ORGANIZATION_DID,
      trustPolicy: { networkMode: 'test-network' },
    });
  });
});
