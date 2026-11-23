// Flow contract: an authorized internal projection signs only an authoritative FHIR readback, uses the tenant ES256 credential key for standard SHC, and adds one exact-byte RFC 7797 ML-DSA companion proof per resolved attester key.
import { jest } from '@jest/globals';
import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';
import { BundleTypes } from 'sos-data-utils-ts/bundle-contract';
import { Content } from "antifraud-data-utils-ts/cryptography";
import {PostQuantumDetachedProofPrefix} from 'antifraud-data-utils-ts/cryptography';
import {SoschainSmartHealthCardQrPrefix} from 'sos-data-utils-ts/clinical-document-shc';
import { VeterinaryHealthCardCredentialManager } from '../../../managers/VeterinaryHealthCardCredentialManager';

const CredentialAlgorithms = Object.freeze({
  SmartHealthCard: 'ES256',
  CompanionProof: 'ML-DSA-65',
});

describe('VeterinaryHealthCardCredentialManager', () => {
  it('issues SHC and one independent companion proof for each attester', async () => {
    const pqcHeader = Content.objectToRawBase64UrlSafe({
      alg: CredentialAlgorithms.CompanionProof, kid: 'attester-pqc', b64: false, crit: ['b64'],
    });
    let attesterAlgorithm: string = CredentialAlgorithms.CompanionProof;
    const kms = {
      getPublicJwks: jest.fn(async (vaultId: string) => ({
        keys: vaultId === 'tenant-vault'
          ? [{ kty: 'EC', crv: 'P-256', alg: CredentialAlgorithms.SmartHealthCard, use: 'sig', kid: 'tenant-es256' }]
          : [{ kty: 'AKP', alg: attesterAlgorithm, use: 'sig', purpose: 'vc_sign', kid: 'attester-pqc' }],
      })),
      createCompactJwsFromEncodedPayload: jest.fn(async (payload: string) => `header.${payload}.signature`),
      createDetachedJwsForBytes: jest.fn(async () => `${pqcHeader}..signature`),
    };
    const manager = new VeterinaryHealthCardCredentialManager(kms as any);

    const fixture = {
      tenantVaultId: 'tenant-vault',
      issuer: 'https://issuer.example/tenant',
      notBefore: 1788825600,
      fhirVersion: '4.0.1',
      authoritativeBundle: {
        resourceType: ResourceTypesFhirR4.Bundle,
        type: BundleTypes.collection,
        entry: [{ resource: { resourceType: ResourceTypesFhirR4.Immunization, status: 'completed' } }],
      },
      attesters: [{ vaultId: 'attester-vault', keyId: 'attester-pqc' }],
    };
    const result = await manager.issueFromAuthoritativeBundle(fixture);

    expect(kms.createCompactJwsFromEncodedPayload).toHaveBeenCalledWith(
      expect.any(String), 'tenant-es256', 'tenant-vault', 'vc_sign', { zip: 'DEF' },
    );
    const exactPayload = (kms.createDetachedJwsForBytes.mock.calls as unknown as Array<[Uint8Array]>)[0][0];
    expect(JSON.parse(Content.bytesToStringUTF8(exactPayload))).toMatchObject({
      iss: 'https://issuer.example/tenant',
      vc: { credentialSubject: { fhirVersion: '4.0.1' } },
    });
    expect(kms.createDetachedJwsForBytes).toHaveBeenCalledWith(
      exactPayload, 'attester-pqc', 'attester-vault', 'vc_sign',
    );
    expect(result.shcQr.every(value => value.startsWith(SoschainSmartHealthCardQrPrefix))).toBe(true);
    expect(result.pqcCompanionProofs).toHaveLength(1);
    expect(result.pqcCompanionProofs[0]).toMatch(new RegExp(`^${PostQuantumDetachedProofPrefix}`));
    expect(result.pqcQr).toHaveLength(1);
    expect(result.pqcQr[0].every(value => value.startsWith(PostQuantumDetachedProofPrefix))).toBe(true);
    attesterAlgorithm = 'ML-DSA-44';
    await expect(manager.issueFromAuthoritativeBundle(fixture)).rejects.toThrow('veterinary_attester_mldsa_credential_key_required');
    expect(kms.createDetachedJwsForBytes).toHaveBeenCalledTimes(1);
  });

  it('fails closed when the tenant has no dedicated ES256 credential key', async () => {
    const manager = new VeterinaryHealthCardCredentialManager({
      getPublicJwks: jest.fn(async () => ({ keys: [{ alg: 'ES384', use: 'sig', kid: 'tenant-es384' }] })),
      createCompactJwsFromEncodedPayload: jest.fn(),
      createDetachedJwsForBytes: jest.fn(),
    } as any);
    await expect(manager.issueFromAuthoritativeBundle({
      tenantVaultId: 'tenant-vault', issuer: 'https://issuer.example/tenant', notBefore: 1,
      fhirVersion: '4.0.1', authoritativeBundle: { resourceType: ResourceTypesFhirR4.Bundle, entry: [{}] },
      attesters: [{ vaultId: 'attester-vault', keyId: 'attester-pqc' }],
    })).rejects.toThrow('veterinary_shc_tenant_es256_key_required');
  });
});
