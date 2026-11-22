// Flow contract: 1. A registered member requests from their own tenant.
// 2. The issuer reads current approved evidence and persists a sealed offer
// authorization. 3. Redemption rechecks both authorities and consumes it once.
// Account, subject, evidence revision and tenant remain bound throughout.
import { exportJWK, generateKeyPair } from 'jose';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { ProofOfAgeWalletIssuanceManager } from '../../../managers/ProofOfAgeWalletIssuanceManager';
import { ReplayProtectionStoreMem } from '../../../adapters/replay-protection-store';
import { KmsService } from '../../../services/KmsService';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';

it('only signs once with current approved evidence for the same member and tenant', async () => {
  const vault = new VaultMemRepository();
  const cache = new TenantsCacheManager(vault, () => kms, e.tenantId);
  const kms: KmsService = new KmsService(new CryptographyService(new AdapterCryptoSdkNode()), cache);
  try {
    await kms.init();
    await kms.provisionKeys(e.tenantId);
    const now = Math.floor(Date.now() / 1000);
    const actorDid = `${e.didWeb}:member`;
    const subjectDid = `${e.didWeb}:individual`;
    const tenant = { tenantVaultId: e.tenantId, tenantDid: e.didWeb,
      authorizationAudience: new URL('/identity/openid/wallet/_authorize-proof-of-age', e.httpsBaseUrl).href };
    const age = { docType: 'eu.europa.ec.av.1', namespaces: { 'eu.europa.ec.av.1': { age_over_18: true } } };
    const holderKey = await exportJWK((await generateKeyPair('ES256')).publicKey);
    let revision = 'approved-evidence';
    let active = true;
    let supersedeDuringSigning = false;
    let claimIndicatesAdult = true;
    let signCount = 0;
    const manager = new ProofOfAgeWalletIssuanceManager({
      repository: vault, kms, replay: new ReplayProtectionStoreMem(), now: () => now,
      verify: async ({clientId, presentation}) => {
        if (!active) throw new Error('Registered device inactive');
        return {clientId, actorDid, subjectDid, presentationId: presentation, expiresAt: now + 60};
      },
      readApprovedEvidence: async (context, identity) => {
        expect(context).toEqual(tenant);
        expect(identity).toEqual({actorDid, subjectDid});
        return revision ? {revision, projection: {
          ...age, namespaces: { [age.docType]: { age_over_18: claimIndicatesAdult } },
        }} : undefined;
      },
      sign: async (projection, key) => {
        expect(projection).toEqual(age);
        expect(key).toEqual(holderKey);
        signCount++;
        if (supersedeDuringSigning) revision = 'superseded-during-signing';
        return 'test-signer-result';
      },
    });
    const begin = (id: string) => manager.authorize(tenant, {clientId: e.resourceUuid, presentation: id});
    const grant = await begin(e.resourceUuid);
    await expect(begin(e.resourceUuid)).rejects.toThrow(/unavailable|used/i);
    await expect(manager.issue({...tenant, authorizationAudience: e.httpsBaseUrl}, grant, holderKey)).rejects.toThrow(/unavailable/i);
    await expect(manager.issue(tenant, {...grant, subjectReference: e.didWeb}, holderKey)).rejects.toThrow(/invalid/i);
    revision = 'superseded';
    await expect(manager.issue(tenant, grant, holderKey)).rejects.toThrow(/evidence/i);
    revision = 'approved-evidence';
    claimIndicatesAdult = false;
    await expect(manager.issue(tenant, grant, holderKey)).rejects.toThrow(/evidence/i);
    claimIndicatesAdult = true;
    expect(signCount).toBe(0);
    revision = 'approved-current';
    const current = await begin(e.demoOrganizationUuids.healthCare);
    await expect(manager.issue(tenant, current, holderKey)).resolves.toBe('test-signer-result');
    await expect(manager.issue(tenant, current, holderKey)).rejects.toThrow(/unavailable|used/i);
    const revoked = await begin(e.demoOrganizationUuids.animalCare);
    active = false;
    await expect(manager.issue(tenant, revoked, holderKey)).rejects.toThrow(/unavailable/i);
    expect(signCount).toBe(1);
    active = true;
    const race = await begin('synthetic-race-receipt');
    supersedeDuringSigning = true;
    await expect(manager.issue(tenant, race, holderKey)).rejects.toThrow(/evidence/i);
    await expect(manager.issue(tenant, race, holderKey)).rejects.toThrow(/unavailable/i);
  } finally { kms.destroy(); vault.clear(); }
});
