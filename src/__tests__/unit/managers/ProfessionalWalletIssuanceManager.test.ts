// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// A scoped professional proof creates one encrypted grant. Only the bound tenant signs after a
// fresh eligibility read, and the resulting credential binds the wallet key. Replays fail closed.
import { exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { ProfessionalWalletIssuanceManager } from '../../../managers/ProfessionalWalletIssuanceManager';
import { ReplayProtectionStoreMem } from '../../../adapters/replay-protection-store';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { KmsService } from '../../../services/KmsService';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';

it('rechecks active eligibility and signs one SD-JWT VC with the existing tenant signing key', async () => {
  const previous = process.env.LEGACY_SIGN_ALG;
  process.env.LEGACY_SIGN_ALG = 'ES256';
  const vault = new VaultMemRepository();
  const cache = new TenantsCacheManager(vault, () => kms, e.tenantId);
  const kms: KmsService = new KmsService(new CryptographyService(new AdapterCryptoSdkNode()), cache);
  try {
    await kms.init();
    await kms.provisionKeys(e.tenantId);
    const now = Math.floor(Date.now() / 1000);
    const actorDid = `${e.didWeb}:employee`;
    const role = HealthcareActorRoles.GeneralistMedicalPractitioner;
    const configurationId = 'employee';
    const vct = `${e.httpsBaseUrl}/types/employee`;
    const tenant = { tenantVaultId: e.tenantId, tenantDid: e.didWeb,
      authorizationAudience: `${e.httpsBaseUrl}/identity/wallet-authorization`, configurationId, vct };
    let current = true;
    const manager = new ProfessionalWalletIssuanceManager({
      repository: vault, kms, replay: new ReplayProtectionStoreMem(),
      verify: async input => {
        expect(input.tenantDid).toBe(tenant.tenantDid);
        expect(input.authorizationAudience).toBe(tenant.authorizationAudience);
        if (!current) throw new Error('Professional licence inactive');
        return { actorDid, role, clientId: e.resourceUuid, presentationId: input.presentation, expiresAt: now + 300 };
      },
      now: () => now,
    });
    const begin = (presentationId: string) => manager.begin(tenant, { clientId: e.resourceUuid, presentation: presentationId });
    const first = await begin(e.resourceUuid);
    await expect(begin(e.resourceUuid)).rejects.toThrow(/already used/i);
    const firstOffer = await manager.reserve(tenant, first);
    const holder = await generateKeyPair('ES256');
    const holderKey = await exportJWK(holder.publicKey);
    const otherTenant = { ...tenant, tenantVaultId: `${e.tenantId}-other` };
    await expect(manager.reserve(otherTenant, first)).rejects.toThrow(/unavailable/i);
    current = false;
    await expect(manager.issue(tenant, firstOffer.command, holderKey)).rejects.toThrow(/inactive/i);
    current = true;
    const second = await begin(`${e.resourceUuid}-second`);
    const { command } = await manager.reserve(tenant, second);
    expect(command).not.toHaveProperty('role');
    expect(command.subjectReference).not.toContain(actorDid);
    const results = await Promise.allSettled([manager.issue(tenant, command, holderKey), manager.issue(tenant, command, holderKey)]);
    const issued = results.find(result => result.status === 'fulfilled');
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(issued?.status).toBe('fulfilled');
    if (!issued || issued.status !== 'fulfilled') throw new Error('Credential was not issued');
    const key = await kms.getPublicVerificationKey(tenant.tenantVaultId, 'ES256', 'vc_sign');
    const { payload } = await jwtVerify(issued.value.credential.split('~')[0], await importJWK(key as any), {
      algorithms: ['ES256'], issuer: tenant.tenantDid, typ: 'dc+sd-jwt', currentDate: new Date(now * 1000),
    });
    expect(payload).toMatchObject({ vct, cnf: { jwk: holderKey }, jti: issued.value.issuanceId });
    expect(payload).toHaveProperty('_sd_alg', 'sha-256');
    const disclosure = issued.value.credential.split('~')[1];
    const [, name, value] = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8'));
    expect([name, value]).toEqual(['hasOccupation', role]);
    expect(payload).not.toHaveProperty('hasOccupation');
  } finally {
    if (previous === undefined) delete process.env.LEGACY_SIGN_ALG;
    else process.env.LEGACY_SIGN_ALG = previous;
    kms.destroy();
    vault.clear();
  }
});
