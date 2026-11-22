// Flow contract: persist real encrypted device, licence and employee records through the memory vault/KMS port; verify the registered professional projection; persist revocation or expiry and reject the same assertion; destroy owned keys. No mocked cryptography or Fabric claim replaces this local state proof.
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { buildProfessionalEmployeeCredential } from 'sos-data-utils-ts/professional-smart';
import { verifyRegisteredProfessionalIdentity } from '../../../bootstrap/verify-registered-presentation-identity';
import { CredentialLedgerAdapterMem } from '../../../adapters/CredentialLedgerAdapterMem';
import { LedgerPresentationVerifier } from '../../../services/LedgerPresentationVerifier';
import { KmsService } from '../../../services/KmsService';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';
import { getEnvSectionId } from '../../../utils/section-env';

it('rechecks encrypted current professional state after device, licence and occupation changes', async () => {
  const vault = new VaultMemRepository(); let kms: KmsService;
  const tenants = new TenantsCacheManager(vault, () => kms, e.tenantId);
  kms = new KmsService(new CryptographyService(new AdapterCryptoSdkNode()), tenants);
  const vaultId = e.tenantId; const employeeCollection = `${e.tenantId}-employees`;
  try {
    await kms.init(); await kms.provisionKeys(vaultId);
    const now = Math.floor(Date.now() / 1000);
    const actorDid = `${e.didWeb}:employee`;
    const keys = await generateKeyPair('ES384');
    const publicKey = { ...await exportJWK(keys.publicKey), kid: `${actorDid}#device` };
    const profile = { clientId: e.resourceUuid, subjectId: `${e.resourceUuid}-employee`,
      activationCode: `${e.resourceUuid}-activation`, jwks: { keys: [publicKey] } };
    const licence = { id: `${e.resourceUuid}-licence`, status: 'active', subjectId: profile.subjectId, activationCode: profile.activationCode,
      issuedToRole: HealthcareActorRoles.GeneralistMedicalPractitioner, exp: now + 600, deviceBindings: [{ clientId: profile.clientId, status: 'active' }] };
    const employee = { status: 'active', didDocument: { id: actorDid }, claims: { [SchemaOrgPersonClaim.Email]: e.firstContactEmail, [SchemaOrgPersonClaim.HasOccupation]: licence.issuedToRole } };
    const store = async (id: string, section: string, content: Record<string, unknown>) => {
      const document = await kms.protectConfidentialData({ id, status: content.status || 'active', sequence: 0, content } as any, vaultId);
      expect(document.jwe || document.blob).toBeTruthy(); expect(document.content).toBeUndefined();
      await vault.put(section === 'employees' ? employeeCollection : vaultId, [document], getEnvSectionId(section));
    };
    await store(profile.clientId, 'device-profiles', profile); await store(licence.id, 'device-licenses', licence); await store(profile.subjectId, 'employees', employee);
    const credential = buildProfessionalEmployeeCredential({ actorDid, role: licence.issuedToRole, email: e.firstContactEmail });
    const verify = () => verifyRegisteredProfessionalIdentity({ credential, holder: profile.clientId, vaultId, employeeCollection, kmsService: kms, vaultRepository: vault, now });
    await expect(verify()).resolves.toMatchObject({ actorDid, role: licence.issuedToRole });
    const authorizationAudience = `${e.httpsBaseUrl}/identity/wallet-authorization`;
    const presentation = await new SignJWT({ iss: profile.clientId, aud: authorizationAudience, iat: now, exp: now + 120,
      jti: e.resourceUuid, vp: { holder: profile.clientId, verifiableCredential: [credential] } })
      .setProtectedHeader({ alg: 'ES384', kid: publicKey.kid }).sign(keys.privateKey);
    const verifier = new LedgerPresentationVerifier({
      network: 'test', ledgerKind: 'memory', ledger: new CredentialLedgerAdapterMem(), now: () => now,
      resolveHolderKeys: async holder => {
        const document = await vault.get<any>(vaultId, holder, getEnvSectionId('device-profiles'));
        return (await kms.unprotectConfidentialData<typeof profile>(document!, vaultId)).jwks;
      },
      assertActiveKey: async holder => {
        const device = await vault.get<any>(vaultId, holder, getEnvSectionId('device-profiles'));
        if (device?.status !== 'active') throw new Error('Device is inactive.');
      },
      resolveIssuerKeys: async () => { throw new Error('Stored professional authority should be used.'); },
      verifyRegisteredIdentity: (projection, holder) => verifyRegisteredProfessionalIdentity({ credential: projection,
        holder, vaultId, employeeCollection, kmsService: kms, vaultRepository: vault, now }),
      authorize: async () => { throw new Error('Wallet authorization must not request data access.'); },
    });
    const verifyWallet = () => verifier.verifyProfessionalWalletEligibility({ tenantDid: e.didWeb,
      tenantVaultId: vaultId, clientId: profile.clientId, authorizationAudience, presentation });
    await expect(verifyWallet()).resolves.toMatchObject({ actorDid, role: licence.issuedToRole });
    const licenceDocument = await vault.get<any>(vaultId, licence.id, getEnvSectionId('device-licenses'));
    await vault.put(vaultId, [{ ...licenceDocument, status: 'revoked' }], getEnvSectionId('device-licenses'));
    await expect(verify()).rejects.toThrow(/licence|inactive|revok/i);
    await expect(verifyWallet()).rejects.toThrow(/licence|inactive|revok/i);
    await store(licence.id, 'device-licenses', licence);
    await store(licence.id, 'device-licenses', { ...licence, exp: now - 1 }); await expect(verify()).rejects.toThrow(/expired|inactive/i);
    await store(licence.id, 'device-licenses', licence);
    await store(profile.subjectId, 'employees', { ...employee, claims: { ...employee.claims, [SchemaOrgPersonClaim.HasOccupation]: HealthcareActorRoles.NursingProfessional } });
    await expect(verify()).rejects.toThrow(/role|employment/i);
    await store(profile.subjectId, 'employees', employee);
    await store(profile.clientId, 'device-profiles', { ...profile, status: 'revoked' }); await expect(verify()).rejects.toThrow(/device|inactive/i);
  } finally { kms.destroy(); vault.clear(); }
});
