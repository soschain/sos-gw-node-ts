// Flow contract: read real encrypted personal-member device/licence records through the same memory-vault/KMS port, bind the actor and relationship to one individual, reject current revocation or substituted subject/role, and destroy owned keys. This proof does not create professional or controller authority.
import { CryptographyService } from 'antifraud-data-utils-ts/cryptography';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { encodeMultibaseSha3 } from 'antifraud-data-utils-ts/encoding';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles, HealthcareRolesByFamily, HealthcareRoleFamilies } from 'sos-data-utils-ts/healthcare-roles';
import { getIndividualMemberIdentityVC } from 'sos-data-utils-ts/individual-smart';
import { verifyRegisteredIndividualMemberIdentity } from '../../../services/registered-individual-member-authority';
import { KmsService } from '../../../services/KmsService';
import { AdapterCryptoSdkNode } from '../../../gdc-backend-utils-node/adapters/node/crypto';
import { VaultMemRepository } from '../../../database/repositories/vault/vault.mem.repository';
import { TenantsCacheManager } from '../../../managers/TenantsCacheManager';
import { getEnvSectionId } from '../../../utils/section-env';
import { LICENSE_USER_CLASS_INDIVIDUAL } from '../../../constants/domain';
import { CredentialLedgerAdapterMem } from '../../../adapters/CredentialLedgerAdapterMem';
import { LedgerPresentationVerifier } from '../../../services/LedgerPresentationVerifier';

it('binds a current licensed personal member to the individual without elevating its role', async () => {
  const vault = new VaultMemRepository(); let kms: KmsService;
  const tenants = new TenantsCacheManager(vault, () => kms, e.tenantId);
  kms = new KmsService(new CryptographyService(new AdapterCryptoSdkNode()), tenants);
  try {
    await kms.init(); await kms.provisionKeys(e.tenantId);
    const now = Math.floor(Date.now() / 1000);
    const relation = Object.values(HealthcareRolesByFamily[HealthcareRoleFamilies.PersonalRelationshipHl7])[0];
    const subjectDid = `${e.didWeb}:individual:multibase:${encodeMultibaseSha3(e.resourceUuid, 384)}`;
    const actorDid = `${subjectDid}:member:${encodeMultibaseSha3(e.firstContactEmail, 384)}:${relation.code}`;
    const profile = { clientId: `${e.resourceUuid}-device`, actorDid, authorizedSubjectDid: subjectDid,
      licenseId: `${e.resourceUuid}-licence`, authenticatedSubject: `firebase:${e.resourceUuid}-person` };
    const licence = { id: profile.licenseId, status: 'active', userClass: LICENSE_USER_CLASS_INDIVIDUAL,
      exp: now + 600, subjectId: `${e.resourceUuid}-person`, authorizedSubjectDid: subjectDid,
      issuedToRole: relation.claim, issuedToEmail: e.firstContactEmail,
      deviceBindings: [{ clientId: profile.clientId, status: 'active' }] };
    const store = async (id: string, section: string, content: Record<string, unknown>) => {
      const document = await kms.protectConfidentialData({ id, status: content.status || 'active', sequence: 0, content } as any, e.tenantId);
      expect(document.jwe || document.blob).toBeTruthy(); expect(document.content).toBeUndefined();
      await vault.put(e.tenantId, [document], getEnvSectionId(section));
    };
    await store(profile.clientId, 'device-profiles', profile); await store(licence.id, 'device-licenses', licence);
    const credential = getIndividualMemberIdentityVC({ actorDid, subjectDid, relationship: relation.claim, email: e.firstContactEmail });
    const verify = (value = credential) => verifyRegisteredIndividualMemberIdentity({ credential: value, holder: profile.clientId, vaultId: e.tenantId, kmsService: kms, vaultRepository: vault, now });
    await expect(verify()).resolves.toMatchObject({ actorDid, subjectDid, role: relation.claim, acr: 'urn:antifraud:acr:openid4vp:individual' });
    const keys = await generateKeyPair('ES384');
    const jwk = { ...await exportJWK(keys.publicKey), kid: e.resourceUuid };
    const audience = new URL('/identity/wallet/_authorize', e.httpsBaseUrl).href;
    const verifier = new LedgerPresentationVerifier({
      network: 'test', ledgerKind: 'memory', ledger: new CredentialLedgerAdapterMem(), now: () => now,
      resolveHolderKeys: async () => ({ keys: [jwk] }),
      assertActiveKey: async () => undefined,
      resolveIssuerKeys: async () => { throw new Error('Registered identity should be read from the vault.'); },
      verifyRegisteredIdentity: projection => verify(projection as typeof credential),
      authorize: async () => { throw new Error('Wallet requests must never grant index scope.'); },
    });
    const presentation = (aud: string, verifiableCredential = [credential]) =>
      new SignJWT({ iss: profile.clientId, aud, iat: now, exp: now + 120, jti: e.resourceUuid,
        vp: { holder: profile.clientId, verifiableCredential } })
        .setProtectedHeader({ alg: 'ES384', kid: jwk.kid }).sign(keys.privateKey);
    const input = { tenantDid: e.didWeb, tenantVaultId: e.tenantId,
      clientId: profile.clientId, authorizationAudience: audience, presentation: await presentation(audience) };
    await expect(verifier.verifyIndividualWalletEligibility(input)).resolves.toMatchObject({ actorDid, subjectDid });
    await expect(verifier.verifyIndividualWalletEligibility({
      ...input, presentation: await presentation(e.httpsBaseUrl),
    })).rejects.toThrow(/audience|aud/i);
    await expect(verifier.verifyIndividualWalletEligibility({
      ...input, presentation: await presentation(audience, [credential, credential]),
    })).rejects.toThrow(/exactly one/i);
    await expect(verify(getIndividualMemberIdentityVC({ actorDid, subjectDid, relationship: HealthcareActorRoles.Controller }))).rejects.toThrow(/relationship|role/i);
    await store(profile.clientId, 'device-profiles', { ...profile, authorizedSubjectDid: `${subjectDid}-other` });
    await expect(verify()).rejects.toThrow(/subject|person|individual/i);
    await store(profile.clientId, 'device-profiles', profile);
    await store(licence.id, 'device-licenses', { ...licence, exp: now - 1 }); await expect(verify()).rejects.toThrow(/expired|inactive/i);
    await expect(verifier.verifyIndividualWalletEligibility(input)).rejects.toThrow(/expired|inactive/i);
    await store(licence.id, 'device-licenses', { ...licence, deviceBindings: [{ clientId: `${profile.clientId}-other`, status: 'active' }] });
    await expect(verify()).rejects.toThrow(/device/i);
  } finally { kms.destroy(); vault.clear(); }
});
