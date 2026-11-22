import { createHash, createPublicKey, randomBytes, randomUUID } from 'node:crypto';
import { IdentityAttestationCapability } from 'antifraud-data-utils-ts';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { IReplayProtectionStore } from '../adapters/replay-protection-store';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import type { LedgerPresentationVerifier } from '../services/LedgerPresentationVerifier';
import { getEnvSectionId } from '../utils/section-env';

export type ProfessionalCredentialSigningAlgorithm = 'ES256' | 'ML-DSA-65';

export type ProfessionalWalletTenant = Readonly<{
  tenantVaultId: string;
  tenantDid: string;
  authorizationAudience: string;
  configurationId: string;
  vct: string;
  credentialSigningAlgorithm?: ProfessionalCredentialSigningAlgorithm;
}>;

type WalletAuthorization = Readonly<{
  tenantDid: string;
  clientId: string;
  presentation: string;
  expiresAt: number;
  offered: boolean;
  configurationId: string;
  vct: string;
  credentialSigningAlgorithm?: ProfessionalCredentialSigningAlgorithm;
  authorizationAudience: string;
}>;

type WalletCommand = Readonly<{
  capability: typeof IdentityAttestationCapability.AttestRelationship;
  actorReference: string;
  subjectReference: string;
  verificationTransactionId: string;
}>;

const opaqueReference = /^[A-Za-z0-9_-]{43}$/u;
const section = () => getEnvSectionId('professional-wallet-authorizations');
const hash = (value: string) => createHash('sha256').update(value);
const roleClaim = SchemaOrgPersonClaim.HasOccupation.split('.').at(-1)!;

function commandFor(reference: string): WalletCommand {
  return {
    capability: IdentityAttestationCapability.AttestRelationship,
    actorReference: `urn:sha256:${hash(`actor:${reference}`).digest('hex')}`,
    subjectReference: `urn:sha256:${hash(`subject:${reference}`).digest('hex')}`,
    verificationTransactionId: reference,
  };
}

function validateHolderKey(input: unknown) {
  const key = input as Record<string, unknown> | null;
  if (!key || key.kty !== 'EC' || key.crv !== 'P-256' || Object.keys(key).length !== 4
    || typeof key.x !== 'string' || !opaqueReference.test(key.x)
    || typeof key.y !== 'string' || !opaqueReference.test(key.y)) {
    throw new TypeError('Wallet credential requires a public P-256 holder key.');
  }
  const jwk = { kty: 'EC', crv: 'P-256', x: key.x, y: key.y };
  createPublicKey({ key: jwk, format: 'jwk' });
  return jwk;
}

export class WalletAuthorizationError extends Error {}

export class ProfessionalWalletIssuanceManager {
  constructor(private readonly dependencies: {
    repository: Pick<IVaultRepository, 'get' | 'put' | 'delete'>;
    kms: Pick<IKmsService, 'protectConfidentialData' | 'unprotectConfidentialData' | 'getPublicVerificationKey' | 'createCompactJws'>;
    replay: IReplayProtectionStore;
    verify: LedgerPresentationVerifier['verifyProfessionalWalletEligibility'];
    now?: () => number;
  }) {}

  async begin(tenant: ProfessionalWalletTenant, input: { clientId: string; presentation: string }): Promise<string> {
    const { clientId, presentation } = input;
    const { presentationId, expiresAt } = await this.dependencies.verify({ ...tenant, clientId, presentation });
    await this.getSigningKeyId(tenant);
    await this.reserveOnce(tenant, 'presentation', `${clientId}:${presentationId}`, expiresAt);
    const reference = randomBytes(32).toString('base64url');
    const { tenantDid, configurationId, vct, authorizationAudience, credentialSigningAlgorithm = 'ES256' } = tenant;
    await this.write(tenant, reference, { tenantDid, clientId, presentation, expiresAt,
      configurationId, vct, authorizationAudience, credentialSigningAlgorithm, offered: false }, 0);
    return reference;
  }

  async reserve(tenant: ProfessionalWalletTenant, reference: string) {
    const current = await this.read(tenant, reference);
    if (current.authorization.offered) throw new WalletAuthorizationError('Wallet authorization was already used.');
    await this.reserveOnce(tenant, 'offer', reference, current.authorization.expiresAt);
    await this.write(tenant, reference, { ...current.authorization, offered: true }, current.sequence + 1);
    return { command: commandFor(reference), configurationId: tenant.configurationId };
  }

  async issue(tenant: ProfessionalWalletTenant, command: unknown, walletKey: unknown) {
    const reference = (command as WalletCommand | undefined)?.verificationTransactionId;
    const expected = commandFor(reference || '');
    if (!reference || !opaqueReference.test(reference) || Object.keys(command as WalletCommand).length !== 4
      || Object.entries(expected).some(([key, value]) => (command as Record<string, unknown>)[key] !== value)) {
      throw new WalletAuthorizationError('Wallet authorization command is invalid.');
    }
    const holderKey = validateHolderKey(walletKey);
    const { authorization } = await this.read(tenant, reference);
    if (!authorization.offered) throw new WalletAuthorizationError('Wallet authorization has no reserved offer.');
    const { role } = await this.dependencies.verify({ ...tenant, clientId: authorization.clientId, presentation: authorization.presentation });
    const signingKeyId = await this.getSigningKeyId(tenant);
    await this.reserveOnce(tenant, 'sign', reference, authorization.expiresAt);
    if (!await this.dependencies.repository.delete(tenant.tenantVaultId, reference, section())) {
      throw new Error('Wallet authorization could not be consumed.');
    }
    const issuanceId = `urn:uuid:${randomUUID()}`;
    const issuedAt = this.now();
    const disclosure = Buffer.from(JSON.stringify([randomBytes(16).toString('base64url'), roleClaim, role])).toString('base64url');
    const credential = await this.dependencies.kms.createCompactJws({
      iss: tenant.tenantDid,
      vct: tenant.vct,
      iat: issuedAt,
      exp: issuedAt + 300,
      jti: issuanceId,
      cnf: { jwk: holderKey },
      _sd_alg: 'sha-256',
      _sd: [hash(disclosure).digest('base64url')],
    }, signingKeyId, tenant.tenantVaultId, 'vc_sign', { typ: 'dc+sd-jwt' });
    return { issuanceId, credential: `${credential}~${disclosure}~` };
  }

  private async getSigningKeyId(tenant: ProfessionalWalletTenant): Promise<string> {
    const algorithm = tenant.credentialSigningAlgorithm ?? 'ES256';
    // The default credential slot excludes communication keys even on a historical tenant.
    const key = await this.dependencies.kms.getPublicVerificationKey(
      tenant.tenantVaultId, algorithm === 'ES256' ? algorithm : undefined, 'vc_sign',
    );
    if (!key?.kid || !('alg' in key) || key.alg !== algorithm) throw new Error('Tenant wallet credential signing key is unavailable.');
    return key.kid;
  }

  private async read(tenant: ProfessionalWalletTenant, reference: string) {
    const document = opaqueReference.test(reference)
      ? await this.dependencies.repository.get<ConfidentialStorageDoc>(tenant.tenantVaultId, reference, section())
      : undefined;
    if (!document || document.status !== 'active') throw new WalletAuthorizationError('Wallet authorization is unavailable.');
    const authorization = await this.dependencies.kms.unprotectConfidentialData<WalletAuthorization>(document, tenant.tenantVaultId);
    if (!authorization || authorization.expiresAt <= this.now()
      || authorization.tenantDid !== tenant.tenantDid || authorization.configurationId !== tenant.configurationId
      || (authorization.credentialSigningAlgorithm ?? 'ES256') !== (tenant.credentialSigningAlgorithm ?? 'ES256')
      || authorization.vct !== tenant.vct || authorization.authorizationAudience !== tenant.authorizationAudience) {
      throw new WalletAuthorizationError('Wallet authorization is unavailable.');
    }
    return { authorization, sequence: document.sequence ?? 0 };
  }

  private async write(tenant: ProfessionalWalletTenant, reference: string, authorization: WalletAuthorization, sequence: number) {
    const document = await this.dependencies.kms.protectConfidentialData({
      id: reference, status: 'active', content: authorization, sequence,
    } as ConfidentialStorageDoc, tenant.tenantVaultId);
    if (document.content || !await this.dependencies.repository.put(tenant.tenantVaultId, [document], section())) {
      throw new Error('Wallet authorization could not be stored securely.');
    }
  }

  private async reserveOnce(tenant: ProfessionalWalletTenant, step: string, id: string, expiresAt: number) {
    const remaining = expiresAt - this.now();
    const replayKey = `wallet-issuance:${tenant.tenantVaultId}:${step}:${hash(id).digest('hex')}`;
    if (remaining <= 0 || !await this.dependencies.replay.reserveIfNotExists(replayKey, remaining)) {
      throw new WalletAuthorizationError('Wallet authorization is expired or was already used.');
    }
  }

  private now() {
    return this.dependencies.now?.() ?? Math.floor(Date.now() / 1000);
  }
}
