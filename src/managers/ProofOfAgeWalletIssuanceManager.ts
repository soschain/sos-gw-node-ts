import { createHash, randomBytes } from 'node:crypto';
import canonicalize from 'canonicalize';
import type { createOpenId4VciIssuer, WalletIssuanceCommand } from 'antifraud-sdk-node-ts';
import { IdentityAttestationCapability } from 'antifraud-data-utils-ts/identity-assurance';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { IReplayProtectionStore } from '../adapters/replay-protection-store';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import type { LedgerPresentationVerifier, IndividualWalletEligibility } from '../services/LedgerPresentationVerifier';
import { getEnvSectionId } from '../utils/section-env';
import { WalletAuthorizationError } from './ProfessionalWalletIssuanceManager';

type IssuerContext = Readonly<{ tenantVaultId: string; tenantDid: string; authorizationAudience: string }>;
type Presentation = Readonly<{ clientId: string; presentation: string }>;
type Member = Pick<IndividualWalletEligibility, 'actorDid' | 'subjectDid'>;
type HolderKey = Parameters<Parameters<typeof createOpenId4VciIssuer>[0]['issue']>[1];
type Projection = Readonly<{ docType: string; namespaces: Readonly<Record<string, Readonly<Record<string, boolean>>>> }>;
type Authorization = Readonly<IssuerContext & Presentation & Member & {
  evidenceRevision: string; projectionDigest: string; expiresAt: number;
}>;

const section = () => getEnvSectionId('proof-of-age-wallet-authorizations');
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const referencePattern = /^[A-Za-z0-9_-]{43}$/u;
const unavailable = () => new WalletAuthorizationError('Proof of Age wallet authorization is unavailable.');

function digest(projection: Projection): string {
  const content = canonicalize(projection);
  if (!content) throw unavailable();
  return hash(content);
}

function contextFor({ tenantVaultId, tenantDid, authorizationAudience }: IssuerContext): IssuerContext {
  return { tenantVaultId, tenantDid, authorizationAudience };
}

function commandFor(reference: string): WalletIssuanceCommand {
  return {
    capability: IdentityAttestationCapability.VerifyClaim,
    actorReference: `urn:sha256:${hash('proof-of-age:actor:' + reference)}`,
    subjectReference: `urn:sha256:${hash('proof-of-age:subject:' + reference)}`,
    verificationTransactionId: reference,
  };
}

/** Holds one encrypted grant while the wallet completes OpenID4VCI. */
export class ProofOfAgeWalletIssuanceManager {
  constructor(private readonly dependencies: {
    repository: Pick<IVaultRepository, 'get' | 'put' | 'delete'>;
    kms: Pick<IKmsService, 'protectConfidentialData' | 'unprotectConfidentialData'>;
    replay: IReplayProtectionStore;
    verify: LedgerPresentationVerifier['verifyIndividualWalletEligibility'];
    readApprovedEvidence(context: IssuerContext, member: Member): Promise<Readonly<{ revision: string; projection: Projection }> | undefined>;
    sign(projection: Projection, holder: HolderKey, context: IssuerContext): Promise<string>;
    now?: () => number;
  }) {}

  async authorize(tenant: IssuerContext, proof: Presentation): Promise<WalletIssuanceCommand> {
    const context = contextFor(tenant);
    const { actorDid, subjectDid, presentationId, expiresAt } = await this.verify(context, proof);
    const evidence = await this.dependencies.readApprovedEvidence(context, { actorDid, subjectDid });
    if (!evidence?.revision) throw this.evidenceUnavailable();
    await this.reserveOnce(context, 'presentation', `${proof.clientId}:${presentationId}`, expiresAt);
    const reference = randomBytes(32).toString('base64url');
    const authorization: Authorization = {
      ...context, clientId: proof.clientId, presentation: proof.presentation, actorDid, subjectDid,
      evidenceRevision: evidence.revision, projectionDigest: digest(evidence.projection), expiresAt,
    };
    const sealed = await this.dependencies.kms.protectConfidentialData({
      id: reference, status: 'active', sequence: 0, content: authorization,
    } as ConfidentialStorageDoc, context.tenantVaultId);
    if (sealed.content || !await this.dependencies.repository.put(context.tenantVaultId, [sealed], section())) {
      throw new Error('Proof of Age wallet authorization could not be stored securely.');
    }
    return commandFor(reference);
  }

  async issue(tenant: IssuerContext, command: WalletIssuanceCommand, holder: HolderKey): Promise<string> {
    const context = contextFor(tenant);
    const reference = command.verificationTransactionId;
    if (!referencePattern.test(reference) || Object.keys(command).length !== 4 ||
      Object.entries(commandFor(reference)).some(([name, value]) => command[name as keyof WalletIssuanceCommand] !== value)) {
      throw new WalletAuthorizationError('Invalid Proof of Age wallet authorization command.');
    }
    const stored = await this.dependencies.repository.get<ConfidentialStorageDoc>(context.tenantVaultId, reference, section());
    if (stored?.status !== 'active') throw unavailable();
    const authorization = await this.dependencies.kms.unprotectConfidentialData<Authorization>(stored, context.tenantVaultId);
    if (!authorization || authorization.expiresAt <= this.now() ||
      authorization.tenantVaultId !== context.tenantVaultId || authorization.tenantDid !== context.tenantDid ||
      authorization.authorizationAudience !== context.authorizationAudience) throw unavailable();
    const projection = await this.currentProjection(context, authorization);
    await this.reserveOnce(context, 'signing', reference, authorization.expiresAt);
    if (!await this.dependencies.repository.delete(context.tenantVaultId, reference, section())) throw unavailable();
    const credential = await this.dependencies.sign(projection, holder, context);
    await this.currentProjection(context, authorization);
    return credential;
  }

  private async currentProjection(context: IssuerContext, authorization: Authorization) {
    const { actorDid, subjectDid } = await this.verify(context, authorization);
    if (actorDid !== authorization.actorDid || subjectDid !== authorization.subjectDid ||
      authorization.expiresAt <= this.now()) throw unavailable();
    const evidence = await this.dependencies.readApprovedEvidence(context, { actorDid, subjectDid });
    if (!evidence || evidence.revision !== authorization.evidenceRevision) throw this.evidenceUnavailable();
    const projection = structuredClone(evidence.projection);
    if (digest(projection) !== authorization.projectionDigest) throw this.evidenceUnavailable();
    return projection;
  }

  private async verify(context: IssuerContext, { clientId, presentation }: Presentation) {
    try {
      return await this.dependencies.verify({ ...context, clientId, presentation });
    } catch {
      throw unavailable();
    }
  }

  private async reserveOnce(context: IssuerContext, step: string, value: string, expiresAt: number) {
    const ttl = expiresAt - this.now();
    const key = `proof-of-age-wallet:${context.tenantVaultId}:${step}:${hash(value)}`;
    if (ttl <= 0 || !await this.dependencies.replay.reserveIfNotExists(key, ttl)) throw unavailable();
  }

  private evidenceUnavailable() {
    return new WalletAuthorizationError('Approved Proof of Age evidence is unavailable or has changed.');
  }

  private now() {
    return this.dependencies.now?.() ?? Math.floor(Date.now() / 1000);
  }
}
