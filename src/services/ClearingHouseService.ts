import { HttpRequestMethods } from 'sos-data-utils-ts/bff-wire-contract';
import type { ICryptography } from 'antifraud-data-utils-ts/cryptography';
import { verifyPinnedJwt, canonicalRequestDigest, assertSignedReceiptBinding } from 'antifraud-data-utils-ts/clearing-house';
export { verifyPinnedJwt, verifyPinnedDetachedJws } from 'antifraud-data-utils-ts/clearing-house';
import { createHash, randomUUID } from 'node:crypto';
import { isLocalDemoSecurityMode } from '../security/runtime-security-policy';
import type { TrustRegistryVerificationResult } from '../adapters/trust-registry.adapter';
import { assertTenantClearingHouseTrust, resolveConfiguredClearingHouseTrust, type TenantClearingHouseTrust } from './tenant-clearing-house-trust';

export type ClearingHouseVerificationRequest = {
  tenantDid?: string;
  /** Trusted in-process routing context; never serialized into backend requests. */
  tenantVaultId?: string;
  /** Supplied only after registered client authentication or verified index-token validation. */
  authenticatedClientId?: string;
  /** Internal owner of the existing DCR; never accepted from backend request bodies. */
  holderVaultId?: string;
  vpToken: string;
  presentationSubmission?: unknown;
  acrValues: string[];
  tokenIssuer?: string;
  tokenSubject?: string;
  tokenScope?: string;
  tokenPurpose?: string;
  consentIdentifiers?: string[];
};
export type ClearingHouseVerificationResult = {
  /** Native, in-process activation authority. Remote receipts never populate this field. */
  activationEvidenceSource?: 'ica';
  acr: string; amr?: string[]; vpHash?: string; ledgerVerified: boolean; trustChecks?: TrustRegistryVerificationResult };
export interface IClearingHouseService {
  verifyVpToken(request: ClearingHouseVerificationRequest): Promise<ClearingHouseVerificationResult>;
}

export class ClearingHouseService implements IClearingHouseService {
  constructor(private readonly options: {
    resolveTrust?: (tenantDid: string) => TenantClearingHouseTrust | Promise<TenantClearingHouseTrust>;
    now?: () => number;
    cryptography?: ICryptography;
    allowLocalTestEndpoint?: boolean;
    localVerifier?: IClearingHouseService;
    signClientAssertion?: (input: { tenantDid: string; tenantVaultId?: string; audience: string; requestHash: string }) => Promise<string>;
  } = {}) {}

  async verifyVpToken(request: ClearingHouseVerificationRequest): Promise<ClearingHouseVerificationResult> {
    const mode = (process.env.CLEARING_HOUSE_MODE || (isLocalDemoSecurityMode() ? 'stub' : this.options.localVerifier ? 'local' : 'remote')).toLowerCase();
    if (mode === 'local') {
      if (!this.options.localVerifier) throw new Error('Local Clearing House verifier is not configured.');
      return this.options.localVerifier.verifyVpToken(request);
    }
    const hash = createHash('sha256').update(request.vpToken).digest('hex');
    if (mode === 'stub' && isLocalDemoSecurityMode()) {
      return { acr: request.acrValues[0], amr: ['openid4vp', 'vc'], vpHash: hash, ledgerVerified: true };
    }
    if (mode !== 'remote') throw new Error('Unsupported Clearing House mode: simulation is restricted to explicit local demo.');
    const tenantDid = String(request.tenantDid || '').trim();
    const trust = await (this.options.resolveTrust || resolveConfiguredClearingHouseTrust)(tenantDid);
    const endpoint = assertTenantClearingHouseTrust(trust, tenantDid, this.options.allowLocalTestEndpoint);
    const nonce = randomUUID();
    const body = JSON.stringify({ nonce, tenant_did: tenantDid, vp_token: request.vpToken, presentation_submission: request.presentationSubmission,
      acr_values: request.acrValues, token_issuer: request.tokenIssuer, token_subject: request.tokenSubject,
      token_scope: request.tokenScope, client_id: request.authenticatedClientId, token_purpose: request.tokenPurpose, consent_identifiers: request.consentIdentifiers });
    if (!this.options.signClientAssertion) throw new Error('Signed Clearing House request authentication is not configured.');
    const assertion = await this.options.signClientAssertion({ tenantDid, tenantVaultId: request.tenantVaultId, audience: endpoint.href,
      requestHash: canonicalRequestDigest(JSON.parse(body)) });
    const response = await fetch(endpoint, {
      method: HttpRequestMethods.Post, redirect: 'error', signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/json', accept: 'application/jwt', authorization: `Bearer ${assertion}` }, body,
    });
    if (!response.ok) throw new Error(`Clearing House verification failed (${response.status}).`);
    const compact = (await response.text()).trim();
    if (compact.length > 1_048_576 || compact.split('.').length !== 3) throw new Error('Clearing House requires a signed JWT response.');
    const payload = await verifyPinnedJwt(compact, trust.jwks, trust.issuer, this.options.now?.() ?? Math.floor(Date.now() / 1000), {
      audience: trust.audience, cryptography: this.options.cryptography,
    });
    const requiredClaims: Record<string, unknown> = { ledger_verified: true, vp_hash: hash };
    for (const [name, value] of Object.entries({ token_issuer: request.tokenIssuer, token_subject: request.tokenSubject,
      token_scope: request.tokenScope, client_id: request.authenticatedClientId, token_purpose: request.tokenPurpose,
      consent_identifiers: request.consentIdentifiers })) {
      if (value !== undefined) requiredClaims[name] = value;
    }
    assertSignedReceiptBinding(payload, { nonce, acceptedAssurance: request.acrValues, requiredClaims });
    return { acr: payload.acr as string, amr: payload.amr as string[], vpHash: hash, ledgerVerified: true, trustChecks: payload.trust_checks as TrustRegistryVerificationResult | undefined };
  }
}
