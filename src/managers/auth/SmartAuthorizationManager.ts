import type { IAuthorizationManager } from './IAuthorizationManager';
import type { ClientAccessTokenClaims } from 'antifraud-data-utils-ts/openid-contracts';
import type { BundleEntry } from 'sos-data-utils-ts/bundle-contract';

/** Standalone native-FHIR requests require an explicit server-owned authorization policy. */
export class SmartAuthorizationManager implements IAuthorizationManager {
  constructor(private readonly options: Readonly<{ authorize?: IAuthorizationManager['canAccess'] }> = {}) {}

  public async canAccess(
    claims: ClientAccessTokenClaims,
    resource: BundleEntry,
    action: string,
    consentId?: string,
  ): Promise<boolean> {
    if (!claims?.iss || !claims.sub || !claims.client_id || !this.options.authorize) return false;
    try {
      return await this.options.authorize(claims, resource, action, consentId) === true;
    } catch {
      return false;
    }
  }
}
