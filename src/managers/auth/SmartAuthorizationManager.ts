// src/managers/auth/SmartAuthorizationManager.ts

import { IAuthorizationManager } from './IAuthorizationManager';
import { ClientAccessTokenClaims as IAccessTokenClaims } from 'antifraud-data-utils-ts/openid-contracts';

export class SmartAuthorizationManager implements IAuthorizationManager {
  public async canAccess(
    claims: IAccessTokenClaims,
    resource: any,
    action: 'read' | 'write' | 'create' | 'delete',
    consentId?: string,
  ): Promise<boolean> {
    // For now, allow all access.
    return true;
  }
}
