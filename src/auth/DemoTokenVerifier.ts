import { isLocalDemoSecurityMode } from '../security/runtime-security-policy';
// src/auth/DemoTokenVerifier.ts
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { ITokenVerifier, VerificationResult } from "./ITokenVerifier";

/** Reads demonstration claims only after explicitly selecting the local demo profile. */
export class DemoTokenVerifier implements ITokenVerifier {
  public async verify(token: string): Promise<VerificationResult> {
    if (!isLocalDemoSecurityMode()) return { valid: false, error: 'Demo authentication is unavailable outside explicit local demo.' };
    try {
      // Split the JWT into its three parts.
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Token is not a valid JWT format.' };
      }
      
      // Decode the payload part (the second part).
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));

      // In demo mode, we assume the token is valid if we can decode it.
      return { valid: true, payload: payload };

    } catch (error: any) {
      console.error(`[DemoTokenVerifier] Failed to decode token: ${error.message}`);
      return { valid: false, error: `Failed to decode token: ${error.message}` };
    }
  }
}
