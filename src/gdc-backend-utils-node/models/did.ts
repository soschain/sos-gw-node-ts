// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.
// File: gdc-backend-utils-node/models/did.ts

// Compatibility path for the SOS routing profile and neutral DID key relationships.
// The shared packages below own the definitions.
export type { GatewayDidDocument as DidDocument, GatewayDidService as DidService } from 'sos-data-utils-ts/gateway-did-profile';
export type { VerificationMethod } from 'antifraud-data-utils-ts/did-document';
export type { ServiceEndpointSelector, SecureServiceEndpointSelector } from 'sos-data-utils-ts/confidential-job';

