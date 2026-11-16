// src/routes/handlers/discovery/ping.handler.ts
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { v4 as uuidv4 } from 'uuid';
import type { Request, Response } from 'express';
import type { ICryptography } from 'antifraud-data-utils-ts/cryptography';
import type { FhirBundle } from 'fhir-data-utils-ts/fhir-types';
import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';
import { HttpMediaTypes, HttpStatusCodes } from 'sos-data-utils-ts/bff-wire-contract';
import { createOperationOutcome } from '../../../utils/outcome';
import { IDecodedDidcommPayload } from 'sos-data-utils-ts/confidential-job';
import { IssueLevel, IssueType } from 'fhir-data-utils-ts/operation-outcome';

/**
 * Encodes a hostname from a request's Host header for use in a did:web.
 * Example: 'localhost:3000' -> 'localhost%3A3000'
 */
function getEncodedHostFromRequest(req: Request): string {
  const host = req.get('host') || 'localhost';
  return host.replace(':', '%3A');
}

/**
 * Handles requests to the ping endpoint (e.g., `/.well-known/ping`).
 * This endpoint serves two purposes:
 * 1. A basic health check to confirm the service is running.
 * 2. A demonstration of the API's content negotiation capabilities.
 *
 * The structure of the response varies based on the client's `Accept` header,
 * showcasing the different data formats the API supports.
 */
export const pingHandler = (cryptography: Pick<ICryptography, 'jwsToCompact'>) => async (req: Request, res: Response) => {
    const tenantId = res.locals.tenantId as string;

    // 1. Create the canonical response body (the Bundle). This is the base data structure.
    const responseBundle = {
        type: 'batch-response',
        meta: {
            timestamp: new Date().toISOString(),
            tenantId: tenantId,
        },
        data: [ createOperationOutcome(IssueLevel.Information, IssueType.Throttled, 'Ping successful') ],
    };

    const acceptedType = req.accepts([HttpMediaTypes.Json, HttpMediaTypes.FhirJson, 'application/x-www-form-urlencoded']);

    switch (acceptedType) {
        case HttpMediaTypes.FhirJson:
            // Export the actual resources, rather than treating a raw outcome as an entry wrapper.
            const responseBundleFhir: FhirBundle = {
                resourceType: ResourceTypesFhirR4.Bundle,
                type: responseBundle.type,
                total: responseBundle.data.length,
                entry: responseBundle.data.map(resource => ({
                    resource: { ...resource },
                    response: { status: String(HttpStatusCodes.Ok) },
                })),
            };
            res.type(HttpMediaTypes.FhirJson).json(responseBundleFhir);
            break;

        case 'application/x-www-form-urlencoded':
            // This fixed unsigned compact representation carries no signature/authenticity proof.
            // Retain the request Host-derived issuer label for the existing ping wire profile.
            const issuerDid = `did:web:${getEncodedHostFromRequest(req)}`;
            const responsePayload: IDecodedDidcommPayload = {
                jti: uuidv4(),
                type: 'ping-response',
                thid: `ping-${Date.now()}`,
                iss: issuerDid,
                aud: 'anonymous',
                exp: Math.floor(Date.now() / 1000) + 300, // Expires in 5 minutes
                body: responseBundle,
            };
            const jws = cryptography.jwsToCompact({ protected: { alg: 'none' }, payload: responsePayload, signature: '' });
            res.type('application/x-www-form-urlencoded').send(`response=${jws}`);
            break;

        case HttpMediaTypes.Json:
        default:
            // For standard JSON API clients, we return the canonical bundle directly,
            // without the unsigned compact envelope.
            res.json(responseBundle);
            break;
    }
};
