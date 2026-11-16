export { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';

/**
 * Existing GW-local lookup keys retained for consumer compatibility.
 * The canonical resource catalog is owned by fhir-data-utils-ts.
 */
export const GatewayLocalFhirResourceTypes = Object.freeze({
  OperationOutcome: 'OperationOutcome',
  Parameters: 'Parameters',
} as const);
