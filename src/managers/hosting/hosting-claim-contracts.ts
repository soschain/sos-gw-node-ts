import { SchemaOrgOfferClaim, SchemaOrgOrderClaim, SchemaOrgOrganizationClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { toExternalClaimLabel } from '../../utils/claim-contract';

/**
 * Minimum gateway-enforced claim contracts for host legal-organization flows.
 *
 * These constants document the specific claim paths that GW itself treats as
 * non-optional in addition to any broader schema validation.
 */
export const HOST_TRANSACTION_REQUIRED_INPUT_CLAIMS = [
  SchemaOrgOrganizationClaim.AlternateName,
  SchemaOrgServiceClaim.Category,
] as const;

export const HOST_TRANSACTION_REQUIRED_OUTPUT_CLAIMS = [
  SchemaOrgOfferClaim.Identifier,
] as const;

export const HOST_ACTIVATE_REQUIRED_INPUT_CLAIMS = [
  SchemaOrgOrganizationClaim.AlternateName,
  SchemaOrgServiceClaim.Category,
  SchemaOrgOrganizationClaim.AddressCountry,
] as const;

export const HOST_ACTIVATE_REQUIRED_OUTPUT_CLAIMS = [
  SchemaOrgOfferClaim.Identifier,
] as const;

export const HOST_ORDER_REQUIRED_INPUT_CLAIMS = [
  SchemaOrgOrderClaim.AcceptedOfferIdentifier,
] as const;

export const HOST_ORDER_REQUIRED_INPUT_DISPLAY_CLAIMS = [
  toExternalClaimLabel(SchemaOrgOrderClaim.AcceptedOfferIdentifier),
] as const;
