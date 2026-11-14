import { SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { testConfigDataHost, testConfigTenant1 } from "./organization.data";

// Terms of service accepted for running the software service
export const testServiceTermsClaimsForHost = {
    [SchemaOrgServiceClaim.Category]: testConfigDataHost.provider?.service.sectorCategory, // sector type
    [SchemaOrgServiceClaim.IdentifierReference]: testConfigDataHost.provider?.service.identifier,
    [SchemaOrgServiceClaim.TermsOfService]: testConfigDataHost.provider?.service.termsOfService,
    [SchemaOrgServiceClaim.ServiceType]: testConfigDataHost.provider?.service.serviceType,
}

// Terms of service accepted by the tenant's registrant (the `admin` or tenant's `controller`)
export const testServiceTermsClaimsForTenant1 = {
    [SchemaOrgServiceClaim.Category]: testConfigTenant1.provider?.service.category, // sector type
    [SchemaOrgServiceClaim.IdentifierReference]: testConfigTenant1.provider?.service.identifier,
    [SchemaOrgServiceClaim.TermsOfService]: testConfigTenant1.provider?.service.termsOfService,
    [SchemaOrgServiceClaim.ServiceType]: testConfigTenant1.provider?.service.serviceType,
}