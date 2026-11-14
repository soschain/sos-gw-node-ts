// src/__tests__/data/customer-onboarding.data.ts
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { JobAction, Resource, Format, Section, Sector } from 'gdc-common-utils-ts/models/urlPath';
import { IDecodedDidcommPayload } from 'sos-data-utils-ts/confidential-job';
import { JobRequest, JobStatus } from 'sos-data-utils-ts/confidential-job';
import { testCustomer1Data } from './customer.data';
import { testTenant1AddressCountry,
    testTenant1AlternateName,
    testTenant1UrlExternal,
    testTenant1DidWebExternal
} from './organization.data';

export const testCustomer1ServiceProviderAcceptedTerms = "https://provider.example.com/terms";
export const testCustomer1ServiceProviderCategory = Sector.HEALTH_CARE; // data from the individual consent (terms)

/** http://terminology.hl7.org/CodeSystem/v3-ActReason */
export const testCustomer1ServiceProviderAcceptedPurposeType = "http://terminology.hl7.org/CodeSystem/v3-ActReason|FAMRQT,PWATRNY,METAMGT,FRAUD,RECORDMGT,COVAUTH,TREAT,DISASTER,HPAYMT,MLTRAINING,ETREAT,HOPERAT,CAREMGT,HSYSADMIN,PATADMIN,PATSFTY";

// Terms of service accepted by the tenant's registrant (the `admin` or tenant's `controller`)
export const testCustomer1ServiceTermsClaims = {
    [SchemaOrgServiceClaim.Category]: testCustomer1ServiceProviderCategory, // sector type
    [SchemaOrgServiceClaim.TermsOfService]: testCustomer1ServiceProviderAcceptedTerms,
    [SchemaOrgServiceClaim.ServiceType]: testCustomer1ServiceProviderAcceptedPurposeType
}
export const testCustomer1OnboardingClaimsWithTerms = {
    [SchemaOrgPersonClaim.AlternateName]: testCustomer1Data.alternateName,
    [SchemaOrgPersonClaim.Identifier]: testCustomer1Data.uuidIdentifier,
    [SchemaOrgPersonClaim.Email]: testCustomer1Data.email,
    ...testCustomer1ServiceTermsClaims,
}

// --- Full Job Request for this User Story ---

/** Rule: path ends with slash `/`: `individual/org.schema/Person/` */
export const testCustomerOnboardingRelativePath = `${Section.individual}/${Format.Schema}/${Resource.Person}/`

/** https://api.acme.org/individual/org.schema/Person/_batch' */
export const testCustomerBatchRequestUrlExternal =
    `${testTenant1UrlExternal}${testCustomerOnboardingRelativePath}${JobAction._batch}`

/** OpenID Connect for Identity Assurance "Evidence" with one embedded PDF attached */ 
export const testCustomer1ConsentSignedOnboardingEvidenceEmbedded = {
    id: 'urn:multibase:<multibase58(multihash(SHA3-256(attachedbytes)))>',
    type: "application/pdf",
    // NOTE: allow only 1 PDF file for the terms/consent
    attachments: [{
        // 'content' is the data bytes encoded in Base64SafeUrl
        content: "Base64SafeUrl(raw-pdf-bytes)",
        // 'content_type' is a IANA media type
        content_type: "application/pdf",
    }]
}

/** Claims-first Bundle entry; business claims and evidence belong to the resource. */
export const testIndividualConsentSignedOnboardingEntry =     {
    resource: {
        resourceType: Resource.Person,
        meta: {
            claims: testCustomer1OnboardingClaimsWithTerms,
            verification: {
                evidence: [testCustomer1ConsentSignedOnboardingEvidenceEmbedded]
            }
        }
    },
    request: {
        method: 'POST',
        url: testCustomerOnboardingRelativePath
    },
    type: 'IndividualTerms',
};

// ===================================================================================
// USER STORY 1: Professional-Assisted Onboarding
// As a registration agent, I submit a complete profile for a new customer,
// including their public ID, personal details, a legal identifier, and
// evidence of their consent to activate the unified data index.
// ===================================================================================

// --- Batch Entries Constructed by the Professional App ---

export const testIndividualOnboardingBatchEntries = [
    // --- Entry 1: Core Profile & Anchor ---
    // Establishes the anchor ID, core data and proof of consent (terms).
    { ... testIndividualConsentSignedOnboardingEntry},

    // --- Entry 2: Legal Identity ---
    // Adds the Legal Identity. The anchor ID links it to the same individual.
    {
        resource: {
            resourceType: Resource.Person,
            meta: {
                claims: {
                    [SchemaOrgPersonClaim.Identifier]: testCustomer1Data.uuidIdentifier,
                    [SchemaOrgPersonClaim.IdentifierType]: testCustomer1Data.officialIdType,
                    [SchemaOrgPersonClaim.IdentifierValue]: testCustomer1Data.officialIdValue,
                }
            }
        },
        request: {
            method: 'POST',
            url: testCustomerOnboardingRelativePath
        },
        type: 'PersonalIdentity',
    }
];

// TODO: middleware to translate external url request to hosted path
// The tenantId is the simple alternateName (e.g., 'acme').
// The tenantVaultId (e.g., 'health-care_acme') is composed later (`getTenantVaultId`).
export const testCreateCustomerJobRequestProfessionalOnboarding: JobRequest = {
    tenantId: `${testTenant1AlternateName}`, // "acme"
    jurisdiction: `${testTenant1AddressCountry}`, // "US"
    sector: `${testCustomer1ServiceProviderCategory}`, // "health-care"
    section: `${Section.individual}`, // "individual"
    format: `${Format.Schema}`, // "org.schema"
    resourceType: `${Resource.Person}`, // "Person"
    action: `${JobAction._create}`, // "_create"
    content: {
        iss: 'did:web:professional.app.example.com', // Issuer of the request
        aud: testTenant1DidWebExternal, // 'did:web:api.acme.org',
        thid: 'thid-customer-prof-onboarding',
        jti: 'jti-customer-prof-onboarding',
        type: 'api+json',
        body: {
            data: testIndividualOnboardingBatchEntries,
        },
    },
    httpMethod: 'POST',
    // External url: 'https://api.acme.org/individual/org.schema/Person/_batch'
    requestUrl: testCustomerBatchRequestUrlExternal,
    id: 'job-id-customer-prof-onboarding',
    status: JobStatus.DRAFT,
    sequence: 0,
    createdAtTimestamp: 1672531200000, // Jan 1, 2023
};
