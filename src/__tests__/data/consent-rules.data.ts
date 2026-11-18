// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// src/__tests__/data/consent-rules.data.ts
// Always create JSDoc, do not use strings inline in keys nor values, use types instead, and reuse the data test examples.

import { EXAMPLE_API_ORGANIZATION_DID } from 'sos-data-utils-ts/gateway-flow-examples';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
import { HealthcareConsentActions } from 'sos-data-utils-ts/gateway-profile-values';
import { HealthcareConsentPurposes } from 'fhir-data-utils-ts';
import { EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_SUBJECT_DID } from 'sos-data-utils-ts/gateway-resource-flow-examples';
import { ClaimConsent, ConsentStatuses } from "fhir-data-utils-ts/claims";

const testConsentSubject = EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_SUBJECT_DID;

export const testConsentRulePermitOrgDid = {
  id: 'rule-org',
  '@context': 'org.hl7.fhir.api',
  [ClaimConsent.subject]: testConsentSubject,
  [ClaimConsent.identifier]: 'urn:uuid:rule-org',
  [ClaimConsent.decision]: 'permit',
  [ClaimConsent.status]: ConsentStatuses.Active,
  [ClaimConsent.actorIdentifier]: EXAMPLE_API_ORGANIZATION_DID,
  [ClaimConsent.actorRole]: HealthcareActorRoles.Physician,
  [ClaimConsent.action]: HealthcareConsentActions.AllergiesAndIntolerances,
  [ClaimConsent.purpose]: HealthcareConsentPurposes.Treatment,
  [ClaimConsent.date]: '2026-05-20',
} as const;

export const testConsentRulePermitJurisdiction = {
  id: 'rule-jurisdiction',
  '@context': 'org.hl7.fhir.api',
  [ClaimConsent.subject]: testConsentSubject,
  [ClaimConsent.identifier]: 'urn:uuid:rule-jurisdiction',
  [ClaimConsent.decision]: 'permit',
  [ClaimConsent.status]: ConsentStatuses.Active,
  [ClaimConsent.actorIdentifier]: 'urn:iso:3166:ES',
  [ClaimConsent.actorRole]: HealthcareActorRoles.Physician,
  [ClaimConsent.action]: HealthcareConsentActions.AllergiesAndIntolerances,
  [ClaimConsent.purpose]: HealthcareConsentPurposes.Treatment,
  [ClaimConsent.date]: '2026-05-20',
} as const;

export const testConsentRulePermitEmailWildcardRole = {
  id: 'rule-email',
  '@context': 'org.hl7.fhir.api',
  [ClaimConsent.subject]: testConsentSubject,
  [ClaimConsent.identifier]: 'urn:uuid:rule-email',
  [ClaimConsent.decision]: 'permit',
  [ClaimConsent.status]: ConsentStatuses.Active,
  [ClaimConsent.actorIdentifier]: 'doctor1@acme.org',
  [ClaimConsent.actorRole]: '*',
  [ClaimConsent.action]: HealthcareConsentActions.AllergiesAndIntolerances,
  [ClaimConsent.purpose]: HealthcareConsentPurposes.Treatment,
  [ClaimConsent.date]: '2026-05-20',
} as const;

export const testConsentRulePermitOrgDidMultiRole = {
  ...testConsentRulePermitOrgDid,
  id: 'rule-org-multirole',
  [ClaimConsent.identifier]: 'urn:uuid:rule-org-multirole',
  [ClaimConsent.actorRole]: `${HealthcareActorRoles.Physician},ISCO-08|2212`,
} as const;
