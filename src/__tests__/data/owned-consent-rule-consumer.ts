// Flow contract: canonical ConsentRule types retain valid draft fields and reject malformed selectors/decisions without creating authorization.
import type { ConsentRule } from 'fhir-data-utils-ts';
import { ClaimConsent, ConsentDecisions, ConsentStatuses } from 'fhir-data-utils-ts';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareActorRoles } from 'sos-data-utils-ts/healthcare-roles';
const draft: ConsentRule = {
 '@context':'org.hl7.fhir.api',
 [ClaimConsent.status]:ConsentStatuses.Draft,
 [ClaimConsent.decision]:ConsentDecisions.Permit,
 [ClaimConsent.action]:'read',
 [ClaimConsent.subject]:SAFE.didWeb,
 [ClaimConsent.actorIdentifier]:SAFE.didWeb,
 [ClaimConsent.actorRole]:HealthcareActorRoles.Dentist,
 [ClaimConsent.date]:new Date(0).toISOString(),
 [ClaimConsent.purpose]:'TREAT',
 [ClaimConsent.identifier]:'urn:uuid:'+SAFE.resourceUuid,
};
function consume(rule:ConsentRule):void{void rule}
consume(draft);
// @ts-expect-error selectors retain their scalar/CSV wire type
consume({...draft,[ClaimConsent.actorIdentifier]:[SAFE.didWeb]});
// @ts-expect-error decision is the governed permit/deny union
consume({...draft,[ClaimConsent.decision]:'allow'});
