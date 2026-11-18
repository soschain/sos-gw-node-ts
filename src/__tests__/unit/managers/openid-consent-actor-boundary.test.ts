// Flow contract: consent for one canonical employee never authorizes a sibling; only an exact organization DID grants organization-level access.
import { OpenIdAuthManager } from '../../../managers/OpenIdAuthManager';
import { parseActorFromSub } from 'sos-data-utils-ts/actor-identity';
import { buildOrganizationEmployeeDidWeb, StableActorContactKinds } from 'antifraud-data-utils-ts/organization-identity';
import { ClaimConsent } from 'fhir-data-utils-ts/claims';
import { EXAMPLE_EMAIL_PROFESSIONAL, EXAMPLE_EMAIL_CONTROLLER_ORG } from 'sos-data-utils-ts/gateway-flow-examples';
import {
  EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONTEXT,
  EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONSUMER_AUTHORIZED_SIGNATORY_DID,
} from 'sos-data-utils-ts/gateway-resource-flow-examples';

type ActorMatcher = {
  resolveRuleMatchKind(rule: Readonly<Record<string, unknown>>, actor: ReturnType<typeof parseActorFromSub>,
    actorEmail: string | undefined, jurisdiction: string): 'direct' | 'organization' | 'jurisdiction' | undefined;
};
const manager = Object.create(OpenIdAuthManager.prototype) as ActorMatcher;
const organization = EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONTEXT.consumerOrganizationDid;
const actor = (contact: string) => parseActorFromSub(buildOrganizationEmployeeDidWeb({
  organizationDidWeb: organization, contactKind: StableActorContactKinds.Email,
  contact, role: EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONTEXT.actorRole,
}));
const first = actor(EXAMPLE_EMAIL_PROFESSIONAL);
const other = actor(EXAMPLE_EMAIL_CONTROLLER_ORG);
const match = (ruleActor: string, requester = first) => manager.resolveRuleMatchKind(
  { [ClaimConsent.actorIdentifier]: ruleActor }, requester, undefined,
  EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONTEXT.jurisdiction,
);

describe('OpenID consent actor boundaries', () => {
  it('matches the exact employee as a direct grant', () => expect(match(first.sub)).toBe('direct'));
  it('rejects another employee in the same hosted organization', () => expect(match(first.sub, other)).toBeUndefined());
  it('matches the exact organization for the first employee', () => expect(match(organization)).toBe('organization'));
  it('matches the exact organization for another employee', () => expect(match(organization, other)).toBe('organization'));
  it('does not treat another descendant identity as an organization grant', () =>
    expect(match(EXAMPLE_INTER_TENANT_ACCESS_CONTRACT_CONSUMER_AUTHORIZED_SIGNATORY_DID)).toBeUndefined());
});
