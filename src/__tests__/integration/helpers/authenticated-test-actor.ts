// Flow contract: integration authors use a deterministic verified identity, never an anonymous demo bearer.
import {
  EXAMPLE_CONTROLLER_DID,
  EXAMPLE_EMAIL_CONTROLLER_ORG,
} from 'sos-data-utils-ts/gateway-flow-examples';
import { invokeExpress } from './invokeExpress';
import { registerTokenVerifierAdapter } from '../../../auth/token-verifier-registry';
import {
  buildDeterministicIdTokenFixture,
  DeterministicJwtTokenVerifier,
} from '../../utils/deterministic-jwt-fixtures';

const TEST_ACTOR_VERIFIER = 'deterministic-integration-actor';
const TEST_ACTOR_ISSUER = 'did:web:bff.integration.example';
const TEST_ACTOR_AUDIENCE = 'gw-integration-audience';
const TEST_ACTOR_SEED = 'gw-authenticated-integration-actor-seed';

/** Installs one locally verified OIDC-style actor for route-to-worker tests. */
export async function configureAuthenticatedTestActor(input: Readonly<{actorDid?:string;email?:string}> = {}): Promise<{
  actorDid: string;
  authorizationHeader: string;
}> {
  const fixture = await buildDeterministicIdTokenFixture({
    seed: TEST_ACTOR_SEED,
    issuer: TEST_ACTOR_ISSUER,
    audience: TEST_ACTOR_AUDIENCE,
    subject: input.actorDid ?? EXAMPLE_CONTROLLER_DID,
    email: input.email ?? EXAMPLE_EMAIL_CONTROLLER_ORG,
  });
  registerTokenVerifierAdapter(TEST_ACTOR_VERIFIER, () => new DeterministicJwtTokenVerifier({
    issuer: TEST_ACTOR_ISSUER,
    audience: TEST_ACTOR_AUDIENCE,
    publicJwk: fixture.publicJwk,
  }));
  process.env.AUTH_TOKEN_VERIFIER = TEST_ACTOR_VERIFIER;
  process.env.DEMO_ALLOW_INSECURE_BEARER = 'false';
  return {
    actorDid: input.actorDid ?? EXAMPLE_CONTROLLER_DID,
    authorizationHeader: `Bearer ${fixture.compactToken}`,
  };
}

/** Bind the signed upstream test account to the controller actually published by the onboarded fixture tenant. */
export async function configureAuthenticatedTenantController(input: Readonly<{
  app: Parameters<typeof invokeExpress>[0];tenantId:string;jurisdiction:string;sector:string;
}>): Promise<Awaited<ReturnType<typeof configureAuthenticatedTestActor>>> {
  const response=await invokeExpress(input.app,{method:'GET',url:`/${input.tenantId}/cds-${input.jurisdiction}/v1/${input.sector}/.well-known/did.json`});
  if(response.status!==200)throw new Error('The fixture tenant DID document is unavailable.');
  const did=JSON.parse(response.text) as {controller?:string|string[]};
  const controllers=(Array.isArray(did.controller)?did.controller:[did.controller]).filter((value):value is string=>typeof value==='string'&&Boolean(value));
  if(controllers.length!==1)throw new Error('The fixture tenant must publish its exact current controller.');
  return configureAuthenticatedTestActor({actorDid:controllers[0]});
}
