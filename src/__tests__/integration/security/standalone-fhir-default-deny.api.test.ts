// Flow contract: 1. Submit a native Communication to the standalone route. 2. Neither absent authentication nor supplied claim-shaped metadata bypasses the default policy. Authorization invariant: rejection precedes any queue/persistence write.
import express from 'express';
import { createFhirRouter } from '../../../routes/fhir';
import { SmartAuthorizationManager } from '../../../managers/auth/SmartAuthorizationManager';
import { invokeExpress } from '../helpers/invokeExpress';

describe('standalone FHIR default authorization', () => {
  it.each([false, true])('rejects before enqueue (claim-shaped metadata: %s)', async withClaims => {
    const queue = { addJob: jest.fn() };
    const app = express();
    app.use(express.json());
    if (withClaims) app.use((req, _res, next) => {
      (req as any).claims = { iss: 'did:web:issuer.example', sub: 'did:web:actor.example', client_id: 'device', scope: 'fhir:Communication.create' };
      next();
    });
    app.use(createFhirRouter(queue as any, new SmartAuthorizationManager()));
    const response = await invokeExpress(app, {
      method: 'POST', url: '/v1/health-care/individual/org.hl7.fhir.r4/Communication',
      headers: { 'content-type': 'application/json' },
      body: { resourceType: 'Communication', partOf: [{ reference: 'Consent/example' }] },
    });
    expect(response.status).toBe(403);
    expect(queue.addJob).not.toHaveBeenCalled();
  });
});
