// Flow contract: standalone FHIR authorization requires a server-owned policy; missing claims, absent policy and policy errors never grant access.
import { SmartAuthorizationManager } from '../../../managers/auth/SmartAuthorizationManager';

describe('standalone FHIR authorization policy', () => {
  const claims = { iss: 'did:web:issuer.example', sub: 'did:web:actor.example', aud: 'did:web:host.example', exp: 2000000000, iat: 1900000000, scope: 'fhir:Communication.create', client_id: 'registered-device' };
  const target = { resource: { resourceType: 'Communication' } } as any;
  it('denies when no authoritative policy is supplied', async () => {
    expect(await new SmartAuthorizationManager().canAccess(claims, target, 'create', 'consent-id')).toBe(false);
  });
  it('denies missing upstream authentication even if a policy is supplied', async () => {
    const authorize = jest.fn().mockResolvedValue(true);
    const manager = new (SmartAuthorizationManager as any)({ authorize });
    expect(await manager.canAccess(undefined, target, 'create', 'consent-id')).toBe(false);
    expect(authorize).not.toHaveBeenCalled();
  });
  it('requires an explicit positive decision for this exact request', async () => {
    const authorize = jest.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false).mockRejectedValueOnce(new Error('policy unavailable'));
    const manager = new (SmartAuthorizationManager as any)({ authorize });
    expect(await manager.canAccess(claims, target, 'create', 'consent-id')).toBe(true);
    expect(authorize).toHaveBeenCalledWith(claims, target, 'create', 'consent-id');
    expect(await manager.canAccess(claims, target, 'create', 'consent-id')).toBe(false);
    expect(await manager.canAccess(claims, target, 'create', 'consent-id')).toBe(false);
  });
});
