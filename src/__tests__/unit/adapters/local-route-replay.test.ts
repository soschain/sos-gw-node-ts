// Flow contract: a local strict router reserves replay keys in memory; enrolled or deployed routers require an explicitly composed durable store.
import { createLocalRouteReplayProtectionStore, ReplayProtectionStoreMem } from '../../../adapters/replay-protection-store';
describe('local route replay composition', () => {
  it('retains replay checks without requiring Demo for local cryptographic tests', async () => {
    const store = createLocalRouteReplayProtectionStore({ NODE_ENV: 'test', NETWORK_MODE: 'test', SECURITY_MODE: 'strict' });
    expect(store).toBeInstanceOf(ReplayProtectionStoreMem);
    expect(await store.reserveIfNotExists('local-request', 30)).toBe(true);
    expect(await store.reserveIfNotExists('local-request', 30)).toBe(false);
  });
  it.each(['test-network', 'network'])('requires explicit durable composition for %s', network => {
    expect(() => createLocalRouteReplayProtectionStore({ NODE_ENV: 'test', NETWORK_MODE: network })).toThrow(/explicit.*replay|durable/i);
  });
  it.each(['staging', 'production'])('cannot hide deployed %s behind network=test', deployment => {
    expect(() => createLocalRouteReplayProtectionStore({ NODE_ENV: 'test', DEPLOYMENT_ENV: deployment, NETWORK_MODE: 'test' })).toThrow(/explicit.*replay|durable/i);
  });
});
