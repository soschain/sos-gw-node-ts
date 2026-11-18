// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Verification bypasses belong only to the explicitly selected local demo.
// Neither a memory ledger nor a staging deployment grants identity or access.
import { ClearingHouseService } from '../../../services/ClearingHouseService';

describe('Clearing House verification profiles', () => {
  const original = { ...process.env };
  afterEach(() => { process.env = { ...original }; });

  it.each(['test', 'test-network', 'network'])('rejects stub in a non-demo %s profile', async network => {
    process.env.NODE_ENV = network === 'network' ? 'production' : 'test';
    process.env.DEPLOYMENT_ENV = network === 'network' ? 'production' : 'staging';
    process.env.NETWORK_MODE = network;
    process.env.SECURITY_MODE = 'strict';
    process.env.CLEARING_HOUSE_MODE = 'stub';
    // Malformed input deliberately checks that a profile cannot grant verification.
    await expect(new ClearingHouseService().verifyVpToken({ vpToken: '', acrValues: [] }))
      .rejects.toThrow(/demo|stub|verif/i);
  });
});
