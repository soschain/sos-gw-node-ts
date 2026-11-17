// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Demo transport is explicit; signing headers and process-owned key cleanup
// remain delegated to the real KMS without replacing signed token bytes.
import { REPOSITORY_SAFE_EXAMPLES as examples } from 'sos-data-utils-ts/repository-privacy';
import { DemoKmsService } from '../../../services/DemoKmsService';

describe('local demo KMS profile', () => {
  const saved = { ...process.env };
  beforeEach(() => { process.env.NODE_ENV = 'test'; process.env.NETWORK_MODE = 'test'; process.env.DEPLOYMENT_ENV = 'local'; process.env.SECURITY_MODE = 'demo'; });
  afterEach(() => { process.env = { ...saved }; });
  it('does not enable demo custody in a strict local test', () => {
    process.env.SECURITY_MODE = 'strict';
    expect(() => new DemoKmsService({} as any)).toThrow(/demo/i);
  });
  it('preserves the protected presentation header passed to the real signer', async () => {
    const signer = { createCompactJws: jest.fn().mockResolvedValue(examples.resourceUuid) };
    const service = new DemoKmsService(signer as any) as any;
    const payload = { nonce: examples.resourceUuid }; const header = { typ: 'vp+jwt' };
    await service.createCompactJws(payload, examples.resourceUuid, examples.tenantId, 'comm_sig', header);
    expect(signer.createCompactJws).toHaveBeenCalledWith(payload, examples.resourceUuid, examples.tenantId, 'comm_sig', header);
  });
  it('closes the wrapped process-owned key resource', () => {
    const signer = { destroy: jest.fn() }; const service = new DemoKmsService(signer as any) as any;
    service.destroy(); expect(signer.destroy).toHaveBeenCalledTimes(1);
  });
});
