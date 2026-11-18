// Flow contract: professional assignment reads and histories invoke the exact employee-sc transactions and preserve decoded state.
import { jest } from '@jest/globals';
import { fileURLToPath } from 'node:url';
const evaluateTransaction = jest.fn<(...args: string[]) => Promise<Uint8Array>>();
const close = jest.fn();
jest.unstable_mockModule(fileURLToPath(new URL('../../../blockchain/fabric/v3/connect.ts', import.meta.url)), () => ({
  newGrpcConnection: jest.fn(async () => ({ close })),
  newGatewayConnection: jest.fn(async () => ({ close, getNetwork: async () => ({ getContract: () => ({ evaluateTransaction }) }) })),
}));
const { ManageAssetProfessionalAssignment } = await import('../../../blockchain/fabric/v3/manageAssetProfessionalAssignment');
describe('professional assignment canonical Fabric transactions', () => {
  beforeEach(() => { evaluateTransaction.mockReset(); });
  test('reads the assignment through its canonical employee-sc transaction', async () => {
    const asset = { assignmentLink: 'synthetic-assignment', status: 'active' };
    evaluateTransaction.mockResolvedValue(Buffer.from(JSON.stringify(asset)));
    await expect(new ManageAssetProfessionalAssignment({ channelName: 'identity-local' }).read('Org1MSP', 'synthetic-assignment')).resolves.toEqual(asset);
    expect(evaluateTransaction).toHaveBeenCalledWith('GetProfessionalAssignment', 'synthetic-assignment');
  });
  test('retains the supported assignment history transaction', async () => {
    evaluateTransaction.mockResolvedValue(Buffer.from('[]'));
    await expect(new ManageAssetProfessionalAssignment({ channelName: 'identity-local' }).history('Org1MSP', 'synthetic-assignment')).resolves.toEqual([]);
    expect(evaluateTransaction).toHaveBeenCalledWith('getProfessionalAssignmentHistory', 'synthetic-assignment');
  });
});
