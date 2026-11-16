// Flow contract: draining the memory queue waits for every worker and response-store write, including failed jobs, before reporting idle.
import { jest } from '@jest/globals';
import { QueueAdapterMem } from '../../../adapters/queue-mem';
import { AsyncResponseStoreMem, type IAsyncResponseStore } from '../../../adapters/async-response-store.mem';
import type { Worker } from '../../../worker';
import { DCR_REGISTRATION_JOB } from '../../data/example-jobs';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}

describe('memory queue drain', () => {
  let queue: QueueAdapterMem | undefined;
  beforeEach(() => { jest.useFakeTimers(); });
  afterEach(() => { queue?.stop(); jest.useRealTimers(); jest.restoreAllMocks(); });

  it('waits for a dequeued worker and the final response-store write', async () => {
    const processing = deferred<string>();
    const persistence = deferred<void>();
    const set = jest.fn<IAsyncResponseStore['set']>(() => persistence.promise);
    const store: IAsyncResponseStore = { get: () => undefined, set, delete: () => {} };
    const worker = { process: jest.fn<Worker['process']>(() => processing.promise) };
    queue = new QueueAdapterMem(store, worker as unknown as Worker);
    await queue.addJob('example-job', structuredClone(DCR_REGISTRATION_JOB));
    await jest.advanceTimersByTimeAsync(50);
    let drained = false;
    const drain = queue.waitForEmptyQueue().then(() => { drained = true; });
    await Promise.resolve();
    expect(drained).toBe(false);
    processing.resolve('encrypted-response');
    await jest.advanceTimersByTimeAsync(0);
    expect(set).toHaveBeenCalledTimes(1);
    expect(drained).toBe(false);
    persistence.resolve();
    await jest.advanceTimersByTimeAsync(50);
    await drain;
    expect(drained).toBe(true);
  });

  it('does not report idle while another queued or active job remains', async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const worker = { process: jest.fn<Worker['process']>().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise) };
    queue = new QueueAdapterMem(new AsyncResponseStoreMem(), worker as unknown as Worker);
    await queue.addJob('example-first', structuredClone(DCR_REGISTRATION_JOB));
    await queue.addJob('example-second', structuredClone(DCR_REGISTRATION_JOB));
    await jest.advanceTimersByTimeAsync(100);
    let drained = false;
    const drain = queue.waitForEmptyQueue().then(() => { drained = true; });
    first.resolve('encrypted-first');
    await jest.advanceTimersByTimeAsync(50);
    expect(drained).toBe(false);
    second.resolve('encrypted-second');
    await jest.advanceTimersByTimeAsync(50);
    await drain;
    expect(drained).toBe(true);
  });

  it('records a failed job and releases its active processing count', async () => {
    const store = new AsyncResponseStoreMem();
    const worker = { process: jest.fn<Worker['process']>().mockRejectedValue(new Error('example processing failure')) };
    jest.spyOn(console, 'error').mockImplementation(() => {});
    queue = new QueueAdapterMem(store, worker as unknown as Worker);
    const request = structuredClone(DCR_REGISTRATION_JOB);
    await queue.addJob('example-failure', request);
    await jest.advanceTimersByTimeAsync(50);
    await queue.waitForEmptyQueue();
    expect(store.get(request.content!.thid!)?.status).toBe('FAILED');
  });
});
