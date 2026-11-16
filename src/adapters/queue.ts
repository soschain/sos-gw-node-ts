// src/adapters/queue.ts

import { JobRequest } from 'sos-data-utils-ts/confidential-job';


export interface QueueAdapter {
  addJob(jobName: string, request: JobRequest, priority?: number): Promise<void>;
  close?(): Promise<void>;
}
