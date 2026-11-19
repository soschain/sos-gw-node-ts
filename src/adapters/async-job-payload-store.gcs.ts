import { randomUUID } from 'node:crypto';
import { Storage } from '@google-cloud/storage';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';

export type AsyncJobPayloadProtection = Pick<IKmsService, 'protectConfidentialData' | 'unprotectConfidentialData'>;
const PAYLOAD_FORMAT = 'async-job-payload/v1';

type ProtectedJobContent = {
  format: typeof PAYLOAD_FORMAT;
  bucket: string;
  reference: string;
  value: unknown;
};

export interface IAsyncJobPayloadStore {
  put(value: unknown): Promise<string>;
  get(reference: string): Promise<unknown>;
  delete(reference: string): Promise<void>;
}

/** Stores complete job envelopes outside Pub/Sub's message-size boundary. */
export class AsyncJobPayloadStoreGcs implements IAsyncJobPayloadStore {
  private readonly storage: Storage;
  private readonly prefix: string;

  constructor(
    private readonly bucketName: string,
    private readonly protection: AsyncJobPayloadProtection,
    prefix = 'async-jobs',
    storage?: Storage,
  ) {
    if (!bucketName.trim()) throw new Error('GCP_PUBSUB_JOB_BUCKET must not be empty.');
    this.storage = storage || new Storage();
    this.prefix = prefix.replace(/^\/+|\/+$/g, '') || 'async-jobs';
  }

  async put(value: unknown): Promise<string> {
    const reference = `${this.prefix}/${randomUUID()}.json`;
    const content: ProtectedJobContent = {
      format: PAYLOAD_FORMAT,
      bucket: this.bucketName,
      reference,
      value,
    };
    const document = await this.protection.protectConfidentialData({
      id: reference,
      status: 'active',
      sequence: 1,
      content,
    }, 'host');
    if (!document.jwe || typeof document.jwe !== 'object') {
      throw new Error('Async job payload encryption returned no ciphertext.');
    }
    await this.storage.bucket(this.bucketName).file(reference).save(
      Buffer.from(JSON.stringify({ format: PAYLOAD_FORMAT, jwe: document.jwe }), 'utf8'),
      {
        contentType: 'application/json',
        resumable: false,
        metadata: { cacheControl: 'no-store' },
      },
    );
    return reference;
  }

  async get(reference: string): Promise<unknown> {
    this.assertOwnedReference(reference);
    const [bytes] = await this.storage.bucket(this.bucketName).file(reference).download();
    let record: Pick<ConfidentialStorageDoc, 'jwe'> & { format?: string };
    try {
      record = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new Error('Invalid encrypted async job payload.');
    }
    if (record?.format !== PAYLOAD_FORMAT || !record.jwe || typeof record.jwe !== 'object') {
      throw new Error('Async job payload is missing its encrypted envelope.');
    }
    const content = await this.protection.unprotectConfidentialData<ProtectedJobContent>({
      id: reference,
      status: 'active',
      sequence: 1,
      jwe: record.jwe,
    }, 'host');
    if (content?.format !== PAYLOAD_FORMAT || content.bucket !== this.bucketName
      || content.reference !== reference || !Object.hasOwn(content, 'value')) {
      throw new Error('Async job payload does not match its storage reference.');
    }
    return content.value;
  }

  async delete(reference: string): Promise<void> {
    this.assertOwnedReference(reference);
    await this.storage.bucket(this.bucketName).file(reference).delete({ ignoreNotFound: true });
  }

  private assertOwnedReference(reference: string): void {
    if (!reference.startsWith(`${this.prefix}/`) || reference.includes('..')) {
      throw new Error('Invalid async job payload reference.');
    }
  }
}
