import { randomUUID } from 'node:crypto';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';

export type AsyncJobPayloadProtection = Pick<IKmsService, 'protectConfidentialData' | 'unprotectConfidentialData'>;
const PAYLOAD_FORMAT = 'async-job-payload/v1';

type ProtectedJobContent = {
  format: typeof PAYLOAD_FORMAT;
  // The v1 wire field names the storage namespace, originally a GCS bucket.
  bucket: string;
  reference: string;
  value: unknown;
};

export interface IAsyncJobPayloadStore {
  put(value: unknown): Promise<string>;
  get(reference: string): Promise<unknown>;
  delete(reference: string): Promise<void>;
}

export interface AsyncJobPayloadObjectStorage {
  write(reference: string, bytes: Buffer): Promise<void>;
  read(reference: string): Promise<Buffer>;
  delete(reference: string): Promise<void>;
}

/** Protects the job before any durable storage provider can receive it. */
export class AsyncJobPayloadStoreEncrypted implements IAsyncJobPayloadStore {
  private readonly prefix: string;

  constructor(
    private readonly storageNamespace: string,
    private readonly protection: AsyncJobPayloadProtection,
    private readonly storage: AsyncJobPayloadObjectStorage,
    prefix = 'async-jobs',
  ) {
    if (!storageNamespace.trim()) throw new Error('Async job payload storage namespace must not be empty.');
    this.prefix = prefix.replace(/^\/+|\/+$/g, '') || 'async-jobs';
  }

  async put(value: unknown): Promise<string> {
    const reference = `${this.prefix}/${randomUUID()}.json`;
    const content: ProtectedJobContent = {
      format: PAYLOAD_FORMAT,
      bucket: this.storageNamespace,
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
    await this.storage.write(
      reference,
      Buffer.from(JSON.stringify({ format: PAYLOAD_FORMAT, jwe: document.jwe }), 'utf8'),
    );
    return reference;
  }

  async get(reference: string): Promise<unknown> {
    this.assertOwnedReference(reference);
    const bytes = await this.storage.read(reference);
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
    if (content?.format !== PAYLOAD_FORMAT || content.bucket !== this.storageNamespace
      || content.reference !== reference || !Object.hasOwn(content, 'value')) {
      throw new Error('Async job payload does not match its storage reference.');
    }
    return content.value;
  }

  async delete(reference: string): Promise<void> {
    this.assertOwnedReference(reference);
    await this.storage.delete(reference);
  }

  private assertOwnedReference(reference: string): void {
    if (!reference.startsWith(`${this.prefix}/`) || reference.includes('..')) {
      throw new Error('Invalid async job payload reference.');
    }
  }
}
