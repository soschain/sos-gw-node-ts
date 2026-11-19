import { Storage } from '@google-cloud/storage';
import type { AsyncJobPayloadObjectStorage } from './async-job-payload-store';

export class AsyncJobPayloadObjectStorageGcs implements AsyncJobPayloadObjectStorage {
  constructor(
    private readonly bucketName: string,
    private readonly storage = new Storage(),
  ) {
    if (!bucketName.trim()) throw new Error('GCP_PUBSUB_JOB_BUCKET must not be empty.');
  }

  async write(reference: string, bytes: Buffer): Promise<void> {
    await this.storage.bucket(this.bucketName).file(reference).save(bytes, {
      contentType: 'application/json',
      resumable: false,
      metadata: { cacheControl: 'no-store' },
    });
  }

  async read(reference: string): Promise<Buffer> {
    const [bytes] = await this.storage.bucket(this.bucketName).file(reference).download();
    return bytes;
  }

  async delete(reference: string): Promise<void> {
    await this.storage.bucket(this.bucketName).file(reference).delete({ ignoreNotFound: true });
  }
}
