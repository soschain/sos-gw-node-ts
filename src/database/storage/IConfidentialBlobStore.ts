import type { ConfidentialBlobInfo } from 'sos-data-utils-ts/confidential-storage';
import type { ConfidentialBlobReader, ConfidentialBlobStore } from 'sos-sdk-core-ts/confidential-storage-persistence';

/** Compatibility name for the shared blob pointer data contract. */
export type PutConfidentialBlobResult = ConfidentialBlobInfo;
/** Raw payload read through the shared runtime port. */
export type ConfidentialBlobPayload = Awaited<ReturnType<ConfidentialBlobReader['get']>>;

/** Gateway adapters supply an explicit provider for the common encrypted-blob port. */
export interface IConfidentialBlobStore extends ConfidentialBlobStore {
  readonly provider: string;
}
