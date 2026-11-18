import { createHash } from 'node:crypto';
import type { Firestore } from 'firebase-admin/firestore';
import type { IReplayProtectionStore } from './replay-protection-store';

/** Existing database port only: this adapter does not initialize a Firebase app or choose custody. */
export type ReplayFirestorePort = Pick<Firestore, 'collection' | 'runTransaction'>;

/** Atomic replay reservations shared by processes using the same dedicated collection. */
export class ReplayProtectionStoreFirestore implements IReplayProtectionStore {
  private readonly collectionName: string;
  private readonly keyPrefix: string;

  constructor(private readonly db: ReplayFirestorePort, options: { collectionName: string; keyPrefix?: string }) {
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(options.collectionName)) {
      throw new Error('Replay Firestore collection must be a dedicated safe collection name.');
    }
    this.collectionName = options.collectionName;
    this.keyPrefix = options.keyPrefix ?? 'replay:jti';
    if (!this.keyPrefix.trim() || this.keyPrefix.length > 256) throw new Error('Replay key namespace is invalid.');
  }

  async reserveIfNotExists(key: string, ttlSeconds: number): Promise<boolean> {
    if (typeof key !== 'string' || !key.trim() || key.length > 4096) throw new Error('Replay key is invalid.');
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) throw new Error('Replay TTL must be a positive integer.');
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    if (!Number.isFinite(expiresAt.getTime())) throw new Error('Replay expiry is outside the supported date range.');
    const id = createHash('sha256').update(`${this.keyPrefix}:${key}`, 'utf8').digest('hex');
    const reference = this.db.collection(this.collectionName).doc(id);
    return this.db.runTransaction(async transaction => {
      const snapshot = await transaction.get(reference);
      const now = Date.now();
      if (snapshot.exists) {
        const value = snapshot.data()?.expiresAt;
        const previous = value instanceof Date ? value : value && typeof value.toDate === 'function' ? value.toDate() : undefined;
        if (!(previous instanceof Date) || !Number.isFinite(previous.getTime())) throw new Error('Persisted replay expiry is invalid.');
        if (previous.getTime() > now) return false;
      }
      const expiry = new Date(now + ttlSeconds * 1000);
      if (!Number.isFinite(expiry.getTime())) throw new Error('Replay expiry is outside the supported date range.');
      transaction.set(reference, { expiresAt: expiry });
      return true;
    });
  }
}
