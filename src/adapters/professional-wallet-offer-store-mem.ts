import type { StoredWalletOffer, WalletOfferStore } from 'antifraud-sdk-node-ts';

/** In-process store for the single-instance local test profiles. */
export function createMemoryWalletOfferStore(): WalletOfferStore {
  const offers = new Map<string, StoredWalletOffer>();
  const usedNonces = new Map<string, number>();
  return {
    async create(reference, offer) {
      const now = Date.now();
      for (const [key, value] of offers) {
        if (value.expiresAt <= now) offers.delete(key);
      }
      for (const [key, expiry] of usedNonces) {
        if (expiry <= now) usedNonces.delete(key);
      }
      if (offers.has(reference)) throw new Error('Wallet offer already exists.');
      offers.set(reference, offer);
    },
    async read(reference) {
      return offers.get(reference);
    },
    async compareAndSet(reference, revision, offer) {
      const current = offers.get(reference);
      if (!current || current.revision !== revision || current.state !== 'offered'
        || current.expiresAt <= Date.now()) return false;
      offers.set(reference, offer);
      return true;
    },
    async consumeForIssuance({ reference, revision, nonceDigest, nonceExpiresAt }) {
      const current = offers.get(reference);
      const now = Date.now();
      if (!current || current.revision !== revision || current.state !== 'authorized'
        || current.expiresAt <= now || nonceExpiresAt <= now || usedNonces.has(nonceDigest)) return false;
      usedNonces.set(nonceDigest, nonceExpiresAt);
      offers.set(reference, { ...current, state: 'used', revision: revision + 1 });
      return true;
    },
  };
}
