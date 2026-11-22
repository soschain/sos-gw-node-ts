import type {Firestore} from '@google-cloud/firestore'
import type {StoredWalletOffer, WalletOfferStore} from 'antifraud-sdk-node-ts'

const opaqueIdentifier = /^[A-Za-z0-9_-]{43}$/u

/** Persists one issuer's wallet grants and replay reservations across gateway instances. */
export function createFirestoreWalletOfferStore(firestore: Firestore, namespace: string): WalletOfferStore {
  if (!/^[a-z0-9][a-z0-9-]{0,95}$/u.test(namespace)) {
    throw new TypeError('Wallet offer storage requires a configured issuer namespace')
  }
  const collection = firestore.collection(`wallet-offers-${namespace}`)
  function document(prefix: 'offer' | 'nonce', id: string) {
    if (!opaqueIdentifier.test(id)) throw new TypeError('Invalid opaque wallet offer storage identifier')
    return collection.doc(`${prefix}_${id}`)
  }

  return {
    async create(reference, offer) {
      await document('offer', reference).create({...offer, deleteAfter: new Date(offer.expiresAt)})
    },

    async read(reference) {
      const snapshot = await document('offer', reference).get()
      const state = snapshot.data() as StoredWalletOffer | undefined
      if (!state || state.expiresAt <= Date.now()) return undefined
      const {command, configurationId, expiresAt, attempts, revision, pinDigest} = state
      return {command, configurationId, expiresAt, attempts, revision, pinDigest, state: state.state}
    },

    async compareAndSet(reference, revision, next) {
      const offer = document('offer', reference)
      return firestore.runTransaction(async transaction => {
        const current = (await transaction.get(offer)).data() as StoredWalletOffer | undefined
        if (!current || current.state !== 'offered' || current.revision !== revision || current.expiresAt <= Date.now()
          || next.revision !== revision + 1 || (next.state !== 'offered' && next.state !== 'authorized')) return false
        transaction.set(offer, {...next, deleteAfter: new Date(next.expiresAt)})
        return true
      })
    },

    async consumeForIssuance({reference, revision, nonceDigest, nonceExpiresAt}) {
      const offer = document('offer', reference)
      const nonce = document('nonce', nonceDigest)
      return firestore.runTransaction(async transaction => {
        const [offerSnapshot, nonceSnapshot] = await transaction.getAll(offer, nonce)
        const current = offerSnapshot?.data() as StoredWalletOffer | undefined
        const now = Date.now()
        if (!current || !nonceSnapshot || nonceSnapshot.exists || current.state !== 'authorized' || current.revision !== revision
          || current.expiresAt <= now || nonceExpiresAt <= now) return false
        transaction.create(nonce, {deleteAfter: new Date(nonceExpiresAt)})
        transaction.update(offer, {state: 'used', revision: revision + 1})
        return true
      })
    },
  }
}
