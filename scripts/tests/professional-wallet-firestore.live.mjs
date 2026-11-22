// Flow contract: two independently started issuers share one Firestore emulator and can redeem each authorization code and issuer-wide nonce only once.
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import test from 'node:test'
import {Firestore} from '@google-cloud/firestore'
import {createPreAuthorizedWalletOffers, preAuthorizedCodeGrantType} from 'antifraud-sdk-node-ts'
import {createFirestoreWalletOfferStore} from '../../build/adapters/professional-wallet-offer-store-firestore.js'

const credentialIssuer = 'https://issuer.example'
const configurationId = 'synthetic-professional'
const command = Object.freeze({actorReference: 'urn:actor:eligible', subjectReference: 'urn:subject:eligible',
  capability: 'identity.relationship.attest', verificationTransactionId: 'synthetic-verification'})

test('Firestore prevents concurrent redemption and retains the used nonce after issuer restart', async t => {
  assert.match(process.env.FIRESTORE_EMULATOR_HOST ?? '', /^(127\.0\.0\.1|localhost):\d+$/u)
  const projectId = process.env.WALLET_FIRESTORE_EMULATOR_PROJECT || 'demo-wallet-offers'
  const first = new Firestore({projectId})
  const second = new Firestore({projectId})
  const restarted = new Firestore({projectId})
  const namespace = `test-${randomBytes(12).toString('hex')}`
  t.after(async () => {
    await restarted.recursiveDelete(restarted.collection(`wallet-offers-${namespace}`))
    await Promise.all([first.terminate(), second.terminate(), restarted.terminate()])
  })
  const secret = randomBytes(32)
  const issuer = firestore => createPreAuthorizedWalletOffers({credentialIssuer, secret,
    store: createFirestoreWalletOfferStore(firestore, namespace)})
  const a = issuer(first)
  const b = issuer(second)
  async function prepare() {
    const offer = await a.prepare(command, configurationId)
    const reference = new URL(offer.offerUri).pathname.split('/').at(-1)
    const document = await b.readOffer(reference)
    assert.deepEqual(document.credential_configuration_ids, [configurationId])
    const code = document.grants[preAuthorizedCodeGrantType]['pre-authorized_code']
    const outcomes = await Promise.all([a, b].map(instance => instance.exchange(code, offer.transactionCode)))
    const tokens = outcomes.filter(Boolean)
    assert.equal(tokens.length, 1)
    return tokens[0].access_token
  }
  const [tokenA, tokenB] = await Promise.all([prepare(), prepare()])
  const firstGrant = await a.resolveGrant(tokenA)
  const secondGrant = await b.resolveGrant(tokenB)
  const nonce = await a.issueNonce()
  const outcomes = await Promise.all([firstGrant, secondGrant].map(grant => grant.consumeNonce(nonce, command)))
  assert.equal(outcomes.filter(Boolean).length, 1)
  const next = issuer(restarted)
  const used = outcomes[0] ? tokenA : tokenB
  const stillAvailable = outcomes[0] ? tokenB : tokenA
  assert.equal(await next.resolveGrant(used), undefined)
  const remaining = await next.resolveGrant(stillAvailable)
  assert.equal(await remaining.consumeNonce(nonce, command), false)
  assert.equal(await remaining.consumeNonce(await next.issueNonce(), command), true)
  assert.equal(await a.resolveGrant(stillAvailable), undefined)
})
