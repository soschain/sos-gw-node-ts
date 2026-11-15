import { buildDagJsonCidV1FromUtf8String } from 'antifraud-data-utils-ts/encoding';
import { canonicalizeOperationalClaimsForContentId } from 'sos-data-utils-ts/operational-claim-content';

/** Operational content version only; neither a logical record identifier nor a SHA3 ledger reference. */
export function buildOperationalClaimsContentCid(claims: Readonly<Record<string, unknown>>): string {
  return buildDagJsonCidV1FromUtf8String(canonicalizeOperationalClaimsForContentId(claims));
}
