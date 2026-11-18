import {buildStableActorIdentifier} from 'antifraud-data-utils-ts/organization-identity';
import {buildSecureIdValueMember} from 'sos-data-utils-ts/hosted-did';
import {SecureIdTypesIndividual} from 'sos-data-utils-ts/identity-identifiers';
import { parseIndividualMemberDidWeb } from 'sos-data-utils-ts/individual-did-routing';
import { summarizeIndividualMemberIdentityCredential, getIndividualMemberIdentitySameAs, getIndividualMemberIdentityTelephone } from 'sos-data-utils-ts/individual-smart';
import type { IKmsService } from '../gdc-backend-utils-node/models/IKmsService';
import type { IVaultRepository } from '../database/repositories/vault/vault.repository';
import { LICENSE_USER_CLASS_INDIVIDUAL } from '../constants/domain';
import { getEnvSectionId } from '../utils/section-env';
import { openDeviceLicenseDocument } from '../utils/device-license-storage';
import { normalizeConsentActorRole } from '../utils/consent';

type IndividualMemberAuthorityInput = {
  holder: string; vaultId: string;
  kmsService: IKmsService; vaultRepository: IVaultRepository; now?: number;
};

/** Reads current protected authority; callers authenticate wallet possession before using these facts. */
export async function loadRegisteredIndividualMemberAuthority(input: IndividualMemberAuthorityInput) {
  const document = await input.vaultRepository.get<any>(input.vaultId, input.holder, getEnvSectionId('device-profiles'));
  if (document?.status !== 'active') throw new Error('Individual member device registration is inactive.');
  const profile = await input.kmsService.unprotectConfidentialData<any>(document, input.vaultId);
  if (profile.clientId !== input.holder || !profile.actorDid || !profile.authorizedSubjectDid
    || !profile.licenseId || !profile.authenticatedSubject) throw new Error('Member identity does not match its registered actor and individual subject.');
  const licenceDocument = await input.vaultRepository.get<any>(input.vaultId, profile.licenseId, getEnvSectionId('device-licenses'));
  if (licenceDocument?.status !== 'active') throw new Error('Individual member licence record is missing or inactive.');
  const { license: licence } = await openDeviceLicenseDocument(licenceDocument, input.vaultId, input.kmsService);
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (licence.id !== profile.licenseId || licence.status !== 'active' || licence.userClass !== LICENSE_USER_CLASS_INDIVIDUAL
    || !Number.isFinite(licence.exp) || licence.exp <= now) throw new Error('Individual member licence is inactive, expired or invalid.');
  // The individual-organization UUID, verified account subject and controller
  // actor are distinct identities. The protected licence binds the target.
  if(licence.authorizedSubjectDid!==profile.authorizedSubjectDid||!licence.subjectId||(profile.profileDid&&profile.profileDid!==profile.actorDid))throw new Error('Individual member licence belongs to another subject or person.');
  const deviceActive = Array.isArray(licence.deviceBindings)
    ? licence.deviceBindings.some(binding => binding.clientId === input.holder && binding.status === 'active')
    : licence.deviceId === input.holder;
  if (!deviceActive) throw new Error('Individual member licence does not authorize this device.');
  const role = normalizeConsentActorRole(licence.issuedToRole || '', 'family');
  const actor = parseIndividualMemberDidWeb(profile.actorDid);
  const memberIds=[
    licence.issuedToEmail?buildSecureIdValueMember({secureIdTypeMember:SecureIdTypesIndividual.Email,privateIdValueMember:licence.issuedToEmail}):undefined,
    licence.issuedToPhone?buildSecureIdValueMember({secureIdTypeMember:SecureIdTypesIndividual.Phone,privateIdValueMember:licence.issuedToPhone}):undefined,
  ].filter(Boolean);
  if(!memberIds.includes(actor.memberId))throw new Error('Member actor contact does not match its current licence.');
  if(profile.authenticatedEmail&&String(profile.authenticatedEmail).trim().toLowerCase()!==String(licence.issuedToEmail||'').trim().toLowerCase())throw new Error('Member registered contact does not match its current licence.');
  if(profile.authenticatedTelephone&&buildSecureIdValueMember({secureIdTypeMember:SecureIdTypesIndividual.Phone,privateIdValueMember:profile.authenticatedTelephone})!==buildSecureIdValueMember({secureIdTypeMember:SecureIdTypesIndividual.Phone,privateIdValueMember:licence.issuedToPhone||''}))throw new Error('Member registered contact does not match its current licence.');
  if(!role||actor.roleValue.toUpperCase()!==role.split('|').at(-1)?.toUpperCase())throw new Error('Member relationship does not match the current licensed role and individual.');
  const licensedContacts = [
    ...(licence.issuedToEmail ? [{contactKind:'email' as const,contact:licence.issuedToEmail,memberId:memberIds[0]}] : []),
    ...(licence.issuedToPhone ? [{contactKind:'phone' as const,contact:licence.issuedToPhone,memberId:buildSecureIdValueMember({secureIdTypeMember:SecureIdTypesIndividual.Phone,privateIdValueMember:licence.issuedToPhone})}] : []),
  ];
  const canonicalActors=licensedContacts.map(contact=>({...contact,actor:buildStableActorIdentifier(contact)}));
  // A recorded phone activation remains a phone actor when the same current
  // licence also contains email. Legacy absent actor fields derive only from
  // the contact already bound to the protected member DID.
  const stableActorIdentifier=String(licence.activatedBy||canonicalActors.find(contact=>contact.memberId===actor.memberId)?.actor||'').trim();
  if(!canonicalActors.some(contact=>contact.actor===stableActorIdentifier))throw new Error('Member stable actor does not match the current licensed contact.');
  return {profile,licence,role,stableActorIdentifier};
}

/** Current personal identity/relationship proof. Consent is evaluated separately for every data request. */
export async function verifyRegisteredIndividualMemberIdentity(input: IndividualMemberAuthorityInput & { credential: Record<string, any> }) {
  const identity = summarizeIndividualMemberIdentityCredential(input.credential);
  if (!identity || input.credential.issuer || input.credential.iss || input.credential.proof) throw new Error('Unsupported registered individual-member identity projection.');
  const { profile, licence, role } = await loadRegisteredIndividualMemberAuthority(input);
  if (profile.actorDid !== identity.actorDid || profile.authorizedSubjectDid !== identity.subjectDid) throw new Error('Member identity targets another individual or actor.');
  if (normalizeConsentActorRole(identity.relationship, 'family') !== role) throw new Error('Member relationship does not match its current licence.');
  const aliases = new Set(getIndividualMemberIdentitySameAs({ email: licence.issuedToEmail }));
  if (identity.sameAs.some(alias => !aliases.has(alias))) throw new Error('Member contact alias does not match its current licence.');
  if (identity.email && identity.email !== String(licence.issuedToEmail || '').trim().toLowerCase()) throw new Error('Member email does not match its current licence.');
  if (identity.telephone && identity.telephone !== getIndividualMemberIdentityTelephone({ telephone: licence.issuedToPhone })) throw new Error('Member telephone does not match its current licence.');
  return { actorDid: identity.actorDid, subjectDid: identity.subjectDid, role: identity.relationship, acr: 'urn:antifraud:acr:openid4vp:individual',
    email: licence.issuedToEmail, phone: licence.issuedToPhone, sameAs: identity.sameAs };
}
