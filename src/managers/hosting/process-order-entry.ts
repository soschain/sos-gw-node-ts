import { v4 as uuidv4 } from 'uuid';
import type { BundleEntry } from 'sos-data-utils-ts/bundle-contract';
import type { ClaimsRecord } from 'sos-data-utils-ts/confidential-storage';
import { SchemaOrgOfferClaim, SchemaOrgOrderClaim, SchemaOrgOrganizationClaim, SchemaOrgPersonClaim, SchemaOrgServiceClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
import { IssueType } from 'fhir-data-utils-ts/operation-outcome';
import { ManagerError } from 'sos-sdk-core-ts/manager-error';
import type { Sector } from 'gdc-common-utils-ts/models/urlPath';
import { EntityLifecycleStatus } from '../../gdc-backend-utils-node/models/enums';
import type { IServerConfig } from '../../config';
import type { IKmsService } from '../../gdc-backend-utils-node/models/IKmsService';
import type { IVaultRepository } from '../../database/repositories/vault/vault.repository';
import type { ILogger } from '../../loggers/ILogger';
import type { IHostRuntime } from '../IHostRuntime';
import type { HostingOfferOrderService } from './HostingOfferOrderService';
import { getClaimValue, normalizeContextualizedClaims } from '../../utils/claims';
import { readProjectedOfferOrderClaims, buildOfferOrderIndexedAttributes } from '../../utils/offer-order-read-model';
import { getEnvSectionId } from '../../utils/section-env';
import { composeHostDidWebId, createHostedDidWeb } from '../../utils/did-backend';
import { generateTenantCollectionNameFromClaims, getTenantVaultId, resolveOrganizationRouteJurisdiction } from '../../utils/tenant';
import { AllowedIndexableClaims } from '../../gdc-backend-utils-node/models/indexing';
import { registerOrganizationOnLedger } from '../../utils/ledger-organization-registration';
import type { PublicJwk } from 'antifraud-data-utils-ts/cryptography';
import type { DeviceLicense } from 'gdc-common-utils-ts/models/device-license';
import { issueActivationCodeFromPool, reserveTechnicalControllerSeat } from '../../utils/license-issuance';
import { getPersonOccupationClaim } from '../../utils/occupation';
import { buildPaymentCommunication, readOfferPaymentContext } from '../../utils/order-communication';
import { buildGatewayInvoiceBundle } from '../../utils/invoice-bundle';
import { verifyOrderPaymentConfirmation } from '../../utils/payment-confirmation';
import { createOrganizationUrn } from '../../utils/urn';
import { formatMissingRequiredClaimDiagnostic } from '../../utils/claim-contract';
import { buildStableActorIdentifier } from 'antifraud-data-utils-ts/organization-identity';
import { resolveLedgerOrganizationId } from '../../utils/ledger-organization-registration-helpers';
import {
  buildIssuedRoleLicenseLedgerIdentity,
  ensureIssuedRoleLicenseOnLedger,
} from '../../utils/ledger-role-license';
import { GatewayResponseEntryTypes } from 'gdc-common-utils-ts/constants/gateway-response';
import { ResourceTypesFhirR4 } from 'fhir-data-utils-ts';
import { verifyBoundPostalActivationCode } from './postal-activation-code';
import {
  HOST_ORDER_REQUIRED_INPUT_CLAIMS,
  HOST_ORDER_REQUIRED_INPUT_DISPLAY_CLAIMS,
} from './hosting-claim-contracts';
import { GatewayClaim } from '../../shared/gateway-claim-contract';

type ProcessHostOrderEntryDeps = Readonly<{
  entry: BundleEntry;
  environment?: string;
  vaultRepository: IVaultRepository;
  kmsService: IKmsService;
  logger: ILogger;
  config: IServerConfig;
  hostRuntime: IHostRuntime;
  offerOrderService: HostingOfferOrderService;
  extractResources: (claims: ClaimsRecord, environment?: string) => { organization: any; person?: any; service: any };
  extractContainedService: (contained: any) => any;
  finalizeTenantConfig: (
    organization: any,
    alternateName: string,
    processedClaims: ClaimsRecord,
    sector: Sector,
    vaultId: string,
    options?: { primaryDid?: string; controllerDid?: string },
  ) => Promise<any>;
  isLedgerRegistrationEnabled: () => boolean;
  extractServiceEvidence: (service: any) => any;
  buildControllerEntityConfig: (
    legalRep: any,
    tenantUrn: string,
    hostedTenantDid: string,
    vaultId: string,
    storedKeys?: { signerJwk?: PublicJwk; encrypterJwk?: PublicJwk },
  ) => Promise<any>;
  storeControllerEntityConfig: (employeeConfig: any, tenantCollectionName: string, vaultId: string) => Promise<void>;
  getCurrentUrnNetwork: () => string;
  registerOrganizationOnLedger?: typeof registerOrganizationOnLedger;
}>;

/**
 * Matches only the operational tenant of the already registered host legal
 * person. Host bootstrap must not submit the same legal organization to
 * Fabric twice; no DID or internal ledger identifier is involved.
 */
export function isConfiguredHostLegalPersonTenant(
  claims: Record<string, unknown>,
  host: Readonly<{ idType?: unknown; idValue?: unknown }>,
): boolean {
  const tenantType = String(claims[SchemaOrgOrganizationClaim.IdentifierType] || '').trim().toUpperCase();
  const tenantValue = String(claims[SchemaOrgOrganizationClaim.IdentifierValue] || '').trim();
  const hostType = String(host.idType || '').trim().toUpperCase();
  const hostValue = String(host.idValue || '').trim();
  return Boolean(tenantType && tenantValue && tenantType === hostType && tenantValue === hostValue);
}

export async function processHostOrderEntry(deps: ProcessHostOrderEntryDeps): Promise<BundleEntry> {
  const rawClaims = deps.entry?.resource?.meta?.claims;
  const claims = rawClaims ? normalizeContextualizedClaims(rawClaims) : rawClaims;
  if (!claims) {
    throw new ManagerError('Malformed order entry: missing meta.claims', IssueType.Required);
  }

  const offerId = getClaimValue<string>(claims, HOST_ORDER_REQUIRED_INPUT_CLAIMS[0]);
  if (!offerId) {
    throw new ManagerError(
      formatMissingRequiredClaimDiagnostic(HOST_ORDER_REQUIRED_INPUT_CLAIMS[0], {
        context: 'in Order',
        displayLabel: HOST_ORDER_REQUIRED_INPUT_DISPLAY_CLAIMS[0],
      }),
      IssueType.Required,
    );
  }

  const hostCollectionName = deps.hostRuntime.hostCollectionName;
  const results = await deps.vaultRepository.query(hostCollectionName!, {
    sectionId: getEnvSectionId('tenants'),
    where: [{ name: SchemaOrgOfferClaim.Identifier, value: offerId }],
  });

  if (results.length === 0) {
    return deps.offerOrderService.processLicenseOrderEntry(claims, offerId);
  }
  if (results.length > 1) {
    deps.logger.error(`CRITICAL: Multiple pending registrations found for the same offerId: '${offerId}'`);
    throw new ManagerError('Internal system conflict. Multiple pending registrations found.', IssueType.Conflict);
  }

  const secureDoc = results[0] as ConfidentialStorageDoc;
  const decryptedContent = await deps.kmsService.unprotectConfidentialData<ConfidentialStorageDoc['content']>(
    secureDoc,
    'host',
  );

  if (decryptedContent?.status !== EntityLifecycleStatus.Pending) {
    const projectedClaims = readProjectedOfferOrderClaims(secureDoc);
    if (
      decryptedContent?.status === EntityLifecycleStatus.Active
      && String(projectedClaims[SchemaOrgOfferClaim.Identifier] || '').trim() === offerId
    ) {
      const replayClaims: Record<string, unknown> = {
        ...projectedClaims,
        [SchemaOrgOrderClaim.AcceptedOfferIdentifier]: offerId,
      };
      const replayTenantDid = String((decryptedContent as any)?.didDocument?.id || '').trim();
      if (replayTenantDid) {
        replayClaims[GatewayClaim.OrganizationDid] = replayTenantDid;
      }
      return {
        type: GatewayResponseEntryTypes.OrganizationOrder,
        resource: { resourceType: ResourceTypesFhirR4.Organization, id: String(decryptedContent.id || ''), meta: { claims: {
          ...replayClaims,
        } } },
        response: { status: '200' },
      };
    }
    throw new ManagerError(`Found registration for offerId '${offerId}', but it is not in 'pending' state.`, IssueType.Conflict);
  }

  const { claims: processedClaims, contained } = decryptedContent as any;
  const postalActivationCodeBinding = (decryptedContent as any).postalActivationCodeBinding;
  const postalActivationCode = postalActivationCodeBinding
    ? verifyBoundPostalActivationCode(claims, postalActivationCodeBinding, process.env.HOST_POSTAL_ACTIVATION_PEPPER)
    : undefined;
  const alternateName = processedClaims[SchemaOrgOrganizationClaim.AlternateName] as string;
  const sector = processedClaims[SchemaOrgServiceClaim.Category] as Sector;
  const routeJurisdiction = resolveOrganizationRouteJurisdiction(processedClaims);
  const tenantUrn = createOrganizationUrn({
    namespace: deps.config.namespace,
    network: deps.getCurrentUrnNetwork(),
    jurisdiction: routeJurisdiction,
    sector,
    idType: processedClaims[SchemaOrgOrganizationClaim.IdentifierType] as string,
    idValue: processedClaims[SchemaOrgOrganizationClaim.IdentifierValue] as string,
  });
  (processedClaims as any)[SchemaOrgOrganizationClaim.IdentifierReference] = tenantUrn;

  const { organization, person, service } = deps.extractResources(processedClaims, deps.environment);
  const containedService = deps.extractContainedService(contained);
  const vaultId = getTenantVaultId(sector, alternateName);
  const tenantCollectionName = generateTenantCollectionNameFromClaims(processedClaims);
  const hostedTenantDid = createHostedDidWeb(
    composeHostDidWebId(deps.config.apiBaseUrl, deps.config.hostExternalDomain),
    alternateName,
    {
      jurisdiction: routeJurisdiction,
      version: 'v1',
      sector,
    },
  );

  await deps.vaultRepository.createNewVault({ id: tenantCollectionName });
  await deps.kmsService.provisionKeys(vaultId);

  // Build the verified historical representative (the owner of this portal's
  // submitted JWK) before tenant finalization. A differently designated
  // technical controller remains pending until its own sector binding/DCR.
  const [legalRep, processedService] = [person, service];
  const storedKeys = (decryptedContent as any)?.registrationKeys as
    | { signerJwk?: PublicJwk; encrypterJwk?: PublicJwk }
    | undefined;
  const employeeConfig = legalRep
    ? await deps.buildControllerEntityConfig(legalRep, tenantUrn, hostedTenantDid, vaultId, storedKeys)
    : undefined;

  const finalTenantConfig = await deps.finalizeTenantConfig(
    organization,
    alternateName,
    processedClaims,
    sector,
    vaultId,
    {
      primaryDid: typeof (decryptedContent as any).primaryDid === 'string'
        ? (decryptedContent as any).primaryDid
        : undefined,
      controllerDid: employeeConfig?.didDocument?.id,
    },
  );

  const attributes = AllowedIndexableClaims.organizationRegistry
    .map((claimKey: string) => ({
      name: claimKey,
      value: String(processedClaims[claimKey]),
      ...(claimKey === SchemaOrgOrganizationClaim.AlternateName && { unique: true }),
    }))
    .filter((attr: { value: string }) => attr.value !== 'undefined' && attr.value !== 'null');
  attributes.push({
    name: SchemaOrgOfferClaim.Identifier,
    value: offerId,
  });

  const finalTenantRegistrationDoc: ConfidentialStorageDoc = {
    id: vaultId,
    status: finalTenantConfig.status,
    sequence: 1,
    indexed: { attributes, hmac: { id: 'urn:unsupported', type: 'Sha256HmacKey2019' } },
    content: finalTenantConfig,
  };

  const secureFinalDoc = await deps.kmsService.protectConfidentialData(finalTenantRegistrationDoc, 'host');

  if (deps.isLedgerRegistrationEnabled()
    && !isConfiguredHostLegalPersonTenant(processedClaims, deps.config.host || {})) {
    const serviceEvidence = deps.extractServiceEvidence(containedService || service);
    await (deps.registerOrganizationOnLedger || registerOrganizationOnLedger)({
      ledgerConfig: deps.config.ledger,
      hostJurisdiction: deps.config.host.jurisdiction,
      namespace: deps.config.namespace,
      hostExternalDomain: deps.config.hostExternalDomain,
      logger: deps.logger,
      orgId: tenantUrn,
      organization,
      config: finalTenantConfig,
      evidence: serviceEvidence,
      role: 'tenant',
      sector,
      jurisdiction: routeJurisdiction,
    });
  }

  // Keep the Offer-resolvable pending record authoritative until every
  // mandatory ledger write succeeds. This makes Order retries safe after a
  // ledger timeout and prevents a partially active tenant from losing the
  // commercial continuation that created it.
  await deps.vaultRepository.put(hostCollectionName!, [secureFinalDoc], getEnvSectionId('tenants'));

  const legalParticipantDoc: ConfidentialStorageDoc = { id: 'legal-participant.vc.json', status: 'active', sequence: 0, content: finalTenantConfig.governanceVc };
  const legacyVcDoc: ConfidentialStorageDoc = { id: 'vc.json', status: 'active', sequence: 0, content: finalTenantConfig.governanceVc };
  const selfDescDoc: ConfidentialStorageDoc = { id: 'self-description.json', status: 'active', sequence: 0, content: finalTenantConfig.selfDescriptionVc };
  const secureLegalParticipantDoc = await deps.kmsService.protectConfidentialData(legalParticipantDoc, vaultId);
  const secureLegacyVcDoc = await deps.kmsService.protectConfidentialData(legacyVcDoc, vaultId);
  const secureSelfDescDoc = await deps.kmsService.protectConfidentialData(selfDescDoc, vaultId);
  await deps.vaultRepository.put(tenantCollectionName, [secureLegalParticipantDoc, secureLegacyVcDoc, secureSelfDescDoc], getEnvSectionId('.well-known'));

  if (employeeConfig) {
    await deps.storeControllerEntityConfig(employeeConfig, tenantCollectionName, vaultId);
  }
  if (processedService) {
    const serviceDoc: ConfidentialStorageDoc = { id: processedService.id, status: 'active', sequence: 0, content: processedService };
    const secureServiceDoc = await deps.kmsService.protectConfidentialData(serviceDoc, vaultId);
    await deps.vaultRepository.put(tenantCollectionName, [secureServiceDoc], getEnvSectionId('services'));
  }

  const initialEmployeeSeats = processedClaims[SchemaOrgOfferClaim.EligibleQuantityValue] as number | undefined;
  const offerIdentifier = processedClaims[SchemaOrgOfferClaim.Identifier] as string | undefined;
  if (initialEmployeeSeats && initialEmployeeSeats > 0 && offerIdentifier) {
    const now = Date.now();
    const expiryDate = new Date(now);
    expiryDate.setFullYear(expiryDate.getFullYear() + 1);
    const exp = Math.floor(expiryDate.getTime() / 1000);

    const licenseDocs: ConfidentialStorageDoc[] = [];
    for (let i = 0; i < initialEmployeeSeats; i++) {
      const licenseId = uuidv4();
      const license: DeviceLicense = {
        id: licenseId,
        tenantId: alternateName,
        orderId: offerIdentifier,
        userClass: 'employee',
        userCategory: 'default',
        type: 'mobile',
        status: 'available',
        plan: 'default',
        renewalCycle: '12m',
        reactivationEnabled: false,
        exp,
      };
      licenseDocs.push({ id: licenseId, status: license.status, sequence: 0, content: license });
    }
    await deps.vaultRepository.put(vaultId, licenseDocs, getEnvSectionId('device-licenses'));

    const legalRepEmail = processedClaims[SchemaOrgPersonClaim.Email] as string | undefined;
    const legalRepRole = getPersonOccupationClaim(processedClaims as Record<string, any> | undefined);
    if (legalRepEmail && legalRepRole) {
      try {
        const organizationOfficialId = resolveLedgerOrganizationId(processedClaims);
        const jurisdiction = resolveOrganizationRouteJurisdiction(processedClaims);
        const stableActorIdentifier = buildStableActorIdentifier({ contactKind: 'email', contact: legalRepEmail });
        const ledgerIdentity = buildIssuedRoleLicenseLedgerIdentity({
          organizationId: organizationOfficialId,
          jurisdiction,
          contactKind: 'email',
          contact: legalRepEmail,
          licensedRole: legalRepRole,
        });
        const { activationCode, licenseId } = await issueActivationCodeFromPool({
          vaultRepository: deps.vaultRepository,
          kmsService: deps.kmsService,
          tenantVaultId: vaultId,
          userClass: 'employee',
          type: 'mobile',
          email: legalRepEmail,
          role: legalRepRole,
          activationCode: postalActivationCode,
          ownerOrganizationId: organizationOfficialId,
          stableActorIdentifier,
          beforePersist: async () => ensureIssuedRoleLicenseOnLedger({
            identity: ledgerIdentity,
            sector: String(processedClaims[SchemaOrgServiceClaim.Category] || '').trim(),
          }).then(() => undefined),
        });
        (processedClaims as any)['org.schema.IndividualProduct.serialNumber'] = activationCode;
        (processedClaims as any)['org.schema.IndividualProduct.category'] = 'professional';
        await reserveTechnicalControllerSeat({
          vaultRepository: deps.vaultRepository,
          tenantVaultId: vaultId,
          representativeLicenseId: licenseId,
          ownerOrganizationId: organizationOfficialId,
        });
      } catch (e: any) {
        deps.logger.warn?.(
          `[HostingManager] Failed to auto-issue legal rep activation code: ${String(e?.message || e)}`,
        );
      }
    }
  }

  const hostDid = composeHostDidWebId(deps.config.apiBaseUrl, deps.config.hostExternalDomain);
  const tenantDid = finalTenantConfig.didDocument?.id || tenantUrn;
  const paymentCommunication = await buildPaymentCommunication({
    offerId,
    tenantId: alternateName,
    tenantDid,
    senderDid: hostDid,
    email: processedClaims[SchemaOrgPersonClaim.Email] as string | undefined,
    legalName: processedClaims[SchemaOrgOrganizationClaim.LegalName] as string | undefined,
    addressCountry: processedClaims[SchemaOrgOrganizationClaim.AddressCountry] as string | undefined,
    addressRegion: processedClaims[SchemaOrgOrganizationClaim.AddressRegion] as string | undefined,
    addressLocality: processedClaims[SchemaOrgOrganizationClaim.AddressLocality] as string | undefined,
    postalCode: processedClaims[SchemaOrgOrganizationClaim.PostalCode] as string | undefined,
    streetAddress: processedClaims[SchemaOrgOrganizationClaim.StreetAddress] as string | undefined,
    activationCode: (processedClaims as any)['org.schema.IndividualProduct.serialNumber'] as string | undefined,
    activationCategory: (processedClaims as any)['org.schema.IndividualProduct.category'] as string | undefined,
    paymentMethod: claims[SchemaOrgOrderClaim.PaymentMethod] as string | undefined,
    paymentUrl: claims[SchemaOrgOrderClaim.PaymentUrl] as string | undefined,
    invoiceId: claims[SchemaOrgOrderClaim.PartOfInvoice] as string | undefined,
    paymentConfirmed: true,
    ...readOfferPaymentContext(processedClaims),
  });
  paymentCommunication.claims[GatewayClaim.OrganizationDid] = tenantDid;
  const invoiceBundle = buildGatewayInvoiceBundle({
    invoiceId: String(
      paymentCommunication.claims[SchemaOrgOrderClaim.PartOfInvoice]
      || paymentCommunication.claims[SchemaOrgOrderClaim.AcceptedOfferIdentifier]
      || offerId,
    ),
    subjectReference: tenantDid || tenantUrn,
    issuerReference: hostDid,
    recipientReference: tenantDid || tenantUrn,
    issuedAt: String(
      paymentCommunication.claims['org.schema.Order.invoiceIssuedAt']
      || new Date().toISOString(),
    ),
    amount: String(processedClaims[SchemaOrgOfferClaim.Price] || ''),
    currency: String(processedClaims[SchemaOrgOfferClaim.PriceCurrency] || ''),
    paymentMethod: claims[SchemaOrgOrderClaim.PaymentMethod] as string | undefined,
    paymentUrl: claims[SchemaOrgOrderClaim.PaymentUrl] as string | undefined,
  });

  const communicationDoc: ConfidentialStorageDoc & { meta?: Record<string, unknown> } = {
    id: paymentCommunication.communicationId,
    status: EntityLifecycleStatus.Active,
    sequence: 0,
    meta: { claims: paymentCommunication.claims },
    indexed: {
      attributes: buildOfferOrderIndexedAttributes(paymentCommunication.claims),
      hmac: { id: 'urn:unsupported', type: 'Sha256HmacKey2019' },
    },
    content: { claims: paymentCommunication.claims, invoiceBundle },
  };
  const secureCommunicationDoc = await deps.kmsService.protectConfidentialData(communicationDoc, 'host');
  await deps.vaultRepository.put(hostCollectionName, [secureCommunicationDoc], getEnvSectionId('communications'));

  return {
    type: GatewayResponseEntryTypes.OrganizationOrder,
    resource: { ...(invoiceBundle as any), meta: { ...((invoiceBundle as any).meta || {}), claims: paymentCommunication.claims } },
    response: { status: '201' },
  };
}

type ProcessActivatedTenantOrderEntryDeps = Readonly<{
  orderClaims: ClaimsRecord;
  offerId: string;
  matchedOfferClaims: ClaimsRecord;
  vaultRepository: IVaultRepository;
  kmsService: IKmsService;
  logger: ILogger;
  config: IServerConfig;
  hostRuntime: IHostRuntime;
}>;

export async function processActivatedTenantOrderEntry(
  deps: ProcessActivatedTenantOrderEntryDeps,
): Promise<BundleEntry> {
  const verification = await verifyOrderPaymentConfirmation({
    orderClaims: deps.orderClaims,
    offerClaims: deps.matchedOfferClaims,
  });
  if (!verification.verified) {
    throw new ManagerError(`Payment confirmation failed for offerId '${deps.offerId}'.`, IssueType.Conflict);
  }

  const tenantId = String(deps.matchedOfferClaims[SchemaOrgOrganizationClaim.AlternateName] || '').trim();
  const sector = String(
    deps.matchedOfferClaims[SchemaOrgOfferClaim.Category]
    || deps.matchedOfferClaims[SchemaOrgServiceClaim.Category]
    || '',
  ).trim();
  if (!tenantId || !sector) {
    throw new ManagerError('Activated tenant Offer is missing tenant alternateName or sector.', IssueType.Required);
  }

  const tenantVaultId = getTenantVaultId(sector as Sector, tenantId);
  const quantity = Number(deps.matchedOfferClaims[SchemaOrgOfferClaim.EligibleQuantityValue] || 1);
  const expiryDate = new Date(Date.now());
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);
  const exp = Math.floor(expiryDate.getTime() / 1000);
  const licenseDocs: ConfidentialStorageDoc[] = [];
  for (let i = 0; i < quantity; i++) {
    const licenseId = uuidv4();
    const license: DeviceLicense = {
      id: licenseId,
      tenantId,
      orderId: verification.invoiceId || deps.offerId,
      userClass: 'employee',
      userCategory: 'default',
      type: 'mobile',
      status: 'available',
      plan: 'default',
      renewalCycle: '12m',
      reactivationEnabled: false,
      exp,
    };
    licenseDocs.push({ id: licenseId, status: license.status, sequence: 0, content: license });
  }
  await deps.vaultRepository.put(tenantVaultId, licenseDocs, getEnvSectionId('device-licenses'));

  let activationCode: string | undefined;
  let representativeLicenseId: string | undefined;
  const legalRepEmail = deps.matchedOfferClaims[SchemaOrgPersonClaim.Email] as string | undefined;
  const legalRepRole = getPersonOccupationClaim(deps.matchedOfferClaims as Record<string, any> | undefined);
  if (legalRepEmail && legalRepRole) {
    try {
      const organizationOfficialId = resolveLedgerOrganizationId(deps.matchedOfferClaims);
      const jurisdiction = resolveOrganizationRouteJurisdiction(deps.matchedOfferClaims);
      const stableActorIdentifier = buildStableActorIdentifier({ contactKind: 'email', contact: legalRepEmail });
      const ledgerIdentity = buildIssuedRoleLicenseLedgerIdentity({
        organizationId: organizationOfficialId,
        jurisdiction,
        contactKind: 'email',
        contact: legalRepEmail,
        licensedRole: legalRepRole,
      });
      ({ activationCode, licenseId: representativeLicenseId } = await issueActivationCodeFromPool({
        vaultRepository: deps.vaultRepository,
        kmsService: deps.kmsService,
        tenantVaultId,
        userClass: 'employee',
        type: 'mobile',
        email: legalRepEmail,
        role: legalRepRole,
        ownerOrganizationId: organizationOfficialId,
        stableActorIdentifier,
        beforePersist: async () => ensureIssuedRoleLicenseOnLedger({
          identity: ledgerIdentity,
          sector: String(deps.matchedOfferClaims[SchemaOrgServiceClaim.Category] || '').trim(),
        }).then(() => undefined),
      }));
      await reserveTechnicalControllerSeat({
        vaultRepository: deps.vaultRepository,
        tenantVaultId,
        representativeLicenseId,
        ownerOrganizationId: organizationOfficialId,
      });
    } catch (e: any) {
      deps.logger.warn?.(
        `[HostingManager] Failed to auto-issue legal rep activation code after activation order: ${String(e?.message || e)}`,
      );
    }
  }

  const hostDid = composeHostDidWebId(deps.config.apiBaseUrl, deps.config.hostExternalDomain);
  const tenantDid = String(deps.matchedOfferClaims[SchemaOrgOrganizationClaim.IdentifierReference] || '').trim() || `urn:tenant:${tenantId}`;
  const paymentCommunication = await buildPaymentCommunication({
    offerId: deps.offerId,
    tenantId,
    tenantDid,
    senderDid: hostDid,
    email: deps.matchedOfferClaims[SchemaOrgPersonClaim.Email] as string | undefined,
    legalName: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.LegalName] as string | undefined,
    addressCountry: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.AddressCountry] as string | undefined,
    addressRegion: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.AddressRegion] as string | undefined,
    addressLocality: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.AddressLocality] as string | undefined,
    postalCode: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.PostalCode] as string | undefined,
    streetAddress: deps.matchedOfferClaims[SchemaOrgOrganizationClaim.StreetAddress] as string | undefined,
    activationCode,
    activationCategory: activationCode ? 'professional' : undefined,
    paymentMethod: verification.paymentMethod,
    paymentUrl: verification.paymentUrl,
    invoiceId: verification.invoiceId,
    paymentConfirmed: true,
    ...readOfferPaymentContext(deps.matchedOfferClaims),
  });
  paymentCommunication.claims[SchemaOrgOrganizationClaim.AlternateName] = tenantId;

  const invoiceBundle = buildGatewayInvoiceBundle({
    invoiceId: String(
      paymentCommunication.claims[SchemaOrgOrderClaim.PartOfInvoice]
      || verification.invoiceId
      || deps.offerId,
    ),
    subjectReference: tenantDid,
    issuerReference: hostDid,
    recipientReference: tenantDid,
    issuedAt: String(
      paymentCommunication.claims['org.schema.Order.invoiceIssuedAt']
      || new Date().toISOString(),
    ),
    amount: String(deps.matchedOfferClaims[SchemaOrgOfferClaim.Price] || ''),
    currency: String(deps.matchedOfferClaims[SchemaOrgOfferClaim.PriceCurrency] || ''),
    paymentMethod: verification.paymentMethod,
    paymentUrl: verification.paymentUrl,
  });

  const communicationDoc: ConfidentialStorageDoc & { meta?: Record<string, unknown> } = {
    id: paymentCommunication.communicationId,
    status: EntityLifecycleStatus.Active,
    sequence: 0,
    meta: { claims: paymentCommunication.claims },
    indexed: {
      attributes: buildOfferOrderIndexedAttributes(paymentCommunication.claims),
      hmac: { id: 'urn:unsupported', type: 'Sha256HmacKey2019' },
    },
    content: { claims: paymentCommunication.claims, invoiceBundle },
  };
  const secureCommunicationDoc = await deps.kmsService.protectConfidentialData(communicationDoc, 'host');
  await deps.vaultRepository.put(deps.hostRuntime.hostCollectionName, [secureCommunicationDoc], getEnvSectionId('communications'));

  return {
    type: GatewayResponseEntryTypes.OrganizationOrder,
    resource: { ...(invoiceBundle as any), meta: { ...((invoiceBundle as any).meta || {}), claims: paymentCommunication.claims } },
    response: { status: '201' },
  };
}
