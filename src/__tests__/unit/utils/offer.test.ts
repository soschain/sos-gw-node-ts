// Flow contract: docs/LOCAL_FIRST_RELEASE_CONTRACT.md — VetChain offers keep pricing and billing readiness deterministic.
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { VETCHAIN_PRODUCT_BOUNDARY } from '../../../config/vetchain-product-boundary';
import { generateLicenseOffer } from '../../../utils/offer';
import { VET_PAYMENT_TEST_DATA } from 'vet-data-utils-ts/payment';
import { SchemaOrgOfferClaim } from 'antifraud-data-utils-ts/schema-org-claims';

describe('generateLicenseOffer', () => {
  const originalDeploymentEnv = process.env.DEPLOYMENT_ENV;
  const originalNetworkMode = process.env.NETWORK_MODE;
  const originalLocalTestPrice = process.env.VETCHAIN_LOCAL_TEST_LICENSE_UNIT_PRICE;

  afterEach(() => {
    if (originalDeploymentEnv === undefined) delete process.env.DEPLOYMENT_ENV;
    else process.env.DEPLOYMENT_ENV = originalDeploymentEnv;
    if (originalNetworkMode === undefined) delete process.env.NETWORK_MODE;
    else process.env.NETWORK_MODE = originalNetworkMode;
    if (originalLocalTestPrice === undefined) delete process.env.VETCHAIN_LOCAL_TEST_LICENSE_UNIT_PRICE;
    else process.env.VETCHAIN_LOCAL_TEST_LICENSE_UNIT_PRICE = originalLocalTestPrice;
  });

  it('uses the reusable paid USDC fixture only in the exact local test stage', () => {
    process.env.DEPLOYMENT_ENV = 'dev';
    process.env.NETWORK_MODE = 'test';
    process.env.VETCHAIN_LOCAL_TEST_LICENSE_UNIT_PRICE = VET_PAYMENT_TEST_DATA.priceText;
    const claims = generateLicenseOffer(
      VET_PAYMENT_TEST_DATA.quantity,
      hostDid,
      jurisdiction,
      VETCHAIN_PRODUCT_BOUNDARY.professionalSector,
      allowedPaymentMethods,
    );
    expect(claims[SchemaOrgOfferClaim.Price]).toBe(VET_PAYMENT_TEST_DATA.priceText);
    expect(claims[SchemaOrgOfferClaim.PriceCurrency]).toBe(VET_PAYMENT_TEST_DATA.currency);
  });
  const hostDid = 'did:web:host.example.com';
  const jurisdiction = 'es';
  const sector = 'health-care';
  const allowedPaymentMethods = ['Stripe', 'PayPal'];

  it('should generate a free "Tier XS" offer for 5 or fewer employees', () => {
    // Act
    const offerClaims = generateLicenseOffer(5, hostDid, jurisdiction, sector, allowedPaymentMethods);

    // Assert
    expect(offerClaims[SchemaOrgOfferClaim.ItemOfferedName]).toBe('License Tier XS');
    expect(offerClaims[SchemaOrgOfferClaim.Price]).toBe('0.00');
    expect(offerClaims[SchemaOrgOfferClaim.EligibleQuantityValue]).toBe(5);
    expect(offerClaims[SchemaOrgOfferClaim.Identifier]).toContain('urn:cds:ES:v1:health-care:product:org.schema:Offer:');
    expect(offerClaims[SchemaOrgOfferClaim.SerialNumber].split(',')).toHaveLength(5);
  });

  it('should generate a "Tier S" offer for 20 or fewer employees', () => {
    // Act
    const offerClaims = generateLicenseOffer(20, hostDid, jurisdiction, sector, allowedPaymentMethods);

    // Assert
    expect(offerClaims[SchemaOrgOfferClaim.ItemOfferedName]).toBe('License Tier S');
    expect(offerClaims[SchemaOrgOfferClaim.Price]).toBe('49.99');
    expect(offerClaims[SchemaOrgOfferClaim.EligibleQuantityValue]).toBe(20);
    expect(offerClaims[SchemaOrgOfferClaim.SerialNumber].split(',')).toHaveLength(20);
  });

  it('should generate a "Tier M" offer for more than 20 employees', () => {
    // Act
    const offerClaims = generateLicenseOffer(21, hostDid, jurisdiction, sector, allowedPaymentMethods);

    // Assert
    expect(offerClaims[SchemaOrgOfferClaim.ItemOfferedName]).toBe('License Tier M');
    expect(offerClaims[SchemaOrgOfferClaim.Price]).toBe('99.99');
    expect(offerClaims[SchemaOrgOfferClaim.EligibleQuantityValue]).toBe(21);
    expect(offerClaims[SchemaOrgOfferClaim.SerialNumber].split(',')).toHaveLength(21);
  });

  it('should include all required offer claims', () => {
    // Act
    const offerClaims = generateLicenseOffer(1, hostDid, jurisdiction, sector, allowedPaymentMethods);

    // Assert
    // NOTE: these claims are "flat" keys that contain dots (e.g., `org.schema.Offer.price`),
    // so we assert via bracket access instead of `toHaveProperty()` (which treats dots as path separators).
    expect(offerClaims[SchemaOrgOfferClaim.AcceptedPaymentMethod]).toBeDefined();
    expect(offerClaims[SchemaOrgOfferClaim.Category]).toBe(sector);
    expect(offerClaims[SchemaOrgOfferClaim.CheckoutPageUrlTemplate]).toBeDefined();
    expect(offerClaims[SchemaOrgOfferClaim.EligibleCustomerType]).toBeDefined();
    expect(offerClaims[SchemaOrgOfferClaim.Identifier]).toBeDefined();
    expect(offerClaims[SchemaOrgOfferClaim.OfferedBy]).toBe(hostDid);
    expect(offerClaims[SchemaOrgOfferClaim.PriceCurrency]).toBeDefined();
    expect(offerClaims[SchemaOrgOfferClaim.SerialNumber]).toBeDefined();
  });

  it('rejects a missing jurisdiction instead of persisting an undefined Offer URN', () => {
    expect(() => generateLicenseOffer(2, hostDid, undefined as unknown as string, sector, allowedPaymentMethods))
      .toThrow('generateLicenseOffer requires jurisdiction.');
  });

  it.each([
    ['hostDid', '', jurisdiction, sector, 'generateLicenseOffer requires hostDid.'],
    ['sector', hostDid, jurisdiction, '   ', 'generateLicenseOffer requires sector.'],
  ])('rejects a missing %s before an Offer can be persisted', (_field, nextHostDid, nextJurisdiction, nextSector, message) => {
    expect(() => generateLicenseOffer(2, nextHostDid, nextJurisdiction, nextSector, allowedPaymentMethods))
      .toThrow(message);
  });

  it('normalizes the route network and trims identity inputs in the Offer projection', () => {
    const claims = generateLicenseOffer(2, `  ${hostDid}  `, ' es ', ` ${sector} `, allowedPaymentMethods);
    expect(claims[SchemaOrgOfferClaim.Identifier]).toMatch(/^urn:cds:ES:v1:health-care:product:/);
    expect(claims[SchemaOrgOfferClaim.OfferedBy]).toBe(hostDid);
    expect(claims[SchemaOrgOfferClaim.Category]).toBe(sector);
  });

  it('offers at least two VetChain professional seats for USD 0 through 31 December 2026', () => {
    const claims = generateLicenseOffer(
      1, hostDid, 'CA-BC', 'animal-care', allowedPaymentMethods,
      undefined, new Date('2026-12-31T23:59:59.999Z'),
    );

    expect(claims[SchemaOrgOfferClaim.ItemOfferedName]).toBe('VetChain professional licence');
    expect(claims[SchemaOrgOfferClaim.EligibleQuantityValue]).toBe(2);
    expect(claims[SchemaOrgOfferClaim.Price]).toBe('0.00');
    expect(claims[SchemaOrgOfferClaim.PriceCurrency]).toBe('USD');
  });

  it('prices each VetChain professional seat at USD 20 after the promotion', () => {
    process.env.VETCHAIN_BILLING_MERCHANT_ID = 'merchant-selected-before-launch';
    const claims = generateLicenseOffer(
      2, hostDid, 'CA-BC', 'animal-care', allowedPaymentMethods,
      undefined, new Date('2027-01-01T00:00:00.000Z'),
    );

    expect(claims[SchemaOrgOfferClaim.EligibleQuantityValue]).toBe(2);
    expect(claims[SchemaOrgOfferClaim.Price]).toBe('20.00');
    expect(claims[SchemaOrgOfferClaim.PriceCurrency]).toBe('USD');
    delete process.env.VETCHAIN_BILLING_MERCHANT_ID;
  });

  it('does not create a paid VetChain offer until the billing merchant is configured', () => {
    delete process.env.VETCHAIN_BILLING_MERCHANT_ID;
    expect(() => generateLicenseOffer(
      2, hostDid, 'CA-BC', 'animal-care', allowedPaymentMethods,
      undefined, new Date('2027-01-01T00:00:00.000Z'),
    )).toThrow('VetChain paid licensing requires VETCHAIN_BILLING_MERCHANT_ID.');
  });
});
