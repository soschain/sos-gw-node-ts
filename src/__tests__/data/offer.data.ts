// src/__tests__/data/offer.data.ts
// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { SchemaOrgOfferClaim } from 'antifraud-data-utils-ts/schema-org-claims';

export const testClaimsOfferEntityExpanded = {
    [SchemaOrgOfferClaim.AcceptedPaymentMethod]: "Stripe",
    [SchemaOrgOfferClaim.Category]: "health-care",
    [SchemaOrgOfferClaim.CheckoutPageUrlTemplate]: "<payment-url>",
    [SchemaOrgOfferClaim.EligibleCustomerType]: "employee",
    [SchemaOrgOfferClaim.EligibleQuantityValue]: 2, // for the legal representative and a first employee
    [SchemaOrgOfferClaim.Identifier]: "urn:cds-<jurisdiction>:v1:<sector>:product:org.schema:Offer:<offer-uuid>",
    [SchemaOrgOfferClaim.ItemOfferedName]: "License Tier XS",
    [SchemaOrgOfferClaim.ItemOfferedSku]: "web-or-app-identifier",
    [SchemaOrgOfferClaim.OfferedBy]: "did:web:host.example.com",
    [SchemaOrgOfferClaim.Price]: "0.00",
    [SchemaOrgOfferClaim.PriceCurrency]: "EUR",
    [SchemaOrgOfferClaim.SerialNumber]: "<license1>,<license2>"
}

export const testClaimsOfferFamilyExpanded = {
    [SchemaOrgOfferClaim.AcceptedPaymentMethod]: "Stripe",
    [SchemaOrgOfferClaim.Category]: "health-care",
    [SchemaOrgOfferClaim.CheckoutPageUrlTemplate]: "<payment-url>",
    [SchemaOrgOfferClaim.EligibleCustomerType]: "individual",
    [SchemaOrgOfferClaim.EligibleQuantityValue]: 2, // for the representative and the subject (individual / customer / patient / donor)
    [SchemaOrgOfferClaim.Identifier]: "urn:cds-<jurisdiction>:v1:<sector>:product:org.schema:Offer:<offer-uuid>",
    [SchemaOrgOfferClaim.ItemOfferedName]: "License Tier XS",
    [SchemaOrgOfferClaim.ItemOfferedSku]: "web-or-app-identifier",
    [SchemaOrgOfferClaim.OfferedBy]: "did:web:gateway.example.com",
    [SchemaOrgOfferClaim.Price]: "0.00",
    [SchemaOrgOfferClaim.PriceCurrency]: "EUR",
    [SchemaOrgOfferClaim.SerialNumber]: "<license1>,<license2>"
}