// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import express from 'express';
import request from 'supertest';
import { EXAMPLE_FORM_SUBJECT_PHONE } from 'sos-data-utils-ts/gateway-flow-examples';
import { SchemaOrgPersonClaim } from 'antifraud-data-utils-ts/schema-org-claims';
import { createUhcTwilioWebhooksRouter } from '../../../routes/uhc-twilio-webhooks';
import { createSubjectVaultVoiceTargetResolver } from '../../../services/SubjectVaultVoiceTargetResolver';

describe('telephony log privacy', () => {
  const privateText = 'synthetic confidential input';
  const subjectPhone = EXAMPLE_FORM_SUBJECT_PHONE;

  it('delivers an authenticated inbound SMS to its callback without logging its body or phone', async () => {
    const app = express();
    const validateWebhookSignature = jest.fn(() => true);
    const onInboundResponse = jest.fn(async () => { throw new Error(privateText); });
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      app.use('/webhooks', createUhcTwilioWebhooksRouter({
        apiBaseUrl: 'https://example.invalid',
        phoneAdapter: { validateWebhookSignature } as any,
        signatureValidation: true,
        onInboundResponse,
      }));
      await request(app).post('/webhooks/twilio/sms/inbound').type('form')
        .send({ From: subjectPhone, Body: privateText }).expect(200);
      expect(validateWebhookSignature).toHaveBeenCalledTimes(1);
      expect(onInboundResponse).toHaveBeenCalledWith(expect.objectContaining({ from: subjectPhone, body: privateText }));
      const logs = JSON.stringify([log.mock.calls, error.mock.calls]);
      expect(logs).not.toContain(privateText);
      expect(logs).not.toContain(subjectPhone);
    } finally {
      log.mockRestore();
      error.mockRestore();
    }
  });

  it('resolves the phone without logging decrypted claims or subject identifiers', async () => {
    const debug = jest.spyOn(console, 'debug').mockImplementation(() => {});
    const info = jest.spyOn(console, 'info').mockImplementation(() => {});
    const getContainersInSection = jest.fn(async () => [{ id: privateText }]);
    const unprotectConfidentialData = jest.fn(async () => ({ claims: { [SchemaOrgPersonClaim.Telephone]: subjectPhone } }));
    try {
      const resolve = createSubjectVaultVoiceTargetResolver({
        vaultRepository: { getContainersInSection } as any,
        kmsService: { unprotectConfidentialData } as any,
      });
      await expect(resolve({ subjectId: privateText } as any, { tenantId: 'host' } as any))
        .resolves.toEqual({ source: 'subject-vault', to: subjectPhone });
      const logs = JSON.stringify([debug.mock.calls, info.mock.calls]);
      expect(logs).not.toContain(privateText);
      expect(logs).not.toContain(subjectPhone);
    } finally {
      debug.mockRestore();
      info.mockRestore();
    }
  });
});
