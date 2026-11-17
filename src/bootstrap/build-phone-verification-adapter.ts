import type { IServerConfig } from '../config';
import type { IPhoneAdapter } from '../adapters/phone/IPhoneAdapter';
import { MockPhoneAdapter } from '../adapters/phone/MockPhoneAdapter';
import { TwilioPhoneAdapter } from '../adapters/phone/TwilioPhoneAdapter';
import { isLocalDemoSecurityMode, isLocalDemoSecurityModeForConfiguration, type RuntimeSecurityConfiguration } from '../security/runtime-security-policy';

type PhoneVerificationConfiguration = Pick<IServerConfig, 'uhcTelephony'> & RuntimeSecurityConfiguration;

/** Select a real Verify provider; simulated OTP belongs only to explicit local Demo. */
export function buildPhoneVerificationAdapter(config: PhoneVerificationConfiguration): IPhoneAdapter {
  const twilio = config.uhcTelephony?.twilio;
  const realProviderReady = config.uhcTelephony?.provider === 'twilio'
    && Boolean(twilio?.accountSid?.trim() && twilio.authToken?.trim() && twilio.verifyServiceSid?.trim());
  if (realProviderReady && twilio?.accountSid && twilio.authToken && twilio.verifyServiceSid) {
    return new TwilioPhoneAdapter({
      accountSid: twilio.accountSid,
      authToken: twilio.authToken,
      apiKeySid: twilio.apiKeySid,
      apiKeySecret: twilio.apiKeySecret,
      messagingServiceSid: twilio.messagingServiceSid || '',
      verifyServiceSid: twilio.verifyServiceSid,
      voiceFromNumber: twilio.voiceFromNumber,
    });
  }
  if (!isLocalDemoSecurityMode() || !isLocalDemoSecurityModeForConfiguration(config)) {
    throw new Error('Enabled phone verification requires a configured real Twilio Verify provider outside explicit local Demo.');
  }
  return new MockPhoneAdapter();
}
