import { isKnownServiceCapability, parseServiceCapabilityTokens } from 'sos-data-utils-ts/service-capabilities';

type ServiceAuthorizationIssue = Readonly<{ code: string; message: string }>;
function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' ? value as Record<string, unknown> : undefined;
}
function categoryTokens(value: unknown): string[] {
  if (Array.isArray(value)) return [...new Set(value.flatMap(categoryTokens))];
  return typeof value === 'string' ? [...new Set(value.split(',').map(token => token.trim()).filter(Boolean))] : [];
}

/** Scope admission only; the existing activation trust boundary must verify this credential first. */
export function validateHostedServiceAuthorization(input: {
  organizationCredential?: unknown;
  requiredCategory?: string;
  requiredServiceTypes?: ReadonlyArray<string | undefined | null>;
}): ServiceAuthorizationIssue[] {
  const subjects = record(input.organizationCredential)?.credentialSubject;
  const subject = record(Array.isArray(subjects) ? subjects[0] : subjects) || {};
  const offer = record(subject.makesOffer) || {};
  const categories = categoryTokens(offer.category ?? subject.category);
  const services = [...new Set([
    ...parseServiceCapabilityTokens(offer.serviceType ?? subject.serviceType),
    ...parseServiceCapabilityTokens(offer.additionalType ?? subject.additionalType).filter(isKnownServiceCapability),
  ])];
  const category = String(input.requiredCategory || '').trim();
  const requiredServices = [...new Set((input.requiredServiceTypes || []).map(value => String(value || '').trim()).filter(Boolean))];
  const errors: ServiceAuthorizationIssue[] = [];
  if (category) {
    if (!categories.length) errors.push({
      code: 'MISSING_ORGANIZATION_SERVICE_CATEGORY',
      message: 'ICA-issued organization credential is missing credentialSubject.makesOffer.category authorization.',
    });
    else if (!categories.includes(category) && !categories.includes('*')) errors.push({
      code: 'UNAUTHORIZED_ORGANIZATION_SERVICE_CATEGORY',
      message: `ICA-issued organization credential does not authorize service category '${category}'.`,
    });
  }
  if (requiredServices.length) {
    if (!services.length) errors.push({
      code: 'MISSING_ORGANIZATION_SERVICE_TYPE',
      message: 'ICA-issued organization credential is missing credentialSubject.makesOffer.serviceType authorization.',
    });
    else {
      const unauthorized = requiredServices.find(value => !services.includes(value));
      if (unauthorized !== undefined) errors.push({
        code: 'UNAUTHORIZED_ORGANIZATION_SERVICE_TYPE',
        message: `ICA-issued organization credential does not authorize serviceType '${unauthorized}'.`,
      });
    }
  }
  return errors;
}
