import { describe, expect, it } from '@jest/globals';
import { HealthcareCoreSections, HealthcarePermissionSummarySections } from 'sos-data-utils-ts/healthcare-sections';

describe('shared healthcare constants', () => {
  it('retains the complete core operational IPS sections', () => {
    expect(HealthcareCoreSections.Alert.attributeValue).toBe('LOINC|104605-1');
    expect(HealthcareCoreSections.PregnancyHistory.attributeValue).toBe('LOINC|10162-6');
    expect(HealthcareCoreSections.GoalsAndPreferences.attributeValue).toBe('LOINC|81338-6');
  });

  it('exposes the operational permission-summary subset', () => {
    expect(HealthcarePermissionSummarySections.Alert).toBeDefined();
    expect(HealthcarePermissionSummarySections.PregnancyHistory).toBeDefined();
    expect(HealthcarePermissionSummarySections.GoalsAndPreferences).toBeDefined();

    expect('DietAndNutrition' in HealthcarePermissionSummarySections).toBe(false);
    expect('HistoryOfFamilyMemberDiseases' in HealthcarePermissionSummarySections).toBe(false);
    expect('HistoryOfHospitalizationsAndOutpatientVisits' in HealthcarePermissionSummarySections).toBe(false);
    expect('HistoryOfPresentIllness' in HealthcarePermissionSummarySections).toBe(false);
    expect('ProblemListNarrativeReported' in HealthcarePermissionSummarySections).toBe(false);
    expect('Instructions' in HealthcarePermissionSummarySections).toBe(false);
  });
});
