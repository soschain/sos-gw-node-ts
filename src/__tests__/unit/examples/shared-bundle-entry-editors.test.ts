// Flow contract: owned FHIR editors project the same three clinical resources into a Composition-first document with explicit native Patient context; the context projection never creates an index identity or access authority.
import { EXAMPLE_CONDITION_CODE, EXAMPLE_CONDITION_IDENTIFIER, EXAMPLE_COMPOSITION_DATE_MEDICATION_DOCUMENT, EXAMPLE_COMPOSITION_IDENTIFIER_MEDICATION_DOCUMENT, EXAMPLE_COMPOSITION_TITLE_MEDICATION_DOCUMENT, EXAMPLE_MEDICATION_STATEMENT_IDENTIFIER, EXAMPLE_MEDICATION_STATEMENT_STATUS, EXAMPLE_MEDICATION_STATEMENT_TEXT, EXAMPLE_SUBJECT_DID } from 'sos-data-utils-ts/gateway-flow-examples';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';
import { HealthcareCoreSections } from 'sos-data-utils-ts/healthcare-sections';
import { BundleReader } from 'sos-data-utils-ts/bundle-contract';
import { type FhirResource, normalizeFhirApiClaimKey, buildClinicalDocumentBundle, clinicalArtifactFhirR4FromEditorClaims, clinicalArtifactSubjectClaims, clinicalArtifactFhirR4ToFlat, buildVitalSignObservationEntry, FHIR_IPS_CLINICAL_ARTIFACT_SCHEMAS, FHIR_IPS_DOCUMENT_TYPE_CLAIM, VitalSignsCodes, VitalSignsUnits, AllergyIntoleranceClaim, MedicationStatementClaim, ConditionClaim } from 'fhir-data-utils-ts';

describe('owned clinical editor and document workflow in GW', () => {
  it('exposes owned clinical editing and scalar vital-sign projection capabilities', () => {
    for (const resourceType of ['Observation','AllergyIntolerance','MedicationStatement','Condition'] as const) {
      const schema = FHIR_IPS_CLINICAL_ARTIFACT_SCHEMAS[resourceType];
      expect(clinicalArtifactFhirR4FromEditorClaims(resourceType, schema.initialClaims, clinicalArtifactSubjectClaims(resourceType, EXAMPLE_SUBJECT_DID)).resourceType).toBe(resourceType);
    }
    const vital = buildVitalSignObservationEntry({identifier:SAFE.resourceUuid,subject:EXAMPLE_SUBJECT_DID,code:VitalSignsCodes.SystolicBloodPressure,unit:VitalSignsUnits.MillimeterOfMercury,valueQuantity:120});
    expect(vital.resource.resourceType).toBe('Observation');
    const nativeVitalResource: FhirResource = vital.resource;
    expect(nativeVitalResource.valueQuantity).toEqual(expect.objectContaining({value:120}));
  });

  it('uses typed entry editors for AllergyIntolerance, MedicationStatement, and Condition claims', () => {
    const authored = [
      {resourceType:'AllergyIntolerance' as const,entryId:'allergy-001',section:HealthcareCoreSections.AllergiesAndIntolerances.attributeValue,claims:{[AllergyIntoleranceClaim.Identifier]:'urn:uuid:allergy-001',[AllergyIntoleranceClaim.Subject]:EXAMPLE_SUBJECT_DID,[AllergyIntoleranceClaim.Code]:'http://snomed.info/sct|91936005'}},
      {resourceType:'MedicationStatement' as const,entryId:'medication-001',section:HealthcareCoreSections.HistoryOfMedicationUse.attributeValue,claims:{[MedicationStatementClaim.Identifier]:EXAMPLE_MEDICATION_STATEMENT_IDENTIFIER,[MedicationStatementClaim.Subject]:EXAMPLE_SUBJECT_DID,[MedicationStatementClaim.Status]:EXAMPLE_MEDICATION_STATEMENT_STATUS,[MedicationStatementClaim.CodeText]:EXAMPLE_MEDICATION_STATEMENT_TEXT}},
      {resourceType:'Condition' as const,entryId:'condition-001',section:HealthcareCoreSections.ProblemList.attributeValue,claims:{[ConditionClaim.Identifier]:EXAMPLE_CONDITION_IDENTIFIER,[ConditionClaim.Subject]:EXAMPLE_SUBJECT_DID,[ConditionClaim.Code]:EXAMPLE_CONDITION_CODE}},
    ];
    const bundle = buildClinicalDocumentBundle({
      documentId:SAFE.resourceUuid,compositionId:EXAMPLE_COMPOSITION_IDENTIFIER_MEDICATION_DOCUMENT.replace(/^urn:uuid:/u,''),subjectReference:EXAMPLE_SUBJECT_DID,
      documentType:FHIR_IPS_DOCUMENT_TYPE_CLAIM,title:EXAMPLE_COMPOSITION_TITLE_MEDICATION_DOCUMENT,date:EXAMPLE_COMPOSITION_DATE_MEDICATION_DOCUMENT,status:'final',authorReferences:[EXAMPLE_SUBJECT_DID],
      subjectProjection:{resourceType:'Patient',id:SAFE.resourceUuid,fullUrl:EXAMPLE_SUBJECT_DID},
      entries:authored.map(entry=>({resourceType:entry.resourceType,entryId:entry.entryId,sectionCodes:[entry.section],claims:Object.fromEntries(Object.entries(clinicalArtifactFhirR4ToFlat(clinicalArtifactFhirR4FromEditorClaims(entry.resourceType,entry.claims))).map(([key,value])=>[normalizeFhirApiClaimKey(key),value]))})),
    });

    const reader = new BundleReader(bundle);

    // A document build materializes the three authored clinical entries plus
    // the Composition root and the Patient projection derived from its subject.
    expect(reader.getEntries()).toHaveLength(5);
    expect(bundle.entry).toHaveLength(5);
    expect(bundle.entry?.map((entry: any) => entry.resource?.resourceType)).toEqual(
      expect.arrayContaining([
        'Composition',
        'Patient',
        'AllergyIntolerance',
        'MedicationStatement',
        'Condition',
      ]),
    );

    const entries = reader.getEntries() as Array<{
      resource?: {
        meta?: {
          claims?: Record<string, unknown>;
        };
      };
    }>;

    const clinicalEntries = entries.filter((entry) =>
      ['AllergyIntolerance', 'MedicationStatement', 'Condition'].includes(
        String((entry.resource as any)?.resourceType || ''),
      ),
    );
    expect(clinicalEntries).toHaveLength(3);

    expect(clinicalEntries[0]?.resource?.meta?.claims).toEqual(
      expect.objectContaining({
        'AllergyIntolerance.identifier': 'urn:uuid:allergy-001',
        'AllergyIntolerance.subject': EXAMPLE_SUBJECT_DID,
        'Composition.section': HealthcareCoreSections.AllergiesAndIntolerances.attributeValue,
      }),
    );
    expect(clinicalEntries[1]?.resource?.meta?.claims).toEqual(
      expect.objectContaining({
        'MedicationStatement.identifier': EXAMPLE_MEDICATION_STATEMENT_IDENTIFIER,
        'MedicationStatement.subject': EXAMPLE_SUBJECT_DID,
        'MedicationStatement.code-text': EXAMPLE_MEDICATION_STATEMENT_TEXT,
      }),
    );
    expect(clinicalEntries[2]?.resource?.meta?.claims).toEqual(
      expect.objectContaining({
        'Condition.identifier': EXAMPLE_CONDITION_IDENTIFIER,
        'Condition.subject': EXAMPLE_SUBJECT_DID,
        'Condition.code': EXAMPLE_CONDITION_CODE,
      }),
    );
  });
});
