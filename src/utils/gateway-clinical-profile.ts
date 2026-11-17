import type {FhirResource} from 'fhir-data-utils-ts/fhir-types';
import {ResourceTypesFhirR4 as R,ResourceTypesFhirR5 as R5} from 'fhir-data-utils-ts';
import {normalizeFhirApiClaimKey} from 'fhir-data-utils-ts/claim-helpers';
import {identifierToValue} from 'fhir-data-utils-ts/converters';
import {
  indexedR4ResourceToClaims,indexedR4ClaimsToResource,indexedStructuralResourceToClaims,
  type IndexedR4SemanticInputType,type IndexedR4SemanticOutputType,
  type IndexedStructuralCompatibilityType,
} from 'fhir-data-utils-ts/indexed-r4';

// Fixed GW admission profiles. A future library family does not opt itself into this gateway.
const semanticInputTypes=Object.freeze([R.MedicationStatement,R.Observation,R.AllergyIntolerance,R.Condition,R.DeviceUseStatement,R.Flag,R.Procedure,R.Immunization,R.DocumentReference,R.RelatedPerson,R.DiagnosticReport,R.CarePlan,R.Encounter,R.Consent] as const);
const structuralInputTypes=Object.freeze([R.ImagingStudy,R.ImmunizationRecommendation,R.Medication,R5.EncounterHistory,R.AdverseEvent] as const);
const semanticOutputTypes=Object.freeze([R.AllergyIntolerance,R.CarePlan,R.Composition,R.Condition,R.Consent,R.DeviceUseStatement,R.DiagnosticReport,R.DocumentReference,R.Flag,R.Immunization,R.MedicationStatement,R.Observation,R.Procedure] as const);

function isSemanticInput(resource:FhirResource):resource is FhirResource&Readonly<{resourceType:IndexedR4SemanticInputType}>{
  return semanticInputTypes.some(type=>type===resource.resourceType);
}
function isStructuralInput(resource:FhirResource):resource is FhirResource&Readonly<{resourceType:IndexedStructuralCompatibilityType}>{
  return structuralInputTypes.some(type=>type===resource.resourceType);
}
/** Native import only. Embedded-claim precedence and authorization remain in the manager. */
export function projectGatewayClinicalNativeClaims(resource:FhirResource,structuralIdentifierIndexKey?:string):Record<string,unknown>{
  if(isSemanticInput(resource))return indexedR4ResourceToClaims(resource,{profile:'indexed-r4-semantic'});
  if(isStructuralInput(resource)){
    const claims=indexedStructuralResourceToClaims(resource,{profile:'indexed-structural-compat-v1'});
    if(structuralIdentifierIndexKey){
      const key=normalizeFhirApiClaimKey(structuralIdentifierIndexKey);
      if(!key.startsWith(`${resource.resourceType}.`))throw new TypeError('Clinical identifier index key must belong to the selected resource.');
      const first=Array.isArray(resource.identifier)?resource.identifier[0]:undefined;
      if(first&&typeof first.value==='string'&&first.value.trim())claims[key]=first.value.trim();
    }
    return claims;
  }
  throw new TypeError('Gateway clinical input resource type is unsupported.');
}

/** Selects semantic input columns without moving GW bookkeeping into the native FHIR projection. */
function semanticProjectionClaims(claims:Readonly<Record<string,unknown>>):Record<string,unknown>{
  const projection:Record<string,unknown>={};
  for(const [key,value] of Object.entries(claims)){
    if(key==='@context'){projection[key]=value;continue;}
    if(key==='@type'||value===undefined||value===null)continue;
    if(key.startsWith('org.hl7.fhir.')&&!key.startsWith('org.hl7.fhir.api.'))throw new TypeError('Unsupported FHIR projection claim namespace.');
    try{normalizeFhirApiClaimKey(key);}catch{continue;}
    if(['string','number','boolean'].includes(typeof value))projection[key]=value;
    else if(Array.isArray(value)&&value.every(item=>item===undefined||item===null||['string','number','boolean'].includes(typeof item))){
      // The prior GW native exporter projected governed primitive arrays as CSV.
      projection[key]=value.map(item=>item===undefined||item===null?'':String(item)).join(',');
    }else throw new TypeError('Clinical native projection requires a scalar or primitive-array claim.');
  }
  return projection;
}
/** Explicit R4-shaped compatibility output; the caller retains its existing GW overlays. */
export function projectGatewayIndexedClaimsToNative(resourceType:string,claims:Readonly<Record<string,unknown>>):FhirResource{
  const selected:IndexedR4SemanticOutputType|undefined=semanticOutputTypes.find(type=>type===resourceType);
  if(!selected)throw new TypeError('Gateway clinical output resource type is unsupported.');
  return indexedR4ClaimsToResource(selected,semanticProjectionClaims(claims),{profile:'indexed-r4-semantic'});
}

export type GatewayClinicalIndexIdentity=Readonly<{indexValue?:string;aliases:readonly string[]}>;
/** A proven native system/value pair can retain its old business index key while clinical claims retain the token. */
export function resolveGatewayClinicalIndexIdentity(resource:Readonly<{identifier?:unknown}>,identifierClaim:string|undefined):GatewayClinicalIndexIdentity{
  const claim=identifierClaim?.trim();
  if(!claim)return {aliases:[]};
  const first=Array.isArray(resource.identifier)?resource.identifier[0]:undefined;
  if(first&&typeof first==='object'&&!Array.isArray(first)&&typeof first.value==='string'){
    const value=first.value.trim(),system=typeof first.system==='string'?first.system:undefined;
    const token=identifierToValue({value:first.value,...(system?{system}:{})})?.trim();
    if(value&&system&&token&&(claim===token||claim===value))return {indexValue:value,aliases:[...new Set([claim,token,value])]};
  }
  // Preserve historical raw metadata identifiers; never infer a system or use resource.id.
  return {indexValue:claim,aliases:[claim]};
}

/** Derived search copy only. Signed/stored clinical claims are never rewritten for index identity. */
export function projectGatewayClinicalIndexClaims(claims:Readonly<Record<string,unknown>>,identifierNames:readonly string[],indexValue:string|undefined):Record<string,unknown>{
  const indexed={...claims};
  if(indexValue===undefined)return indexed;
  for(const key of Object.keys(indexed))if(identifierNames.some(name=>key===name||key.endsWith(`.${name}`)))indexed[key]=indexValue;
  return indexed;
}
