// Flow contract: current DSP route registration and advertisement use SOS-owned deterministic relative-path formatters with exact existing wire behavior; authorization and URL resolution remain unchanged.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
import * as owned from 'sos-data-utils-ts/gateway-dataspace-routing';
const expected=JSON.parse(readFileSync('src/__tests__/data/dataspace-routing-vectors.json','utf8'));
const names={buildGwDataspaceBasePath:'buildGatewayDataspaceBasePath',buildGwDspaceVersionWellKnownPath:'buildGatewayDataspaceVersionPath',buildGwCatalogRequestPath:'buildGatewayDataspaceCatalogRequestPath',buildGwCatalogCollectionPath:'buildGatewayDataspaceCatalogCollectionPath',buildGwCatalogArtifactPath:'buildGatewayDataspaceCatalogArtifactPath',buildGwCatalogDatasetPath:'buildGatewayDataspaceCatalogDatasetPath'};
const paths=['src/routes/discovery.ts','src/utils/services.ts','src/__tests__/unit/utils/services.test.ts','src/__tests__/unit/utils/dataspace.did-services.compliance.test.ts','src/__tests__/integration/wellKnownApi.test.ts'];
test('all five DSP route consumers use canonical SOS Data builders rather than a legacy import or alias',()=>{
 for(const path of paths){const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true);let found=0;
  for(const s of source.statements){const bindings=s.importClause?.namedBindings;if(!ts.isImportDeclaration(s)||!bindings||!ts.isNamedImports(bindings))continue;
   for(const e of bindings.elements){const name=e.propertyName?.text??e.name.text;if(Object.hasOwn(names,name)||Object.values(names).includes(name)){
    found++;assert.equal(s.moduleSpecifier.text,'sos-data-utils-ts/gateway-dataspace-routing',path);assert.equal(Object.hasOwn(names,name),false,`${path}:old API`);assert.equal(e.name.text,name,`${path}:alias`);
   }}
  }
  assert.ok(found>0,`missing inventoried ${path}`);
 }
});
test('preserves all original tenant/host/precedence/fallback and explicit dataset path vectors without mutation',()=>{
 assert.equal(expected.allExact,true);assert.equal(expected.vectors.length,106);
 for(const vector of expected.vectors){const before=structuredClone(vector.input);assert.equal(owned[vector.name](vector.input,...(Object.hasOwn(vector,'datasetId')?[vector.datasetId]:[])),vector.expected);assert.deepEqual(vector.input,before);}
});
