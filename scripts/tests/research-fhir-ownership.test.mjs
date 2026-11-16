// Flow contract: canonical Group and ResearchStudy catalogs/projections use their existing independent FHIR owner; descriptive membership and research parties grant no authority.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const canonicalNames = new Set([
  'GroupFlatClaimCatalog', 'normalizeGroupR5FlatClaimsResource',
  'ResearchStudyFlatClaimCatalog', 'ResearchStudyR5PartyRoleCodes',
  'ResearchStudyR5PartyRoleSystem', 'normalizeResearchStudyR5FlatClaimsResource',
  'projectGroupPractitionerRoleMemberFlatClaimResources',
  'projectGroupR5FlatClaimsResource', 'projectResearchStudyR5SearchClaims',
])

test('Group and ResearchStudy standards imports do not use product or GDC data packages', async () => {
  const root = new URL('../../src/', import.meta.url)
  const violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      const importing = ts.isImportDeclaration(node)
      if (!(importing || ts.isExportDeclaration(node)) || !node.moduleSpecifier || !ts.isStringLiteralLike(node.moduleSpecifier) || !/^(?:gdc|vet|uhc)-/.test(node.moduleSpecifier.text)) continue
      const bindings = importing ? node.importClause?.namedBindings : node.exportClause
      if (bindings && (ts.isNamedImports(bindings) || ts.isNamedExports(bindings))) {
        for (const item of bindings.elements) {
          const name = item.propertyName?.text ?? item.name.text
          if (canonicalNames.has(name)) violations.push(`${path}: ${name}`)
        }
      }
    }
  }
  assert.deepEqual(violations, [])
})
