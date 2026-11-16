// Flow contract: neutral DIDComm envelopes, SOS message entries and the existing SOS wire-format catalog have independent owners without changing clinical meaning or authentication decisions.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const messageNames = new Set(['CommMsgExtended', 'DataEntry', 'DidCommPayload', 'DidCommAttachment', 'DIDCOMM_DEFAULT_ACCEPT_HEADER', 'DIDCOMM_PLAINTEXT_JSON_MEDIA_TYPE'])

test('communication message and wire-format imports do not use GDC contracts', async () => {
  const root = new URL('../../src/', import.meta.url)
  const violations = []
  for (const path of (await readdir(root, { recursive: true })).filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    for (const node of source.statements) {
      const importing = ts.isImportDeclaration(node)
      if (!(importing || ts.isExportDeclaration(node)) || !node.moduleSpecifier || !ts.isStringLiteralLike(node.moduleSpecifier) || !node.moduleSpecifier.text.startsWith('gdc-')) continue
      const module = node.moduleSpecifier.text
      const bindings = importing ? node.importClause?.namedBindings : node.exportClause
      if (bindings && (ts.isNamedImports(bindings) || ts.isNamedExports(bindings))) {
        for (const item of bindings.elements) {
          const name = item.propertyName?.text ?? item.name.text
          if (messageNames.has(name) || (name === 'Format' && /\/constants\/Schemas(?:\.js)?$/.test(module))) violations.push(`${path}: ${name}`)
        }
      }
    }
  }
  assert.deepEqual(violations, [])
})
