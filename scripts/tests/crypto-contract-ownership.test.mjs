// Flow contract: Gateway cryptographic engines and key contracts come from Antifraud and never from a frozen runtime.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import ts from 'typescript'

const frozenModules = /^gdc-common-utils-ts\/(?:CryptographyService|interfaces\/(?:ICryptography|ICryptoHelper|Cryptography\.types)|models\/(?:jwk|aes))$/u
const owned = new Set(['AesManager', 'CryptographyService', 'ICryptography', 'ICryptoHelper', 'JWK', 'JwkSet', 'BaseJwk', 'EcBaseJwk', 'MldsaAlg', 'MlkemCurve', 'PublicJwk', 'MlkemPublicJwk', 'MldsaPublicJwk', 'MlkemPrivateJwk', 'MldsaPrivateJwk', 'ProtectedDataAES', 'AesGcmComponents'])

test('static and dynamic engine/key imports have their neutral package owner', async () => {
  const root = new URL('../../src/', import.meta.url)
  const files = await readdir(root, { recursive: true })
  const violations = []
  for (const path of files.filter(path => path.endsWith('.ts'))) {
    const source = ts.createSourceFile(path, await readFile(new URL(path.replaceAll('\\', '/'), root), 'utf8'), ts.ScriptTarget.Latest, true)
    const visit = node => {
      if (ts.isStringLiteralLike(node) && frozenModules.test(node.text)) violations.push(`${path}: ${node.text}`)
      if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier) && node.moduleSpecifier.text.startsWith('gdc-')) {
        const bindings = node.importClause?.namedBindings
        if (bindings && ts.isNamedImports(bindings)) for (const item of bindings.elements) {
          const name = item.propertyName?.text ?? item.name.text
          if (owned.has(name)) violations.push(`${path}: ${name}`)
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
  assert.equal(violations.length, 0, violations.join('\n'))
})
