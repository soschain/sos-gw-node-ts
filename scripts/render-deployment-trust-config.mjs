// Flow contract: operator-owned trust objects are validated before deployment and
// serialized as JSON-compatible YAML strings without shell/sed interpolation.
import { readFileSync, writeFileSync } from 'node:fs';

const names = ['CREDENTIAL_TRUSTED_ISSUERS_JSON', 'CLEARING_HOUSE_REQUESTERS_JSON', 'GXDCH_TENANTS_JSON'];
const values = new Map();
for (const name of names) {
  let value;
  try { value = JSON.parse(process.env[name]?.trim() || '{}'); }
  catch { throw new Error(`${name} must contain a JSON object.`); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must contain a JSON object.`);
  values.set(name, JSON.stringify(JSON.stringify(value)));
}
const target = process.argv[2];
if (target !== '--validate') {
  if (!target || process.argv.length !== 3) throw new Error('Expected a rendered ConfigMap path or --validate.');
  let text = readFileSync(target, 'utf8');
  for (const [name, yamlString] of values) {
    const marker = `__${name}_YAML__`;
    if (text.split(marker).length !== 2) throw new Error(`Expected exactly one ${name} placeholder.`);
    text = text.replace(marker, () => yamlString);
  }
  writeFileSync(target, text);
}
