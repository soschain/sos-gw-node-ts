import { resolve as resolveTypeScript, load as loadTypeScript } from 'ts-node/esm';

/** Keep published dependency exports under Node's own module-format rules. */
export function resolve(specifier, context, nextResolve) {
  const relativeOrFile = specifier.startsWith('.') || specifier.startsWith('/')
    || specifier.startsWith('file:');
  if (!relativeOrFile || context.parentURL?.includes('/node_modules/')) {
    return nextResolve(specifier, context);
  }
  return resolveTypeScript(specifier, context, nextResolve);
}

/** Transpile local TypeScript only; native JavaScript dependencies stay native. */
export function load(url, context, nextLoad) {
  if (url.endsWith('.ts') && !url.includes('/node_modules/')) {
    return loadTypeScript(url, context, nextLoad);
  }
  return nextLoad(url, context);
}
