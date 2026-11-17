import { register } from 'node:module';

process.env.TS_NODE_TRANSPILE_ONLY = '1';
process.env.TS_NODE_SKIP_IGNORE = '1';
process.env.TS_NODE_EXPERIMENTAL_RESOLVER = '1';
process.env.TS_NODE_EXPERIMENTAL_SPECIFIER_RESOLUTION = 'node';
process.env.TS_NODE_COMPILER_OPTIONS = JSON.stringify({
  module: 'NodeNext',
  moduleResolution: 'NodeNext',
  allowImportingTsExtensions: true,
});

register(new URL('./tsnode-local-loader.mjs', import.meta.url));
