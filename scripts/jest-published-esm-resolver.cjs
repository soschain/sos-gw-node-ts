/** Resolve the published ESM exports used by the independent encoding stack. */
module.exports = (request, options) => {
  try {
    return options.defaultResolver(request, options);
  } catch (error) {
    const esmOnly = request === '@ipld/dag-json'
      || request === 'multiformats' || request.startsWith('multiformats/')
      || request === 'cborg' || request.startsWith('cborg/');
    const missingImportCondition = ['MODULE_NOT_FOUND', 'ERR_PACKAGE_PATH_NOT_EXPORTED'].includes(error.code)
      || /No known conditions for /u.test(error.message);
    if (!esmOnly || !missingImportCondition) throw error;
    return options.defaultResolver(request, {
      ...options,
      conditions: [...new Set([...(options.conditions || []).filter(value => value !== 'require'), 'import'])],
    });
  }
};
