// An explicitly synthetic, loopback-only HTTPS oracle for the local image gate.
// No production ICA, credential database, cloud identity or private key is read.
import { createServer } from 'node:https';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';

export async function startLocalFabricFixtureStatusServer({ profile, issuer, key, cert, port = 0, advertisedHostname = '127.0.0.1' }) {
  if (profile !== 'local-fabric' || [process.env.NODE_ENV, process.env.DEPLOYMENT_ENV].some(value => ['production', 'prod', 'staging'].includes(String(value || '').toLowerCase()))) {
    throw new Error('The synthetic status oracle is restricted to the explicit local Fabric profile.');
  }
  if (!Array.isArray(issuer?.credentials) || !issuer?.jwks?.keys?.length || !key || !cert) throw new Error('Local signed credentials and TLS custody are required.');
  if (!['127.0.0.1', 'localhost', 'host.docker.internal'].includes(advertisedHostname)) throw new Error('Fixture discovery may advertise only the explicit local harness.');
  const statusRequestType = `${e.httpsBaseUrl}/ica/credential-status-request`;
  const pending = new Map();
  let origin; let advertisedOrigin;
  const server = createServer({ key, cert }, async (req, res) => {
    const json = (code, body) => { res.writeHead(code, { 'content-type': 'application/didcomm-plain+json' }); res.end(JSON.stringify(body)); };
    try {
      const url = new URL(req.url, origin);
      if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') return json(200, {
        issuer: advertisedOrigin, jwks_uri: `${advertisedOrigin}/.well-known/jwks.json`, id_token_signing_alg_values_supported: ['ES384'],
      });
      if (req.method === 'GET' && url.pathname === '/.well-known/ica-configuration') return json(200, {
        syntheticFixture: true, profile: 'local-fabric', issuer: issuer.issuerDid, statusRequestType,
        statusEndpointTemplate: `${advertisedOrigin}/credentials/{credentialType}/_status`,
      });
      if (req.method === 'GET' && url.pathname === '/.well-known/jwks.json') return json(200, issuer.jwks);
      if (req.method === 'GET' && url.pathname === '/.well-known/did.json') return json(200, { id: issuer.issuerDid,
        verificationMethod: issuer.jwks.keys.map(jwk => ({ id: `${issuer.issuerDid}#${jwk.kid}`, controller: issuer.issuerDid, type: 'JsonWebKey2020', publicKeyJwk: jwk })),
        assertionMethod: issuer.jwks.keys.map(jwk => `${issuer.issuerDid}#${jwk.kid}`) });
      const match = /^\/credentials\/([A-Za-z][A-Za-z0-9:_,\-]*)\/(_status|_status-response)$/.exec(url.pathname);
      if (req.method !== 'POST' || !match) return json(404, { error: 'Unknown local fixture route.' });
      const chunks = []; let length = 0;
      for await (const chunk of req) { length += chunk.length; if (length > 65_536) return json(413, { error: 'Local status input too large.' }); chunks.push(chunk); }
      const input = JSON.parse(Buffer.concat(chunks).toString() || '{}');
      const types = match[1];
      if (match[2] === '_status') {
        const entries = input?.body?.data;
        if (input.type !== statusRequestType || typeof input.thid !== 'string' || !input.thid || input.thid.length > 256
          || !Array.isArray(entries) || entries.length !== 1 || typeof entries[0]?.credentialId !== 'string' || !entries[0].credentialId) return json(400, { error: 'Invalid local fixture status request.' });
        const now = Date.now(); for (const [id, job] of pending) if (job.expiresAt <= now) pending.delete(id);
        if (pending.size >= 1024) return json(503, { error: 'Local fixture thread limit reached.' });
        if (pending.has(input.thid)) return json(409, { error: 'Local fixture thread already exists.' });
        pending.set(input.thid, { types, credentialId: entries[0].credentialId, expiresAt: now + 60_000 });
        const poll = new URL(`/credentials/${types}/_status-response`, origin); poll.searchParams.set('thid', input.thid);
        res.writeHead(202, { location: `${poll.pathname}${poll.search}` }); return res.end();
      }
      const thread = url.searchParams.get('thid'); const job = pending.get(thread);
      if (!job || job.types !== types || job.expiresAt <= Date.now()) return json(404, { error: 'Unknown local fixture thread.' });
      pending.delete(thread);
      const credential = issuer.credentials.find(value => value.id === job.credentialId && value.type.join(',') === types);
      return json(200, { body: { data: [{ response: { status: '200' }, resource: { status: 'resolved', thid: thread,
        credentialType: types, content: [{ credentialId: job.credentialId, status: credential ? issuer.status(job.credentialId) : 'unknown', checkedAt: new Date().toISOString() }] } }] } });
    } catch { if (!res.headersSent) return json(400, { error: 'Invalid local fixture request.' }); res.end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  const address = server.address(); origin = `https://127.0.0.1:${address.port}`; advertisedOrigin = `https://${advertisedHostname}:${address.port}`;
  return { origin, advertisedOrigin, statusRequestType, statusEndpointTemplate: `${advertisedOrigin}/credentials/{credentialType}/_status`, close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}
