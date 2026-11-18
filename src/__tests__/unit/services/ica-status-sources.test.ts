// Flow contract: consult every approved status source for a shared issuer; any revocation or unavailable source denies acceptance, while unknown records never override a revocation.
import { createServer, type Server } from 'node:http';
import { REPOSITORY_SAFE_EXAMPLES as e } from 'sos-data-utils-ts/repository-privacy';
import { IcaCredentialStatusClient } from '../../../services/IcaCredentialStatusClient';

describe('ICA status across approved sources', () => {
  const servers: Server[] = [];
  afterEach(async () => { await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve())))); });
  async function fixture(states: readonly string[]) {
    let origin = '';
    const observed = new Set<number>();
    const credential = { id: e.resourceUuid, issuer: `did:web:${new URL(e.httpsBaseUrl).hostname}`, type: ['VerifiableCredential', 'OrganizationCredential'] };
    const server = createServer(async (req, res) => {
      const url = new URL(req.url!, origin);
      const source = Number(url.pathname.split('/')[1]);
      if (url.pathname.endsWith('/_status')) {
        observed.add(source);
        if (states[source] === 'unavailable') { res.writeHead(503); res.end(); return; }
        const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
        const input = JSON.parse(Buffer.concat(chunks).toString());
        const poll = new URL(url.pathname.replace(/_status$/, '_status-response'), origin);
        poll.searchParams.set('thid', input.thid);
        res.writeHead(202, { location: poll.href }); res.end();
      } else {
        res.setHeader('content-type', 'application/didcomm-plain+json');
        res.end(JSON.stringify({ body: { data: [{ response: { status: '200' }, resource: {
          status: 'resolved', thid: url.searchParams.get('thid'), credentialType: credential.type.join(','),
          content: [{ credentialId: credential.id, status: states[source], checkedAt: new Date().toISOString() }],
        } }] } }));
      }
    });
    servers.push(server); server.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Listener unavailable.');
    origin = `http://127.0.0.1:${address.port}`;
    const endpoints = states.map((_, index) => `${origin}/${index}/credentials/{credentialType}/_status`);
    const client = new IcaCredentialStatusClient({
      allowLocalTestEndpoint: true,
      resolveRequestType: () => `${e.httpsBaseUrl}/credential-status-request`,
      resolveEndpoint: (() => endpoints) as any,
    });
    return { client, credential, observed };
  }
  it('accepts a current credential only after consulting every approved store', async () => {
    const f = await fixture(['unknown', 'good']);
    await expect(f.client.check(f.credential)).resolves.toMatchObject({ status: 'good' });
    expect([...f.observed].sort()).toEqual([0, 1]);
  });
  it('preserves revocation when another approved store returns good', async () => {
    const f = await fixture(['revoked', 'good']);
    await expect(f.client.check(f.credential)).resolves.toMatchObject({ status: 'revoked' });
    expect(f.observed.size).toBe(2);
  });
  it('does not accept good from one source while another source is unavailable', async () => {
    const f = await fixture(['good', 'unavailable']);
    await expect(f.client.check(f.credential)).rejects.toThrow();
  });
  it('returns unknown when every approved store has no record', async () => {
    const f = await fixture(['unknown', 'unknown']);
    await expect(f.client.check(f.credential)).resolves.toMatchObject({ status: 'unknown' });
  });
  it.each([0, 17])('rejects an unbounded or empty approved source set (%s)', async count => {
    const f = await fixture(Array.from({length: count}, () => 'unknown'));
    await expect(f.client.check(f.credential)).rejects.toThrow(/sources/i);
    expect(f.observed.size).toBe(0);
  });

});
