import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSealer, UnlockStore } from '../src/index.js';
import { createVaultClient, describeUnlock, VAULT_MESSAGES } from '../src/vault-ui.js';
import { createVaultHandlers, mountVaultRoutes } from '../src/vault-server.js';
import { keyVaultCardHtml, vaultStatusText } from '../src/vault-card.js';

const APP = 'testapp';
const SCOPE = 'playlists';
const USER = 'usr_42';
const PASS = 'a long enough passphrase';

/** An in-memory server: the real handlers behind a fake fetch, routed like mountVaultRoutes. */
function harness() {
  const seals = new Map();
  const unlocks = new UnlockStore();
  const sealer = createSealer({ app: APP, scope: SCOPE });
  const handlers = createVaultHandlers({
    sealer,
    store: {
      get: async (id) => seals.get(id) ?? null,
      create: async (id, seal) => (seals.has(id) ? false : (seals.set(id, seal), true)),
      replace: async (id, seal) => void seals.set(id, seal),
    },
    onUnlock: async (id, dek, ttl) => unlocks.unlock(id, new Uint8Array(dek), ttl),
    onLock: (id) => unlocks.lock(id),
    status: (id) => unlocks.status(id),
  });
  const routes = new Map();
  const app = {};
  for (const verb of ['get', 'post', 'put']) {
    app[verb] = (path, h) => routes.set(`${verb.toUpperCase()} ${path}`, h);
  }
  mountVaultRoutes(app, { handlers, userId: () => USER });
  const fetch = async (url, init = {}) => {
    const h = routes.get(`${init.method || 'GET'} ${url}`);
    if (!h) return new Response('{}', { status: 404 });
    let out;
    const c = {
      req: { json: async () => JSON.parse(init.body || '{}') },
      header() {},
      json: (body, status = 200) => (out = new Response(JSON.stringify(body), { status })),
    };
    await h(c);
    return out;
  };
  return { seals, unlocks, handlers, fetch };
}

test('create -> unlock -> lock -> unlock -> change passphrase, end to end', async () => {
  const h = harness();
  const client = createVaultClient({ app: APP, scope: SCOPE, userId: USER, fetch: h.fetch });

  const made = await client.create({ passphrase: PASS, confirm: PASS, ttl: '1h' });
  assert.match(made.recoveryKey, /\S{20,}/);
  assert.equal(made.unlock.unlocked, true);
  assert.equal(h.unlocks.status(USER).unlocked, true);
  assert.equal(describeUnlock(made.unlock), VAULT_MESSAGES.unlocked);

  await client.lock();
  assert.equal(h.unlocks.status(USER).unlocked, false);

  const again = await client.unlock({ passphrase: PASS, ttl: '8h' });
  assert.equal(again.unlocked, true);

  await client.lock();
  const viaRecovery = await client.unlock({ passphrase: made.recoveryKey, recovery: true });
  assert.equal(viaRecovery.unlocked, true);

  await client.changePassphrase({ passphrase: PASS, newPassphrase: 'another long passphrase' });
  await client.lock();
  await assert.rejects(client.unlock({ passphrase: PASS }), { message: VAULT_MESSAGES.wrong });
  assert.equal((await client.unlock({ passphrase: 'another long passphrase' })).unlocked, true);

  const st = await client.status();
  assert.equal(st.exists, true);
  assert.equal(st.unlocked, true);
});

test('client refuses short or mismatched passphrases before any crypto or request', async () => {
  let calls = 0;
  const client = createVaultClient({ app: APP, userId: USER, fetch: async () => (calls++, new Response('{}')) });
  await assert.rejects(client.create({ passphrase: 'short', confirm: 'short' }), { message: VAULT_MESSAGES.tooShort });
  await assert.rejects(client.create({ passphrase: PASS, confirm: `${PASS}!` }), { message: VAULT_MESSAGES.mismatch });
  assert.equal(calls, 0);
});

test('server errors surface as the server sentence, with status and code', async () => {
  const h = harness();
  const client = createVaultClient({ app: APP, scope: SCOPE, userId: USER, fetch: h.fetch });
  await assert.rejects(client.unlock({ passphrase: PASS }), (err) => err.status === 404 && err.code === 'vault_missing');
  await client.create({ passphrase: PASS, confirm: PASS });
  await assert.rejects(client.create({ passphrase: PASS, confirm: PASS }), { status: 409 });
});

test('handlers validate input', async () => {
  const h = harness();
  assert.equal((await h.handlers.create(USER, { seal: { v: 1 } })).status, 400);
  const sealer = createSealer({ app: APP, scope: SCOPE });
  const { seal, dek } = await sealer.createSeal(PASS, USER);
  assert.equal((await h.handlers.create(USER, { seal })).status, 201);
  assert.equal((await h.handlers.unlock(USER, { dek: 'AAAA' })).status, 403);
  assert.equal((await h.handlers.unlock(USER, { dek: Buffer.from(dek).toString('base64'), ttl: 'forever' })).status, 400);
  // A data key for a different user's seal does not open this one.
  const other = await sealer.createSeal(PASS, 'someone_else');
  assert.equal((await h.handlers.unlock(USER, { dek: Buffer.from(other.dek).toString('base64') })).status, 403);
  assert.equal((await h.handlers.replace(USER, { seal: other.seal, dek: Buffer.from(dek).toString('base64') })).status, 403);
});

test('card markup: create form when there is no vault, escaped copy and attributes', () => {
  const html = keyVaultCardHtml({
    app: APP,
    scope: SCOPE,
    userId: 'u"1',
    vault: { exists: false },
    intro: ['Your <lists> are sealed.'],
    scriptSrc: '/vendor-vault.js?v=1',
  });
  assert.match(html, /data-key-vault/);
  assert.match(html, /data-app="testapp"/);
  assert.match(html, /data-scope="playlists"/);
  assert.match(html, /data-user="u&quot;1"/);
  assert.match(html, /<form[^>]*data-vault-form/);
  assert.match(html, /name="confirm"/);
  assert.match(html, /type="submit"[^>]*data-vault-create/);
  assert.match(html, /Your &lt;lists&gt; are sealed\./);
  assert.match(html, /<script src="\/vendor-vault\.js\?v=1" defer><\/script>/);
  assert.doesNotMatch(html, /data-vault-unlock|data-vault-lock/);
});

test('card markup: unlock form with recovery and change passphrase; lock button when unlocked', () => {
  const locked = keyVaultCardHtml({ app: APP, userId: 'u', vault: { exists: true, unlocked: false, legacy: 2 } });
  assert.match(locked, /type="submit"[^>]*data-vault-unlock/);
  assert.match(locked, /name="recovery"/);
  assert.match(locked, /type="button" data-vault-rewrap/);
  assert.match(locked, /Locked\. 2 older item\(s\) will be re-sealed/);
  const open = keyVaultCardHtml({ app: APP, userId: 'u', vault: { exists: true, unlocked: true, expiresAt: 0 } });
  assert.match(open, /data-vault-lock/);
  assert.doesNotMatch(open, /data-vault-form/);
  assert.equal(vaultStatusText({}), 'No vault yet.');
});
