import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  createSealer,
  isSealRecord,
  isInboxEntry,
  WrongPassphraseError,
  encodeRecoveryKey,
  decodeRecoveryKey,
  randomBytes,
} from '../src/index.js';

const USER = 'usr_1';
const PASS = 'a long enough passphrase';
const sealer = createSealer({ app: 'testapp' });

test('seal, unlock and open secrets', async () => {
  const { dek, seal, recoveryKey } = await sealer.createSeal(PASS, USER);
  assert.ok(isSealRecord(seal));
  assert.match(recoveryKey, /^[A-Z0-9]{4}(-[A-Z0-9]{1,4})+$/);

  const blob = await sealer.sealSecrets(dek, { GITHUB_TOKEN: 'ghp_x', N: 5 }, USER);
  assert.ok(!JSON.stringify(blob).includes('ghp_x'));

  const again = await sealer.unlockSeal(seal, PASS, USER);
  assert.deepEqual(await sealer.unsealSecrets(again, blob, USER), { GITHUB_TOKEN: 'ghp_x', N: '5' });
});

test('wrong passphrase, wrong user and wrong app all fail', async () => {
  const { dek, seal } = await sealer.createSeal(PASS, USER);
  await assert.rejects(sealer.unlockSeal(seal, 'not the passphrase', USER), WrongPassphraseError);
  await assert.rejects(sealer.unlockSeal(seal, PASS, 'usr_2'), WrongPassphraseError);
  const other = createSealer({ app: 'otherapp' });
  await assert.rejects(other.unlockSeal(seal, PASS, USER), WrongPassphraseError);

  const blob = await sealer.sealSecrets(dek, { A: '1' }, USER);
  await assert.rejects(sealer.unsealSecrets(dek, blob, 'usr_2'));
  await assert.rejects(sealer.unsealSecrets(dek, blob, USER, 'another_field'));
});

test('recovery key unlocks; rewrap keeps ciphertext and recovery valid', async () => {
  const { dek, seal, recoveryKey } = await sealer.createSeal(PASS, USER);
  const blob = await sealer.sealSecrets(dek, { K: 'v' }, USER);

  const recovered = await sealer.unlockSealWithRecovery(seal, recoveryKey.toLowerCase(), USER);
  assert.deepEqual(await sealer.unsealSecrets(recovered, blob, USER), { K: 'v' });

  const next = await sealer.rewrapSeal(dek, seal, 'a brand new passphrase', USER);
  await assert.rejects(sealer.unlockSeal(next, PASS, USER), WrongPassphraseError);
  const dek2 = await sealer.unlockSeal(next, 'a brand new passphrase', USER);
  assert.deepEqual(await sealer.unsealSecrets(dek2, blob, USER), { K: 'v' });
  await sealer.unlockSealWithRecovery(next, recoveryKey, USER);
  assert.equal(next.inbox_public_key, seal.inbox_public_key);
});

test('short passphrases are refused', async () => {
  await assert.rejects(sealer.createSeal('short', USER), /at least 10/);
});

test('server seals to the inbox; only the unlocked user opens it', async () => {
  const { dek, seal } = await sealer.createSeal(PASS, USER);
  const entry = await sealer.sealToInbox(seal.inbox_public_key, { OAUTH: 'tok' }, USER);
  assert.ok(isInboxEntry(entry));
  // A tampered entry is left in place, not merged and not consumed.
  const forged = await sealer.sealToInbox(seal.inbox_public_key, { OAUTH: 'evil' }, 'usr_2');
  const { patch, consumed } = await sealer.openInbox(dek, seal, [entry, { ...forged, id: 'x' }], USER);
  assert.deepEqual(patch, { OAUTH: 'tok' });
  assert.deepEqual(consumed, [entry.id]);
});

test('verifyDataKey tells the right key from a random one', async () => {
  const { dek, seal } = await sealer.createSeal(PASS, USER);
  assert.equal(await sealer.verifyDataKey(dek, seal, USER), true);
  assert.equal(await sealer.verifyDataKey(randomBytes(32), seal, USER), false);
  assert.equal(await sealer.verifyDataKey(randomBytes(16), seal, USER), false);
});

test('recovery key text round-trips', () => {
  const raw = randomBytes(32);
  assert.deepEqual(decodeRecoveryKey(encodeRecoveryKey(raw)), raw);
  assert.throws(() => decodeRecoveryKey('ABCD'), /invalid recovery key/);
});

test('createSealer validates names', () => {
  assert.throws(() => createSealer({}), /app/);
  assert.throws(() => createSealer({ app: 'Bad App' }), /app/);
  assert.throws(() => createSealer({ app: 'ok', scope: 'no spaces' }), /scope/);
});

test('opens a seal made by b1dz.com (#61): byte-compatible as app b1dz', async () => {
  const v = JSON.parse(readFileSync(new URL('./fixtures/b1dz-v2.json', import.meta.url), 'utf8'));
  const b1dz = createSealer({ app: v.app, scope: v.scope });
  const dek = await b1dz.unlockSeal(v.seal, v.passphrase, v.userId);
  assert.deepEqual(await b1dz.unsealSecrets(dek, v.payload_secret, v.userId), {
    EXCHANGE_SECRET: 's3cret',
    API_KEY: 'k-123',
  });
  const viaRecovery = await b1dz.unlockSealWithRecovery(v.seal, v.recoveryKey, v.userId);
  assert.deepEqual(viaRecovery, dek);
  const { patch } = await b1dz.openInbox(dek, v.seal, v.inbox, v.userId);
  assert.deepEqual(patch, { OAUTH_TOKEN: 'tok-xyz' });
});
