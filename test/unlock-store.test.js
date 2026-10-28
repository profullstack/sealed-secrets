import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  UnlockStore,
  parseTtl,
  clampUnlockTtlSeconds,
  UNLOCK_DEFAULT_TTL_SECONDS,
  UNLOCK_MAX_TTL_SECONDS,
} from '../src/index.js';

test('unlock keeps a copy, expires, and zeroes the key', () => {
  let now = 1_000_000;
  const store = new UnlockStore({ now: () => now, useTimers: false });
  const events = [];
  store.onChange((u, unlocked) => events.push([u, unlocked]));

  const key = new Uint8Array(32).fill(7);
  store.unlock('u1', key, 120);
  key.fill(0);
  const held = store.get('u1');
  assert.equal(held[0], 7);
  assert.equal(store.status('u1').unlocked, true);

  now += 121_000;
  assert.equal(store.get('u1'), null);
  assert.equal(held[0], 0, 'expired key buffer is wiped');
  assert.deepEqual(events, [
    ['u1', true],
    ['u1', false],
  ]);
});

test('lock, lockAll and size', () => {
  const store = new UnlockStore({ useTimers: false });
  store.unlock('a', new Uint8Array(32));
  store.unlock('b', new Uint8Array(32));
  assert.equal(store.size, 2);
  store.lock('a');
  assert.equal(store.get('a'), null);
  store.lockAll();
  assert.equal(store.size, 0);
  assert.throws(() => store.unlock('c', new Uint8Array(16)), /32 bytes/);
});

test('ttl parsing and clamping', () => {
  assert.equal(parseTtl(undefined), UNLOCK_DEFAULT_TTL_SECONDS);
  assert.equal(parseTtl('30m'), 1800);
  assert.equal(parseTtl('8h'), 8 * 3600);
  assert.equal(parseTtl('30d'), UNLOCK_MAX_TTL_SECONDS);
  assert.equal(clampUnlockTtlSeconds(1), 60);
  assert.throws(() => parseTtl('soon'), /bad ttl/);
});
