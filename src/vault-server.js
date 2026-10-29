import { base64ToBytes, isSealRecord, wipe } from './seal.js';
import { parseTtl, UNLOCK_DEFAULT_TTL_SECONDS } from './unlock-store.js';

/**
 * The server half of the key vault (the browser half is ./vault-ui.js).
 *
 * The server stores the sealed record and nothing that opens it. On unlock the
 * browser sends the derived data key (never the passphrase); it is checked
 * against the record, handed to your onUnlock hook (derive what you need, put it
 * in an UnlockStore) and wiped.
 *
 * Framework-agnostic handlers: each takes (userId, body) and returns
 * { status, body }. mountVaultRoutes() wires them into Hono (or anything with
 * app.get/post/put and c.req.json/c.json).
 */

export class VaultHttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const VAULT_SERVER_MESSAGES = {
  sealRequired: 'A sealed vault record is required.',
  exists: 'You already have a key vault.',
  missing: 'Set up your key vault first.',
  rewrapFields: 'seal and dek are required',
  rewrapWrong: 'That does not open your vault.',
  wrong: 'That passphrase does not open your vault.',
  ttl: 'Choose how long to stay unlocked, like 8h or 7d (7 days at most).',
};

export function vaultTtlSeconds(value) {
  if (value === undefined || value === null || value === '') return UNLOCK_DEFAULT_TTL_SECONDS;
  return parseTtl(String(value));
}

/**
 * @param {object} o
 * @param {ReturnType<import('./seal.js').createSealer>} o.sealer
 * @param {{ get(userId): Promise<object|null>, create(userId, seal): Promise<boolean>, replace(userId, seal): Promise<void> }} o.store
 *        create returns false when the user already has one.
 * @param {(userId, dek: Uint8Array, ttlSeconds: number) => Promise<object>} o.onUnlock
 *        dek is wiped after this returns; copy what you derive. Its result is merged into the reply.
 * @param {(userId) => Promise<void>|void} [o.onLock]
 * @param {(userId) => {unlocked:boolean, expiresAt:any}} [o.status]
 * @param {(userId) => Promise<object>} [o.view] extra fields for GET
 * @param {(userId, seal) => Promise<void>|void} [o.onCreate]
 * @param {object} [o.messages]
 */
export function createVaultHandlers({
  sealer,
  store,
  onUnlock,
  onLock,
  status,
  view,
  onCreate,
  messages = {},
} = {}) {
  if (!sealer || !store || !onUnlock) {
    throw new Error('createVaultHandlers: sealer, store and onUnlock are required');
  }
  const m = { ...VAULT_SERVER_MESSAGES, ...messages };
  const fail = (s, error, code) => ({ status: s, body: code ? { error, code } : { error } });

  return {
    async get(userId) {
      const seal = await store.get(String(userId));
      const st = status ? status(String(userId)) : {};
      const extra = view ? await view(String(userId)) : {};
      return {
        status: 200,
        body: { ...extra, exists: Boolean(seal), unlocked: Boolean(st?.unlocked), expiresAt: st?.expiresAt ?? null, seal: seal ?? null },
      };
    },

    async create(userId, body = {}) {
      if (!isSealRecord(body.seal)) return fail(400, m.sealRequired);
      const made = await store.create(String(userId), body.seal);
      if (!made) return fail(409, m.exists);
      await onCreate?.(String(userId), body.seal);
      return { status: 201, body: { exists: true } };
    },

    /** A new passphrase: the same data key wrapped again; both records must open with it. */
    async replace(userId, body = {}) {
      const current = await store.get(String(userId));
      if (!current) return fail(404, m.missing, 'vault_missing');
      if (!isSealRecord(body.seal) || typeof body.dek !== 'string') return fail(400, m.rewrapFields);
      const dek = base64ToBytes(body.dek);
      try {
        const ok =
          dek.length === 32 &&
          (await sealer.verifyDataKey(dek, current, String(userId))) &&
          (await sealer.verifyDataKey(dek, body.seal, String(userId)));
        if (!ok) return fail(403, m.rewrapWrong);
      } finally {
        wipe(dek);
      }
      await store.replace(String(userId), body.seal);
      return { status: 200, body: { exists: true } };
    },

    async unlock(userId, body = {}) {
      const seal = await store.get(String(userId));
      if (!seal) return fail(404, m.missing, 'vault_missing');
      let ttl;
      try {
        ttl = vaultTtlSeconds(body.ttl);
      } catch {
        return fail(400, m.ttl);
      }
      const dek = base64ToBytes(String(body.dek || ''));
      try {
        if (dek.length !== 32 || !(await sealer.verifyDataKey(dek, seal, String(userId)))) {
          return fail(403, m.wrong);
        }
        const extra = (await onUnlock(String(userId), dek, ttl)) ?? {};
        return { status: 200, body: { unlocked: true, ...extra } };
      } finally {
        wipe(dek);
      }
    },

    async lock(userId) {
      await onLock?.(String(userId));
      return { status: 200, body: { unlocked: false, expiresAt: null } };
    },
  };
}

/**
 * Wire the handlers into Hono-style routes:
 *   GET/POST/PUT {base}, POST {base}/unlock, POST {base}/lock
 *
 * @param {object} app            has get/post/put(path, handler)
 * @param {object} o
 * @param {ReturnType<typeof createVaultHandlers>} o.handlers
 * @param {(c) => string|Promise<string>} o.userId  return the signed-in user's id, or throw/return a Response
 * @param {string} [o.base='/my/vault']
 */
export function mountVaultRoutes(app, { handlers, userId, base = '/my/vault' }) {
  const wrap = (fn, { readBody = true } = {}) => async (c) => {
    const who = await userId(c);
    if (who && typeof who === 'object' && 'status' in who && typeof who.headers === 'object') return who;
    const body = readBody ? await c.req.json().catch(() => ({})) : {};
    const out = await fn(who, body);
    c.header?.('cache-control', 'no-store');
    return c.json(out.body, out.status);
  };
  app.get(base, wrap(handlers.get, { readBody: false }));
  app.post(base, wrap(handlers.create));
  app.put(base, wrap(handlers.replace));
  app.post(`${base}/unlock`, wrap(handlers.unlock));
  app.post(`${base}/lock`, wrap(handlers.lock, { readBody: false }));
  return app;
}
