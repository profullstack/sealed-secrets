/**
 * In-memory unlock sessions: userId -> data key, with a TTL.
 *
 * The only place a worker should hold a user's data key. Never write it to a
 * database, Redis, disk, logs, error reports or process.env. A restart empties
 * the store, so every sealed user is locked until they unlock again. Lock and
 * expiry zero the key buffer.
 */

export const UNLOCK_DEFAULT_TTL_SECONDS = 8 * 3600;
export const UNLOCK_MAX_TTL_SECONDS = 7 * 24 * 3600;
export const UNLOCK_MIN_TTL_SECONDS = 60;

export function clampUnlockTtlSeconds(v) {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number.parseInt(v, 10) : NaN;
  if (!Number.isFinite(n)) return UNLOCK_DEFAULT_TTL_SECONDS;
  return Math.min(UNLOCK_MAX_TTL_SECONDS, Math.max(UNLOCK_MIN_TTL_SECONDS, Math.floor(n)));
}

/** "8h", "30m", "7d", "3600" -> seconds (clamped). */
export function parseTtl(text) {
  if (!text) return UNLOCK_DEFAULT_TTL_SECONDS;
  const m = /^(\d+)\s*([smhd]?)$/i.exec(String(text).trim());
  if (!m) throw new Error(`bad ttl "${text}" (use e.g. 30m, 8h, 7d)`);
  const mult = { '': 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2].toLowerCase()];
  return clampUnlockTtlSeconds(Number(m[1]) * mult);
}

export class UnlockStore {
  #sessions = new Map();
  #listeners = new Set();
  #now;
  #useTimers;

  constructor({ now = Date.now, useTimers = true } = {}) {
    this.#now = now;
    this.#useTimers = useTimers;
  }

  /** Called with (userId, unlocked) on unlock, lock and expiry. Returns an unsubscribe. */
  onChange(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  #emit(userId, unlocked) {
    for (const fn of this.#listeners) {
      try {
        fn(userId, unlocked);
      } catch {
        // listeners never break the store
      }
    }
  }

  /** Stores a COPY of the key; the caller should wipe its own buffer. */
  unlock(userId, key, ttlSeconds = UNLOCK_DEFAULT_TTL_SECONDS) {
    if (!userId) throw new Error('userId required');
    if (!key || key.length !== 32) throw new Error('data key must be 32 bytes');
    this.#drop(userId, false);
    const ttl = clampUnlockTtlSeconds(ttlSeconds);
    const expiresAt = this.#now() + ttl * 1000;
    const timer = this.#useTimers ? setTimeout(() => this.lock(userId), ttl * 1000) : null;
    timer?.unref?.();
    this.#sessions.set(userId, { key: new Uint8Array(key), expiresAt, timer });
    this.#emit(userId, true);
    return { unlocked: true, expiresAt: new Date(expiresAt).toISOString() };
  }

  /** The user's data key while unlocked, else null. Do not keep it past the current job. */
  get(userId) {
    const s = this.#sessions.get(userId);
    if (!s) return null;
    if (s.expiresAt <= this.#now()) {
      this.lock(userId);
      return null;
    }
    return s.key;
  }

  status(userId) {
    return this.get(userId)
      ? {
          unlocked: true,
          expiresAt: new Date(this.#sessions.get(userId).expiresAt).toISOString(),
        }
      : { unlocked: false, expiresAt: null };
  }

  lock(userId) {
    this.#drop(userId, true);
  }

  #drop(userId, notify) {
    const s = this.#sessions.get(userId);
    if (!s) return;
    if (s.timer) clearTimeout(s.timer);
    s.key.fill(0);
    this.#sessions.delete(userId);
    if (notify) this.#emit(userId, false);
  }

  lockAll() {
    for (const userId of [...this.#sessions.keys()]) this.lock(userId);
  }

  get size() {
    return this.#sessions.size;
  }
}
