/**
 * User-held sealing for the keys and secrets users give an app.
 *
 * Isomorphic: WebCrypto only (browser, Node >= 20, Bun, Deno, Workers). No
 * server key can open anything sealed here; every key comes from the user.
 *
 *   passphrase --PBKDF2-SHA256 600k, 16-byte salt--> ikm
 *   ikm --HKDF-SHA256 (info "<app>/kek/v2")--> KEK (AES-256-GCM)
 *   KEK wraps a random 32-byte data key (DEK)          -> seal.wrapped_dek
 *   recovery key --HKDF--> RKEK wraps the same DEK      -> seal.recovery_wrapped_dek
 *   DEK seals the secret map (AAD: app, scope, user, field)
 *   DEK seals a fixed string                            -> seal.key_check
 *
 * The DEK is what a client hands a worker to unlock a session (see
 * UnlockStore). The passphrase never leaves the client.
 *
 * Inbox: each seal also carries an ECDH P-256 key pair. The public half is
 * stored in the clear; the private half is sealed under the DEK. A server (an
 * OAuth callback, say) seals new secrets to the public key with sealToInbox
 * and can never read them back; an unlocked client opens them with openInbox.
 *
 * Extracted from b1dz.com (#61, 2026-10-28). With app "b1dz" and scope
 * "user_settings" the output is byte-compatible with b1dz's seal_version 2.
 */

export const SEAL_VERSION = 2;
export const PBKDF2_ITERATIONS = 600_000;
export const MIN_PBKDF2_ITERATIONS = 600_000;
export const MIN_PASSPHRASE_LENGTH = 10;
export const SECRET_FIELD = 'payload_secret';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const INBOX_PRIVATE_FIELD = 'inbox_private_key';
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

const enc = new TextEncoder();
const dec = new TextDecoder();

function subtle() {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error('WebCrypto (crypto.subtle) is not available');
  return c.subtle;
}

function buf(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

export function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Best-effort wipe of a key buffer once it is no longer needed. */
export function wipe(bytes) {
  if (bytes) bytes.fill(0);
}

export class WrongPassphraseError extends Error {
  constructor(msg = 'wrong passphrase') {
    super(msg);
    this.name = 'WrongPassphraseError';
  }
}

async function gcmEncrypt(key, plaintext, ad) {
  const iv = randomBytes(IV_BYTES);
  const sealed = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv, additionalData: buf(ad), tagLength: TAG_BYTES * 8 },
      key,
      buf(plaintext),
    ),
  );
  return {
    ciphertext: bytesToBase64(sealed.slice(0, sealed.length - TAG_BYTES)),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(sealed.slice(sealed.length - TAG_BYTES)),
  };
}

async function gcmDecrypt(key, blob, ad) {
  const ct = base64ToBytes(blob.ciphertext);
  const tag = base64ToBytes(blob.tag);
  const joined = new Uint8Array(ct.length + tag.length);
  joined.set(ct, 0);
  joined.set(tag, ct.length);
  const out = await subtle().decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(blob.iv),
      additionalData: buf(ad),
      tagLength: TAG_BYTES * 8,
    },
    key,
    buf(joined),
  );
  return new Uint8Array(out);
}

async function aesKey(raw) {
  if (raw.length !== 32) throw new Error(`data key must be 32 bytes (got ${raw.length})`);
  return subtle().importKey('raw', buf(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function hkdfAesKey(ikm, salt, info) {
  const base = await subtle().importKey('raw', buf(ikm), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: buf(salt), info: buf(enc.encode(info)) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

const B32 = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'; // Crockford-ish, no I L O U

/** 32 random bytes as grouped base32 text, e.g. ABCD-EFGH-... (52 chars). */
export function encodeRecoveryKey(raw) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of raw) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g).join('-');
}

export function decodeRecoveryKey(text) {
  const clean = String(text)
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('invalid recovery key');
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length < 32) throw new Error('invalid recovery key');
  return new Uint8Array(out.slice(0, 32));
}

/** Normalise a decrypted secret map to string values only. */
export function toSecretMap(parsed) {
  const result = {};
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return result;
  for (const [k, v] of Object.entries(parsed)) {
    if (typeof v === 'string') result[k] = v;
    else if (typeof v === 'number' || typeof v === 'boolean') result[k] = String(v);
  }
  return result;
}

export function isCipherBlob(v) {
  if (!v || typeof v !== 'object') return false;
  return (
    typeof v.ciphertext === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.tag === 'string' &&
    v.ciphertext.length > 0 &&
    v.iv.length > 0 &&
    v.tag.length > 0
  );
}

export function isSealRecord(v) {
  if (!v || typeof v !== 'object') return false;
  const kdf = v.kdf;
  return (
    v.v === SEAL_VERSION &&
    !!kdf &&
    kdf.alg === 'PBKDF2-SHA256' &&
    typeof kdf.iterations === 'number' &&
    kdf.iterations >= MIN_PBKDF2_ITERATIONS &&
    typeof kdf.salt === 'string' &&
    isCipherBlob(v.wrapped_dek) &&
    isCipherBlob(v.key_check) &&
    isCipherBlob(v.inbox_private_sealed) &&
    (v.recovery_wrapped_dek === null || isCipherBlob(v.recovery_wrapped_dek)) &&
    typeof v.inbox_public_key === 'string'
  );
}

export function isInboxEntry(v) {
  if (!v || typeof v !== 'object') return false;
  return (
    typeof v.id === 'string' &&
    typeof v.epk === 'string' &&
    typeof v.created_at === 'string' &&
    isCipherBlob(v.blob)
  );
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
}

/**
 * A sealer for one app and one kind of record.
 *
 * `app` separates one product's ciphertext from another's: a seal made for
 * "b1dz" cannot be opened as "outreachgraph" even with the right passphrase.
 * `scope` names the record the secrets belong to (default "user_settings").
 */
export function createSealer({ app, scope = 'user_settings' } = {}) {
  if (!NAME.test(app ?? '')) throw new Error('createSealer: app must be a short lowercase name');
  if (!NAME.test(scope)) throw new Error('createSealer: scope must be a short lowercase name');

  const keyCheckText = `${app}-key-check-v2`;

  function aad(userId, field) {
    if (!userId) throw new Error('userId required for AAD');
    return enc.encode(`${app}:${scope}:${userId}:${field}`);
  }

  /** Passphrase -> KEK. PBKDF2-SHA256 (>= 600k) then HKDF, matching OpenCreds. */
  async function deriveKek(passphrase, kdf) {
    if (kdf.alg !== 'PBKDF2-SHA256') throw new Error(`unsupported kdf ${kdf.alg}`);
    if (kdf.iterations < MIN_PBKDF2_ITERATIONS) throw new Error('kdf iterations below policy');
    const salt = base64ToBytes(kdf.salt);
    const pw = await subtle().importKey(
      'raw',
      buf(enc.encode(passphrase.normalize('NFKC'))),
      'PBKDF2',
      false,
      ['deriveBits'],
    );
    const bits = new Uint8Array(
      await subtle().deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: buf(salt), iterations: kdf.iterations },
        pw,
        256,
      ),
    );
    try {
      return await hkdfAesKey(bits, salt, `${app}/kek/v2`);
    } finally {
      wipe(bits);
    }
  }

  /** Recovery key (high entropy, shown once) -> KEK. No stretching needed. */
  async function deriveRecoveryKek(recoveryKey) {
    const raw = decodeRecoveryKey(recoveryKey);
    try {
      return await hkdfAesKey(raw, enc.encode(`${app}/recovery`), `${app}/recovery-kek/v2`);
    } finally {
      wipe(raw);
    }
  }

  async function sealJson(dek, obj, userId, field = SECRET_FIELD) {
    return gcmEncrypt(await aesKey(dek), enc.encode(JSON.stringify(obj)), aad(userId, field));
  }

  async function unsealJson(dek, blob, userId, field = SECRET_FIELD) {
    const out = await gcmDecrypt(await aesKey(dek), blob, aad(userId, field));
    try {
      return JSON.parse(dec.decode(out));
    } finally {
      wipe(out);
    }
  }

  async function sealSecrets(dek, secrets, userId, field = SECRET_FIELD) {
    return sealJson(dek, toSecretMap(secrets), userId, field);
  }

  async function unsealSecrets(dek, blob, userId, field = SECRET_FIELD) {
    return toSecretMap(await unsealJson(dek, blob, userId, field));
  }

  async function buildSeal(dek, passphrase, recoveryKey, userId, iterations, keepInbox, keepRecovery) {
    const kdf = { alg: 'PBKDF2-SHA256', iterations, salt: bytesToBase64(randomBytes(16)) };
    const kek = await deriveKek(passphrase, kdf);
    const wrapped_dek = await gcmEncrypt(kek, dek, aad(userId, 'dek:passphrase'));
    let recovery_wrapped_dek = keepRecovery ?? null;
    if (recoveryKey) {
      const rkek = await deriveRecoveryKek(recoveryKey);
      recovery_wrapped_dek = await gcmEncrypt(rkek, dek, aad(userId, 'dek:recovery'));
    }
    const key_check = await sealJson(dek, keyCheckText, userId, 'key_check');
    let inbox = keepInbox;
    if (!inbox) {
      const pair = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveBits',
      ]);
      const pub = new Uint8Array(await subtle().exportKey('raw', pair.publicKey));
      const priv = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
      const inbox_private_sealed = await gcmEncrypt(
        await aesKey(dek),
        priv,
        aad(userId, INBOX_PRIVATE_FIELD),
      );
      wipe(priv);
      inbox = { inbox_public_key: bytesToBase64(pub), inbox_private_sealed };
    }
    return { v: SEAL_VERSION, kdf, wrapped_dek, recovery_wrapped_dek, key_check, ...inbox };
  }

  /** First-time setup: new DEK, wrapped under the passphrase and a recovery key. */
  async function createSeal(passphrase, userId, iterations = PBKDF2_ITERATIONS) {
    requirePassphrase(passphrase);
    const dek = randomBytes(32);
    const recoveryRaw = randomBytes(32);
    const recoveryKey = encodeRecoveryKey(recoveryRaw);
    wipe(recoveryRaw);
    const seal = await buildSeal(dek, passphrase, recoveryKey, userId, iterations);
    return { dek, seal, recoveryKey };
  }

  /** True when `dek` is this user's data key (for a worker's unlock endpoint). */
  async function verifyDataKey(dek, seal, userId) {
    if (!dek || dek.length !== 32) return false;
    try {
      return (await unsealJson(dek, seal.key_check, userId, 'key_check')) === keyCheckText;
    } catch {
      return false;
    }
  }

  async function assertKeyCheck(dek, seal, userId) {
    if (!(await verifyDataKey(dek, seal, userId))) throw new WrongPassphraseError('key check failed');
  }

  /** Change passphrase: same DEK (so ciphertext stays valid), new salt and wrap. */
  async function rewrapSeal(dek, seal, newPassphrase, userId) {
    requirePassphrase(newPassphrase);
    await assertKeyCheck(dek, seal, userId);
    return buildSeal(
      dek,
      newPassphrase,
      null,
      userId,
      Math.max(seal.kdf.iterations, PBKDF2_ITERATIONS),
      { inbox_public_key: seal.inbox_public_key, inbox_private_sealed: seal.inbox_private_sealed },
      seal.recovery_wrapped_dek,
    );
  }

  /** Passphrase -> DEK. Throws WrongPassphraseError on a bad passphrase. */
  async function unlockSeal(seal, passphrase, userId) {
    const kek = await deriveKek(passphrase, seal.kdf);
    let dek;
    try {
      dek = await gcmDecrypt(kek, seal.wrapped_dek, aad(userId, 'dek:passphrase'));
    } catch {
      throw new WrongPassphraseError();
    }
    await assertKeyCheck(dek, seal, userId);
    return dek;
  }

  async function unlockSealWithRecovery(seal, recoveryKey, userId) {
    if (!seal.recovery_wrapped_dek) throw new WrongPassphraseError('no recovery key on file');
    let dek;
    try {
      const rkek = await deriveRecoveryKek(recoveryKey);
      dek = await gcmDecrypt(rkek, seal.recovery_wrapped_dek, aad(userId, 'dek:recovery'));
    } catch {
      throw new WrongPassphraseError('wrong recovery key');
    }
    await assertKeyCheck(dek, seal, userId);
    return dek;
  }

  async function inboxKey(shared, epk, userId) {
    return hkdfAesKey(shared, epk, `${app}/inbox/v2/${userId}`);
  }

  /** Server side: seal a patch to the user's inbox public key. It can never read it back. */
  async function sealToInbox(publicKeyB64, patch, userId) {
    const recipient = await subtle().importKey(
      'raw',
      buf(base64ToBytes(publicKeyB64)),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const eph = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const shared = new Uint8Array(
      await subtle().deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256),
    );
    const epk = new Uint8Array(await subtle().exportKey('raw', eph.publicKey));
    try {
      const key = await inboxKey(shared, epk, userId);
      const blob = await gcmEncrypt(
        key,
        enc.encode(JSON.stringify(toSecretMap(patch))),
        aad(userId, 'inbox'),
      );
      return {
        id: bytesToBase64(randomBytes(9)).replace(/[+/=]/g, ''),
        epk: bytesToBase64(epk),
        blob,
        created_at: new Date().toISOString(),
      };
    } finally {
      wipe(shared);
    }
  }

  /** Unlocked client: open queued inbox entries. Returns the merged patch and the ids consumed. */
  async function openInbox(dek, seal, entries, userId) {
    const patch = {};
    const consumed = [];
    if (!entries?.length) return { patch, consumed };
    const pkcs8 = await gcmDecrypt(
      await aesKey(dek),
      seal.inbox_private_sealed,
      aad(userId, INBOX_PRIVATE_FIELD),
    );
    let priv;
    try {
      priv = await subtle().importKey(
        'pkcs8',
        buf(pkcs8),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits'],
      );
    } finally {
      wipe(pkcs8);
    }
    const sorted = [...entries].sort((a, b) => a.created_at.localeCompare(b.created_at));
    for (const e of sorted) {
      try {
        const epk = base64ToBytes(e.epk);
        const pub = await subtle().importKey(
          'raw',
          buf(epk),
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          [],
        );
        const shared = new Uint8Array(
          await subtle().deriveBits({ name: 'ECDH', public: pub }, priv, 256),
        );
        const key = await inboxKey(shared, epk, userId);
        wipe(shared);
        const out = await gcmDecrypt(key, e.blob, aad(userId, 'inbox'));
        Object.assign(patch, toSecretMap(JSON.parse(dec.decode(out))));
        wipe(out);
        consumed.push(e.id);
      } catch {
        // Leave an unreadable entry in place; it is reported, not dropped.
      }
    }
    return { patch, consumed };
  }

  return Object.freeze({
    app,
    scope,
    createSeal,
    unlockSeal,
    unlockSealWithRecovery,
    rewrapSeal,
    verifyDataKey,
    sealJson,
    unsealJson,
    sealSecrets,
    unsealSecrets,
    sealToInbox,
    openInbox,
  });
}
