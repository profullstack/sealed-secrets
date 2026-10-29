import { bytesToBase64, createSealer, MIN_PASSPHRASE_LENGTH, wipe } from './seal.js';

/**
 * The key vault, in the browser: create, unlock, lock and change passphrase.
 *
 * Every bit of cryptography happens here. The passphrase and the recovery key
 * never leave the page; the server gets the sealed record and, on unlock, only
 * the derived data key (see ./vault-server.js for the matching routes).
 *
 * Two layers, so the flows can be tested without a DOM:
 *   createVaultClient()  the flows (fetch + WebCrypto), returns plain results
 *   mountKeyVault()      binds a card drawn by keyVaultCardHtml() (./vault-card.js)
 *
 * Things learned the hard way on the watch sites (2026-10-29):
 *  - PBKDF2 at 600k runs twice on create; on a TV stick or an old phone that is
 *    many seconds of a page that looks dead. Say "Sealing..." first and let it paint.
 *  - The fields must be a <form> so Enter (and a TV remote's Go key) submits.
 *  - window.prompt() is suppressed in installed apps and some browsers, so the
 *    recovery key is shown on the page, with Copy, until the reader confirms.
 *  - Ship the bundle as an IIFE: two unwrapped bundles on one page collide on
 *    minified top-level names ("Identifier 'P' has already been declared").
 */

export const VAULT_MESSAGES = {
  sealing: 'Sealing... this takes a few seconds.',
  unlocking: 'Unlocking... this takes a few seconds.',
  changing: 'Changing your passphrase... this takes a few seconds.',
  locking: 'Locking...',
  tooShort: `Use a passphrase of ${MIN_PASSPHRASE_LENGTH} characters or more.`,
  mismatch: 'The two passphrases are different.',
  wrong: 'That passphrase does not open your vault.',
  unlocked: 'Unlocked.',
  locked: 'Locked. Anything sealed waits until you unlock again.',
  changed: 'Passphrase changed. Your recovery key still works.',
  failed: 'That did not work.',
  missing: 'Set up your key vault first.',
  noCrypto:
    'This browser cannot do the encryption the vault needs (WebCrypto). Try a current browser over https.',
  recoveryTitle: 'Your recovery key',
  recoveryHelp:
    'Save it now, in a password manager ideally. It is shown only this once and it is the only way back in if you forget your passphrase.',
  copy: 'Copy',
  copied: 'Copied.',
  saved: 'I have saved it',
};

/** Let the browser paint the progress text before the CPU-bound key derivation starts. */
const nextPaint = () =>
  new Promise((resolve) => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => setTimeout(resolve, 0));
    } else {
      setTimeout(resolve, 0);
    }
  });

/**
 * The flows, no DOM.
 *
 * @param {object} o
 * @param {string} o.app       must match the server's sealer app
 * @param {string} [o.scope]   must match the server's sealer scope
 * @param {string} o.userId
 * @param {string} [o.endpoint='/my/vault']
 * @param {typeof fetch} [o.fetch]
 * @param {object} [o.messages]
 */
export function createVaultClient({
  app,
  scope = 'user_settings',
  userId,
  endpoint = '/my/vault',
  fetch: fetchImpl = globalThis.fetch?.bind(globalThis),
  messages = {},
  sealer = null,
} = {}) {
  if (!userId) throw new Error('createVaultClient: userId is required');
  const m = { ...VAULT_MESSAGES, ...messages };
  const s = sealer ?? createSealer({ app, scope });
  const base = endpoint.replace(/\/+$/, '');

  const api = async (path, body, method = 'POST') => {
    const res = await fetchImpl(`${base}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(out.error || `${m.failed} (${res.status})`);
      err.status = res.status;
      err.code = out.code;
      throw err;
    }
    return out;
  };

  const sendUnlock = async (dek, ttl) => {
    try {
      return await api('/unlock', { dek: bytesToBase64(dek), ttl: ttl || '8h' });
    } finally {
      wipe(dek);
    }
  };

  const openDek = async (seal, passphrase, { recovery = false } = {}) => {
    if (!seal) throw Object.assign(new Error(m.missing), { status: 404, code: 'vault_missing' });
    try {
      return recovery
        ? await s.unlockSealWithRecovery(seal, String(passphrase).trim(), userId)
        : await s.unlockSeal(seal, passphrase, userId);
    } catch (err) {
      if (err?.name === 'WrongPassphraseError') throw new Error(m.wrong);
      throw err;
    }
  };

  const checkPassphrase = (passphrase) => {
    if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
      throw new Error(m.tooShort);
    }
  };

  return {
    messages: m,
    api,
    /** GET the status and the sealed record. */
    status: () => api('', null, 'GET'),
    /** Make the seal, store it, unlock. Returns { recoveryKey, unlock }. */
    async create({ passphrase, confirm, ttl }) {
      checkPassphrase(passphrase);
      if (confirm !== undefined && passphrase !== confirm) throw new Error(m.mismatch);
      const made = await s.createSeal(passphrase, userId);
      try {
        await api('', { seal: made.seal });
      } catch (err) {
        wipe(made.dek);
        throw err;
      }
      const unlock = await sendUnlock(made.dek, ttl);
      return { recoveryKey: made.recoveryKey, unlock };
    },
    async unlock({ passphrase, recovery = false, ttl }) {
      if (!passphrase) throw new Error(m.wrong);
      const { seal } = await api('', null, 'GET');
      const dek = await openDek(seal, passphrase, { recovery });
      return sendUnlock(dek, ttl);
    },
    lock: () => api('/lock'),
    async changePassphrase({ passphrase, recovery = false, newPassphrase }) {
      checkPassphrase(newPassphrase);
      const { seal } = await api('', null, 'GET');
      const dek = await openDek(seal, passphrase, { recovery });
      try {
        const next = await s.rewrapSeal(dek, seal, newPassphrase, userId);
        return await api('', { seal: next, dek: bytesToBase64(dek) }, 'PUT');
      } finally {
        wipe(dek);
      }
    },
  };
}

/** "Unlocked." plus anything the server's onUnlock hook reported. */
export function describeUnlock(out, m = VAULT_MESSAGES) {
  const moved = out?.migration?.migrated || 0;
  return moved ? `${m.unlocked} ${moved} older item(s) re-sealed with your vault.` : m.unlocked;
}

/**
 * Bind a key vault card (see keyVaultCardHtml for the markup contract).
 *
 * Reads data-app, data-scope, data-user and data-endpoint from `root` unless
 * passed. Returns { client, destroy }.
 */
export function mountKeyVault(root, options = {}) {
  if (!root) return null;
  const d = root.dataset || {};
  const client = createVaultClient({
    app: options.app ?? d.app,
    scope: options.scope ?? d.scope ?? 'user_settings',
    userId: options.userId ?? d.user,
    endpoint: options.endpoint ?? d.endpoint ?? '/my/vault',
    messages: options.messages,
    fetch: options.fetch,
  });
  const m = client.messages;
  const reload = options.reload ?? (() => location.reload());
  const reloadAfterMs = options.reloadAfterMs ?? 1200;
  const doc = root.ownerDocument;

  let status = root.querySelector('[data-vault-status]');
  if (!status) {
    status = doc.createElement('p');
    status.setAttribute('data-vault-status', '');
    status.setAttribute('aria-live', 'polite');
    root.prepend(status);
  }
  const say = (text, kind = 'notice') => {
    status.textContent = text;
    status.className = kind;
    status.dataset.state = kind;
  };
  const field = (name) => root.querySelector(`[name="${name}"]`);
  const value = (name) => field(name)?.value ?? '';
  const checked = (name) => Boolean(field(name)?.checked);

  if (!globalThis.crypto?.subtle) {
    say(m.noCrypto, 'error');
    for (const b of root.querySelectorAll('button')) b.disabled = true;
    return { client, destroy() {} };
  }

  let busy = false;
  const setBusy = (on) => {
    busy = on;
    root.setAttribute('aria-busy', on ? 'true' : 'false');
    for (const b of root.querySelectorAll('button, input, select')) b.disabled = on;
  };
  const run = (progress, fn) => async (event) => {
    event?.preventDefault?.();
    if (busy) return;
    setBusy(true);
    say(progress, 'working');
    await nextPaint();
    try {
      const done = await fn();
      if (done) {
        say(done, 'notice');
        setTimeout(reload, reloadAfterMs);
      }
    } catch (err) {
      say(err?.message || m.failed, 'error');
    } finally {
      setBusy(false);
    }
  };

  const showRecovery = (key) => {
    const panel = doc.createElement('div');
    panel.setAttribute('data-vault-recovery', '');
    panel.className = 'vault-recovery';
    const h = doc.createElement('strong');
    h.textContent = m.recoveryTitle;
    const help = doc.createElement('p');
    help.className = 'small';
    help.textContent = m.recoveryHelp;
    const code = doc.createElement('code');
    code.setAttribute('data-vault-recovery-key', '');
    code.textContent = key;
    code.style.userSelect = 'all';
    code.style.wordBreak = 'break-all';
    const copy = doc.createElement('button');
    copy.type = 'button';
    copy.textContent = m.copy;
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(key);
        copy.textContent = m.copied;
      } catch {
        const range = doc.createRange();
        range.selectNodeContents(code);
        const sel = doc.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
    const done = doc.createElement('button');
    done.type = 'button';
    done.setAttribute('data-vault-recovery-done', '');
    done.textContent = m.saved;
    done.addEventListener('click', () => reload());
    panel.append(h, help, code, doc.createTextNode(' '), copy, doc.createTextNode(' '), done);
    const form = root.querySelector('[data-vault-form]');
    if (form) form.replaceWith(panel);
    else root.append(panel);
  };

  const create = run(m.sealing, async () => {
    const { recoveryKey, unlock } = await client.create({
      passphrase: value('passphrase'),
      confirm: field('confirm') ? value('confirm') : undefined,
      ttl: value('ttl'),
    });
    say(`${describeUnlock(unlock, m)}`, 'notice');
    showRecovery(recoveryKey);
    return null; // stays on the page until the reader says they saved the key
  });
  const unlock = run(m.unlocking, async () =>
    describeUnlock(
      await client.unlock({
        passphrase: value('passphrase'),
        recovery: checked('recovery'),
        ttl: value('ttl'),
      }),
      m,
    ),
  );
  const lock = run(m.locking, async () => {
    await client.lock();
    return m.locked;
  });
  const rewrap = run(m.changing, async () => {
    await client.changePassphrase({
      passphrase: value('passphrase'),
      recovery: checked('recovery'),
      newPassphrase: value('new_passphrase'),
    });
    return m.changed;
  });

  const form = root.querySelector('[data-vault-form]');
  const onSubmit = (event) => {
    // Enter in the new-passphrase field means "change it", anywhere else the main action.
    if (event.submitter?.hasAttribute?.('data-vault-rewrap')) return rewrap(event);
    if (doc.activeElement === field('new_passphrase') && !event.submitter) return rewrap(event);
    return root.querySelector('[data-vault-create]') ? create(event) : unlock(event);
  };
  const lockBtn = root.querySelector('[data-vault-lock]');
  const rewrapBtn = root.querySelector('[data-vault-rewrap]');
  form?.addEventListener('submit', onSubmit);
  lockBtn?.addEventListener('click', lock);
  rewrapBtn?.addEventListener('click', rewrap);
  root.dataset.vaultMounted = '1';

  return {
    client,
    destroy() {
      form?.removeEventListener('submit', onSubmit);
      lockBtn?.removeEventListener('click', lock);
      rewrapBtn?.removeEventListener('click', rewrap);
      delete root.dataset.vaultMounted;
    },
  };
}
