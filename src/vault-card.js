import { MIN_PASSPHRASE_LENGTH } from './seal.js';

/**
 * The key vault card's markup, as an HTML string, so every site draws the same
 * form the browser controller (./vault-ui.js) expects. Server-side only; no DOM.
 *
 * Markup contract (mountKeyVault reads these):
 *   [data-key-vault]          root, with data-app, data-scope, data-user, data-endpoint
 *   [data-vault-status]       status line (aria-live)
 *   form[data-vault-form]     passphrase, confirm (create) or recovery checkbox (unlock), ttl
 *   [data-vault-create] / [data-vault-unlock]  the submit button
 *   [data-vault-lock]         when unlocked
 *   [data-vault-rewrap] + new_passphrase       change passphrase (when a vault exists)
 *
 * Copy is the site's: pass `intro` (array of paragraphs) and `lost`.
 */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escapeHtml = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);

export const DEFAULT_TTL_OPTIONS = [
  ['1h', '1 hour'],
  ['8h', '8 hours'],
  ['1d', '1 day'],
  ['7d', '7 days'],
];

export function vaultStatusText(vault = {}, { legacyNoun = 'older item(s)' } = {}) {
  let text = !vault.exists
    ? 'No vault yet.'
    : vault.unlocked
      ? `Unlocked until ${new Date(vault.expiresAt).toUTCString()}.`
      : 'Locked.';
  if (vault.legacy) text += ` ${vault.legacy} ${legacyNoun} will be re-sealed when you unlock.`;
  return text;
}

/**
 * @param {object} o
 * @param {string} o.app
 * @param {string} [o.scope]
 * @param {string} o.userId
 * @param {{exists:boolean, unlocked:boolean, expiresAt?:string|number|null, legacy?:number}} o.vault
 * @param {string} [o.endpoint='/my/vault']
 * @param {string} [o.id='key-vault']
 * @param {string} [o.title='Key vault']
 * @param {string[]} [o.intro]   paragraphs (plain text, escaped)
 * @param {string} [o.lost]      the "lose both and it is gone" warning
 * @param {string} [o.scriptSrc] bundle to load (the auto entry), deferred
 * @param {string} [o.nonce]
 * @param {string} [o.className='card']
 * @param {Array<[string,string]>} [o.ttlOptions]
 * @param {string} [o.defaultTtl='8h']
 */
export function keyVaultCardHtml({
  app,
  scope = 'user_settings',
  userId,
  vault = { exists: false, unlocked: false },
  endpoint = '/my/vault',
  id = 'key-vault',
  title = 'Key vault',
  intro = [],
  lost = 'If you lose both your passphrase and your recovery key, what is sealed is gone for good: nobody here can open it.',
  scriptSrc,
  nonce,
  className = 'card',
  ttlOptions = DEFAULT_TTL_OPTIONS,
  defaultTtl = '8h',
  legacyNoun,
} = {}) {
  const e = escapeHtml;
  const p = (t) => `<p class="muted small">${e(t)}</p>`;
  const exists = Boolean(vault.exists);
  let body;
  if (exists && vault.unlocked) {
    body = '<p><button type="button" data-vault-lock>Lock now</button></p>';
  } else {
    const ttl = ttlOptions
      .map(([v, label]) => `<option value="${e(v)}"${v === defaultTtl ? ' selected' : ''}>${e(label)}</option>`)
      .join('');
    body = [
      '<form class="stack" data-vault-form autocomplete="on" novalidate>',
      // A hidden username helps password managers file the passphrase under this site.
      `<input type="text" name="username" autocomplete="username" value="${e(userId)}" hidden aria-hidden="true" tabindex="-1">`,
      `<input type="password" name="passphrase" required minlength="${MIN_PASSPHRASE_LENGTH}" autocomplete="${exists ? 'current-password' : 'new-password'}" placeholder="${
        exists ? 'Passphrase (or recovery key)' : `Passphrase, ${MIN_PASSPHRASE_LENGTH} characters or more`
      }" aria-label="Passphrase">`,
      exists
        ? '<label class="small"><input type="checkbox" name="recovery"> That is my recovery key</label>'
        : '<input type="password" name="confirm" required autocomplete="new-password" placeholder="The same again" aria-label="Passphrase again">',
      `<label class="small">Stay unlocked for <select name="ttl">${ttl}</select></label>`,
      exists
        ? '<button type="submit" class="cta" data-vault-unlock>Unlock</button>'
        : '<button type="submit" class="cta" data-vault-create>Create my vault</button>',
      exists
        ? `<details><summary class="small">Change passphrase</summary><input type="password" name="new_passphrase" minlength="${MIN_PASSPHRASE_LENGTH}" autocomplete="new-password" placeholder="New passphrase" aria-label="New passphrase"> <button type="button" data-vault-rewrap>Change it</button></details>`
        : '',
      '</form>',
    ].join('');
  }
  const script = scriptSrc
    ? `<script src="${e(scriptSrc)}" defer${nonce ? ` nonce="${e(nonce)}"` : ''}></script>`
    : '';
  return [
    `<section id="${e(id)}" class="${e(className)}" data-key-vault data-app="${e(app)}" data-scope="${e(scope)}" data-user="${e(userId)}" data-endpoint="${e(endpoint)}">`,
    `<h2>${e(title)}</h2>`,
    ...intro.map(p),
    lost ? p(lost) : '',
    `<p data-vault-status class="notice" aria-live="polite">${e(vaultStatusText(vault, legacyNoun ? { legacyNoun } : undefined))}</p>`,
    body,
    script,
    '</section>',
  ].join('');
}
