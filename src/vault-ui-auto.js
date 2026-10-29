import { mountKeyVault } from './vault-ui.js';

/**
 * Side-effect entry: bundle it (as an IIFE) and load it on the page that draws
 * the card. Mounts every [data-key-vault] element, and #key-vault for older markup.
 */
function mountAll() {
  const roots = new Set([
    ...document.querySelectorAll('[data-key-vault]'),
    ...[document.getElementById('key-vault')].filter(Boolean),
  ]);
  for (const root of roots) {
    if (root.dataset.vaultMounted) continue;
    mountKeyVault(root);
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAll);
  else mountAll();
}
