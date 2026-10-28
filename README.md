# @profullstack/sealed-secrets

Store the API keys, tokens and passwords your users give you so that **only they can open them**.

The house rule: anywhere a Profullstack app accepts a user's key or secret (exchange API keys,
wallet private keys, BYO AI keys, OAuth tokens, SMTP passwords, GitHub tokens), it seals it
with this package. Nothing the server holds can decrypt it: not an env var, not a database
dump, not root on the box. This is the b1dz.com design (#61, 2026-10-28) as a module, and it
uses the same crypto as logicsrc's OpenCreds vault.

```sh
npm i @profullstack/sealed-secrets
```

WebCrypto only, zero dependencies. The same code runs in the browser, Node 20+, Bun, Deno and
Workers.

## How it works

```
passphrase --PBKDF2-SHA256 600k--> HKDF --> KEK      (the user types this; it never leaves the client)
KEK wraps a random 32-byte data key (DEK)            -> seal.wrapped_dek
recovery key (shown once) wraps the same DEK         -> seal.recovery_wrapped_dek
DEK seals the secret map, AAD = app:scope:user:field -> your secrets column
```

You store two things per user, a `seal` record and the sealed blob. Both are safe to keep in
your database.

## Use it

```js
import { createSealer } from '@profullstack/sealed-secrets';

const sealer = createSealer({ app: 'outreachgraph' }); // scope defaults to "user_settings"

// 1. First time, in the browser or CLI: the user picks a passphrase.
const { dek, seal, recoveryKey } = await sealer.createSeal(passphrase, user.id);
showOnce(recoveryKey); // never store it
const secrets = await sealer.sealSecrets(dek, { GITHUB_TOKEN: 'ghp_...' }, user.id);
await save({ seal, secrets }); // jsonb columns; ciphertext only

// 2. Later: unlock with the passphrase (or the recovery key).
const key = await sealer.unlockSeal(seal, passphrase, user.id);
const { GITHUB_TOKEN } = await sealer.unsealSecrets(key, secrets, user.id);

// 3. Change the passphrase: same data key, so nothing needs re-sealing.
const nextSeal = await sealer.rewrapSeal(key, seal, newPassphrase, user.id);
```

`app` keeps products apart: a seal made for one app cannot be opened as another, even with the
right passphrase. The user id and field name are bound in as AAD, so a blob copied onto another
user or field fails to open.

### Servers that need to write a secret: the inbox

An OAuth callback has to store the provider's token but must not be able to read it later. Every
seal has an ECDH P-256 inbox. The server seals to the public half and queues the entry; the next
unlocked client merges it in.

```js
// server (callback): can write, can never read back
const entry = await sealer.sealToInbox(seal.inbox_public_key, { GOOGLE_REFRESH: token }, user.id);
await queueInbox(user.id, entry);

// unlocked client or worker
const { patch, consumed } = await sealer.openInbox(key, seal, entries, user.id);
```

### Workers that run while the user is away: UnlockStore

A daemon (a trading bot, an outreach sender) can only use a user's secrets while that user has
unlocked a session. The client sends the data key (never the passphrase) over a trusted channel.
The worker checks it with `verifyDataKey` and keeps it in memory with a TTL.

```js
import { UnlockStore, parseTtl } from '@profullstack/sealed-secrets';

const sessions = new UnlockStore();
if (await sealer.verifyDataKey(dek, seal, user.id)) sessions.unlock(user.id, dek, parseTtl('8h'));

const key = sessions.get(user.id); // null once locked or expired: pause that user's jobs
```

The TTL defaults to 8 hours and caps at 7 days. A restart empties the store, so every user is
locked again, and lock or expiry zeroes the key.

## What this is not for

Your own operator secrets (your Resend key, your database URL) belong in the logicsrc team
vault and your host's environment, not here. This package is for secrets that belong to your
users.

## Compatibility

`createSealer({ app: 'b1dz', scope: 'user_settings' })` opens b1dz.com's `seal_version` 2 data
unchanged. The test suite carries a fixture sealed by b1dz's own code.

## License

MIT
