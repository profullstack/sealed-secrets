export {
  SEAL_VERSION,
  PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  MIN_PASSPHRASE_LENGTH,
  SECRET_FIELD,
  WrongPassphraseError,
  createSealer,
  isSealRecord,
  isCipherBlob,
  isInboxEntry,
  toSecretMap,
  encodeRecoveryKey,
  decodeRecoveryKey,
  bytesToBase64,
  base64ToBytes,
  randomBytes,
  wipe,
} from './seal.js';

export {
  UnlockStore,
  UNLOCK_DEFAULT_TTL_SECONDS,
  UNLOCK_MAX_TTL_SECONDS,
  UNLOCK_MIN_TTL_SECONDS,
  clampUnlockTtlSeconds,
  parseTtl,
} from './unlock-store.js';
