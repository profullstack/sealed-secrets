export declare const SEAL_VERSION: 2;
export declare const PBKDF2_ITERATIONS: number;
export declare const MIN_PBKDF2_ITERATIONS: number;
export declare const MIN_PASSPHRASE_LENGTH: number;
export declare const SECRET_FIELD: 'payload_secret';

/** AES-256-GCM output: base64 ciphertext, 12-byte IV and 16-byte tag stored separately. */
export interface CipherBlob {
  ciphertext: string;
  iv: string;
  tag: string;
}

export interface SealKdf {
  alg: 'PBKDF2-SHA256';
  iterations: number;
  /** base64, 16 random bytes */
  salt: string;
}

/** Store this per user (a jsonb column is fine). Nothing in it opens without the passphrase or recovery key. */
export interface SealRecord {
  v: 2;
  kdf: SealKdf;
  wrapped_dek: CipherBlob;
  recovery_wrapped_dek: CipherBlob | null;
  key_check: CipherBlob;
  /** base64 raw P-256 public key; servers seal to it with sealToInbox */
  inbox_public_key: string;
  inbox_private_sealed: CipherBlob;
}

/** One secret patch a server sealed to a user's inbox. */
export interface InboxEntry {
  id: string;
  /** base64 raw ephemeral P-256 public key */
  epk: string;
  blob: CipherBlob;
  created_at: string;
}

export interface CreatedSeal {
  /** The 32-byte data key. Keep it in memory only, and wipe() it when done. */
  dek: Uint8Array;
  seal: SealRecord;
  /** Show to the user exactly once; never store it. */
  recoveryKey: string;
}

export type SecretMap = Record<string, string>;

export interface Sealer {
  readonly app: string;
  readonly scope: string;
  createSeal(passphrase: string, userId: string, iterations?: number): Promise<CreatedSeal>;
  unlockSeal(seal: SealRecord, passphrase: string, userId: string): Promise<Uint8Array>;
  unlockSealWithRecovery(seal: SealRecord, recoveryKey: string, userId: string): Promise<Uint8Array>;
  rewrapSeal(dek: Uint8Array, seal: SealRecord, newPassphrase: string, userId: string): Promise<SealRecord>;
  verifyDataKey(dek: Uint8Array, seal: Pick<SealRecord, 'key_check'>, userId: string): Promise<boolean>;
  sealJson(dek: Uint8Array, value: unknown, userId: string, field?: string): Promise<CipherBlob>;
  unsealJson<T = unknown>(dek: Uint8Array, blob: CipherBlob, userId: string, field?: string): Promise<T>;
  sealSecrets(
    dek: Uint8Array,
    secrets: Record<string, string | number | boolean>,
    userId: string,
    field?: string,
  ): Promise<CipherBlob>;
  unsealSecrets(dek: Uint8Array, blob: CipherBlob, userId: string, field?: string): Promise<SecretMap>;
  sealToInbox(publicKeyB64: string, patch: Record<string, string>, userId: string): Promise<InboxEntry>;
  openInbox(
    dek: Uint8Array,
    seal: Pick<SealRecord, 'inbox_private_sealed'>,
    entries: InboxEntry[],
    userId: string,
  ): Promise<{ patch: SecretMap; consumed: string[] }>;
}

export interface SealerOptions {
  /** Short lowercase app name; separates one product's ciphertext from another's. */
  app: string;
  /** The record the secrets belong to. Default "user_settings". */
  scope?: string;
}

export declare function createSealer(options: SealerOptions): Sealer;

export declare class WrongPassphraseError extends Error {}

export declare function isSealRecord(v: unknown): v is SealRecord;
export declare function isCipherBlob(v: unknown): v is CipherBlob;
export declare function isInboxEntry(v: unknown): v is InboxEntry;
export declare function toSecretMap(parsed: unknown): SecretMap;
export declare function encodeRecoveryKey(raw: Uint8Array): string;
export declare function decodeRecoveryKey(text: string): Uint8Array;
export declare function bytesToBase64(bytes: Uint8Array): string;
export declare function base64ToBytes(b64: string): Uint8Array;
export declare function randomBytes(n: number): Uint8Array;
export declare function wipe(bytes: Uint8Array | null | undefined): void;

export declare const UNLOCK_DEFAULT_TTL_SECONDS: number;
export declare const UNLOCK_MAX_TTL_SECONDS: number;
export declare const UNLOCK_MIN_TTL_SECONDS: number;
export declare function clampUnlockTtlSeconds(v: unknown): number;
/** "8h", "30m", "7d", "3600" -> seconds (clamped to 60s..7d). */
export declare function parseTtl(text: string | undefined): number;

export interface UnlockStatus {
  unlocked: boolean;
  expiresAt: string | null;
}

/** In-memory userId -> data key sessions with a TTL. Never persist what it holds. */
export declare class UnlockStore {
  constructor(options?: { now?: () => number; useTimers?: boolean });
  onChange(fn: (userId: string, unlocked: boolean) => void): () => void;
  unlock(userId: string, key: Uint8Array, ttlSeconds?: number): UnlockStatus;
  get(userId: string): Uint8Array | null;
  status(userId: string): UnlockStatus;
  lock(userId: string): void;
  lockAll(): void;
  readonly size: number;
}
