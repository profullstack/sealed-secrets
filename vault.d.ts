import type { createSealer } from './index.js';

type Sealer = ReturnType<typeof createSealer>;

export interface VaultView {
  exists: boolean;
  unlocked: boolean;
  expiresAt?: string | number | null;
  legacy?: number;
}

/* ./vault-ui (browser) */
export declare const VAULT_MESSAGES: Record<string, string>;
export interface VaultClient {
  messages: Record<string, string>;
  status(): Promise<VaultView & { seal: unknown }>;
  create(o: { passphrase: string; confirm?: string; ttl?: string }): Promise<{ recoveryKey: string; unlock: Record<string, unknown> }>;
  unlock(o: { passphrase: string; recovery?: boolean; ttl?: string }): Promise<Record<string, unknown>>;
  lock(): Promise<Record<string, unknown>>;
  changePassphrase(o: { passphrase: string; recovery?: boolean; newPassphrase: string }): Promise<Record<string, unknown>>;
}
export declare function createVaultClient(o: {
  app: string;
  scope?: string;
  userId: string;
  endpoint?: string;
  fetch?: typeof fetch;
  messages?: Record<string, string>;
  sealer?: Sealer;
}): VaultClient;
export declare function describeUnlock(out: unknown, messages?: Record<string, string>): string;
export declare function mountKeyVault(
  root: HTMLElement,
  o?: { app?: string; scope?: string; userId?: string; endpoint?: string; messages?: Record<string, string>; fetch?: typeof fetch; reload?: () => void; reloadAfterMs?: number },
): { client: VaultClient; destroy(): void } | null;

/* ./vault-card (server-side markup) */
export declare function escapeHtml(v: unknown): string;
export declare const DEFAULT_TTL_OPTIONS: Array<[string, string]>;
export declare function vaultStatusText(vault?: VaultView, o?: { legacyNoun?: string }): string;
export declare function keyVaultCardHtml(o: {
  app: string;
  scope?: string;
  userId: string;
  vault?: VaultView;
  endpoint?: string;
  id?: string;
  title?: string;
  intro?: string[];
  lost?: string;
  scriptSrc?: string;
  nonce?: string;
  className?: string;
  ttlOptions?: Array<[string, string]>;
  defaultTtl?: string;
  legacyNoun?: string;
}): string;

/* ./vault-server */
export interface VaultReply { status: number; body: Record<string, unknown> }
export declare const VAULT_SERVER_MESSAGES: Record<string, string>;
export declare class VaultHttpError extends Error { status: number; code?: string }
export declare function vaultTtlSeconds(value: unknown): number;
export interface VaultHandlers {
  get(userId: string): Promise<VaultReply>;
  create(userId: string, body: unknown): Promise<VaultReply>;
  replace(userId: string, body: unknown): Promise<VaultReply>;
  unlock(userId: string, body: unknown): Promise<VaultReply>;
  lock(userId: string): Promise<VaultReply>;
}
export declare function createVaultHandlers(o: {
  sealer: Sealer;
  store: { get(userId: string): Promise<unknown | null>; create(userId: string, seal: unknown): Promise<boolean>; replace(userId: string, seal: unknown): Promise<void> };
  onUnlock(userId: string, dek: Uint8Array, ttlSeconds: number): Promise<Record<string, unknown> | void>;
  onLock?(userId: string): unknown;
  status?(userId: string): { unlocked: boolean; expiresAt: unknown };
  view?(userId: string): Promise<Record<string, unknown>>;
  onCreate?(userId: string, seal: unknown): unknown;
  messages?: Record<string, string>;
}): VaultHandlers;
export declare function mountVaultRoutes<A>(app: A, o: { handlers: VaultHandlers; userId(c: any): string | Promise<string>; base?: string }): A;
