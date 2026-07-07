import type { Address } from "viem";

export interface KeyvaultMeta {
  railgunAddress: string;
  railgunWalletID: string;
  stealthMetaAddress: `0x${string}`;
  creationBlockNumbers: Record<string, number>;
  derivationVersion: number;
  provisionedAt: string;
}

export interface KeyvaultMetaStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const KEYVAULT_META_PREFIX = "derivault:meta:v1:";

function getDefaultStorage(): KeyvaultMetaStorage | null {
  try {
    return typeof globalThis.localStorage === "undefined" ? null : globalThis.localStorage;
  } catch {
    return null;
  }
}

function resolveStorage(storage?: KeyvaultMetaStorage): KeyvaultMetaStorage | null {
  return storage ?? getDefaultStorage();
}

function getMetaKey(address: Address): string {
  return `${KEYVAULT_META_PREFIX}${address.toLowerCase()}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNumberRecord(value: unknown): value is Record<string, number> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === "number");
}

function isKeyvaultMeta(value: unknown): value is KeyvaultMeta {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value.railgunAddress === "string" &&
    typeof value.railgunWalletID === "string" &&
    typeof value.stealthMetaAddress === "string" &&
    value.stealthMetaAddress.startsWith("0x") &&
    isNumberRecord(value.creationBlockNumbers) &&
    typeof value.derivationVersion === "number" &&
    typeof value.provisionedAt === "string"
  );
}

export function getKeyvaultMeta(
  address: Address,
  storage?: KeyvaultMetaStorage
): KeyvaultMeta | null {
  const resolvedStorage = resolveStorage(storage);
  if (!resolvedStorage) {
    return null;
  }

  const raw = resolvedStorage.getItem(getMetaKey(address));
  if (!raw) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    return isKeyvaultMeta(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function setKeyvaultMeta(
  address: Address,
  meta: KeyvaultMeta,
  storage?: KeyvaultMetaStorage
): void {
  const resolvedStorage = resolveStorage(storage);
  if (!resolvedStorage) {
    return;
  }
  resolvedStorage.setItem(getMetaKey(address), JSON.stringify(meta));
}

export function clearKeyvaultMeta(address: Address, storage?: KeyvaultMetaStorage): void {
  const resolvedStorage = resolveStorage(storage);
  if (!resolvedStorage) {
    return;
  }
  resolvedStorage.removeItem(getMetaKey(address));
}
