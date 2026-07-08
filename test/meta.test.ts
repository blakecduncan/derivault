import { describe, expect, it } from "vitest";
import type { Address } from "viem";

import {
  getKeyvaultMeta,
  setKeyvaultMeta,
  clearKeyvaultMeta,
  type KeyvaultMeta,
  type KeyvaultMetaStorage,
} from "../src/index";

function memoryStorage(): KeyvaultMetaStorage {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
    removeItem: (key) => {
      map.delete(key);
    },
  };
}

const ADDRESS = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c" as Address;
const KEY = `derivault:meta:v1:${ADDRESS.toLowerCase()}`;
const META: KeyvaultMeta = {
  railgunAddress: "0zk1qexampleaddress",
  railgunWalletID: "wallet-abc",
  stealthMetaAddress: "0x0300",
  creationBlockNumbers: { "42161": 123456 },
  derivationVersion: 1,
  provisionedAt: "2026-01-01T00:00:00.000Z",
};

describe("keyvault metadata store", () => {
  it("round-trips through injected storage", () => {
    const storage = memoryStorage();
    setKeyvaultMeta(ADDRESS, META, storage);
    expect(getKeyvaultMeta(ADDRESS, storage)).toEqual(META);
  });

  it("returns null when nothing is stored", () => {
    expect(getKeyvaultMeta(ADDRESS, memoryStorage())).toBeNull();
  });

  it("returns null on corrupted JSON", () => {
    const storage = memoryStorage();
    storage.setItem(KEY, "{ not valid json");
    expect(getKeyvaultMeta(ADDRESS, storage)).toBeNull();
  });

  it("returns null on a shape mismatch", () => {
    const storage = memoryStorage();
    storage.setItem(KEY, JSON.stringify({ foo: 1 }));
    expect(getKeyvaultMeta(ADDRESS, storage)).toBeNull();
  });

  it("clears stored metadata", () => {
    const storage = memoryStorage();
    setKeyvaultMeta(ADDRESS, META, storage);
    clearKeyvaultMeta(ADDRESS, storage);
    expect(getKeyvaultMeta(ADDRESS, storage)).toBeNull();
  });

  it("no-ops (does not throw) without storage in a non-browser environment", () => {
    expect(getKeyvaultMeta(ADDRESS)).toBeNull();
    expect(() => setKeyvaultMeta(ADDRESS, META)).not.toThrow();
    expect(() => clearKeyvaultMeta(ADDRESS)).not.toThrow();
  });
});
