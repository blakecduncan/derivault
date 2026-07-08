import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

import {
  buildUnlockMessage,
  createSignatureUnlockSource,
  openKeyvault,
} from "../src/index";

const KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex;
const account = privateKeyToAccount(KEY);

function makeSource(appName: string, chainId: number) {
  return createSignatureUnlockSource({
    appName,
    address: account.address,
    chainId,
    signMessage: (message) => account.signMessage({ message }),
  });
}

function open(appName: string, chainId = 42161) {
  return openKeyvault(makeSource(appName, chainId));
}

describe("domain separation", () => {
  it("derives different keys for different app names", async () => {
    const a = await open("App A");
    const b = await open("App B");
    expect(a.railgunSeed.mnemonic).not.toBe(b.railgunSeed.mnemonic);
    expect(a.stealthMetaAddress).not.toBe(b.stealthMetaAddress);
  });

  it("derives different keys for different chain ids", async () => {
    const a = await open("App", 1);
    const b = await open("App", 42161);
    expect(a.railgunSeed.mnemonic).not.toBe(b.railgunSeed.mnemonic);
    expect(a.stealthMetaAddress).not.toBe(b.stealthMetaAddress);
  });
});

describe("input validation", () => {
  it("rejects an appName containing newlines", () => {
    expect(() => buildUnlockMessage("Bad\nApp", account.address, 1)).toThrow();
  });

  it("rejects an empty appName", () => {
    expect(() => buildUnlockMessage("", account.address, 1)).toThrow();
  });

  it("rejects a too-short signature from the signer", async () => {
    const source = createSignatureUnlockSource({
      appName: "App",
      address: account.address,
      chainId: 1,
      signMessage: async () => "0xdeadbeef" as Hex, // 4 bytes
    });
    await expect(source.getUnlockSecret()).rejects.toThrow(/64- or 65-byte/);
  });

  it("rejects a non-integer or non-positive chainId", () => {
    expect(() => buildUnlockMessage("App", account.address, Number.NaN)).toThrow();
    expect(() => buildUnlockMessage("App", account.address, 0)).toThrow();
    expect(() => buildUnlockMessage("App", account.address, -1)).toThrow();
    expect(() => buildUnlockMessage("App", account.address, 1.5)).toThrow();
  });

  it("rejects a non-hex signature", async () => {
    const source = createSignatureUnlockSource({
      appName: "App",
      address: account.address,
      chainId: 1,
      signMessage: async () => "not-a-signature" as Hex,
    });
    await expect(source.getUnlockSecret()).rejects.toThrow();
  });
});
