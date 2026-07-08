import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  parseSignature,
  serializeCompactSignature,
  signatureToCompactSignature,
  type Hex,
} from "viem";

import {
  buildUnlockMessage,
  createSignatureUnlockSource,
  openKeyvault,
} from "../src/index";

const FIXED_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex;
const account = privateKeyToAccount(FIXED_KEY);
const APP = "Derivault Example";
const CHAIN = 42161;

function sourceReturning(signature: Hex) {
  return createSignatureUnlockSource({
    appName: APP,
    address: account.address,
    chainId: CHAIN,
    signMessage: async () => signature,
  });
}

// The unlock message is deterministic, so we can pre-sign it and re-encode.
const message = buildUnlockMessage(APP, account.address, CHAIN);

describe("signature encoding canonicalization", () => {
  it("derives the identical keyvault from v=27/28, yParity=0/1, and EIP-2098 compact encodings of the same signature", async () => {
    const raw = await account.signMessage({ message }); // 65-byte, v=27/28
    const p = parseSignature(raw);

    const form_v = raw;
    // 65-byte form ending in raw yParity (00/01) instead of v (1b/1c)
    const form_yParity = (p.r +
      p.s.slice(2) +
      (p.yParity === 0 ? "00" : "01")) as Hex;
    // 64-byte EIP-2098 compact form
    const form_compact = serializeCompactSignature(
      signatureToCompactSignature({ r: p.r, s: p.s, yParity: p.yParity ?? 0 })
    );

    const [kvV, kvYParity, kvCompact] = await Promise.all([
      openKeyvault(sourceReturning(form_v)),
      openKeyvault(sourceReturning(form_yParity)),
      openKeyvault(sourceReturning(form_compact)),
    ]);

    expect(kvYParity.railgunSeed.mnemonic).toBe(kvV.railgunSeed.mnemonic);
    expect(kvCompact.railgunSeed.mnemonic).toBe(kvV.railgunSeed.mnemonic);
    expect(kvYParity.railgunSeed.encryptionKey).toBe(kvV.railgunSeed.encryptionKey);
    expect(kvCompact.railgunSeed.encryptionKey).toBe(kvV.railgunSeed.encryptionKey);
    expect(kvYParity.stealthMetaAddress).toBe(kvV.stealthMetaAddress);
    expect(kvCompact.stealthMetaAddress).toBe(kvV.stealthMetaAddress);
  });

  it("rejects a signature that recovers to a different address", async () => {
    const impostor = privateKeyToAccount(
      "0x2222222222222222222222222222222222222222222222222222222222222222"
    );
    const source = createSignatureUnlockSource({
      appName: APP,
      address: account.address, // expect `account`...
      chainId: CHAIN,
      signMessage: (m) => impostor.signMessage({ message: m }), // ...but `impostor` signs
    });
    await expect(source.getUnlockSecret()).rejects.toThrow(/recover/);
  });

  it("rejects an over-length (smart-account / ERC-1271) signature", async () => {
    const source = sourceReturning(("0x" + "ab".repeat(100)) as Hex); // 100 bytes
    await expect(source.getUnlockSecret()).rejects.toThrow(/64- or 65-byte/);
  });
});
