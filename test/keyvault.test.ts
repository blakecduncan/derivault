import { validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

import {
  createSignatureUnlockSource,
  KeyvaultDeterminismError,
  openKeyvault,
} from "../src/index";
import type { UnlockSecretSource } from "../src/index";

const FIXED_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex;
const CHAIN_ID = 42161;
const APP_NAME = "Derivault Example";

const EXPECTED_MNEMONIC = "high bubble marriage vacuum sausage trial diagram ramp toilet zebra silly artist";
const EXPECTED_STEALTH_META_ADDRESS = "0x03c780d93b525a80edfcd5727c8d8d9ee9e1c603328c7d822dc3f63c1575ad31e5027f5bd90a8a5dd27cd74d439e25505160e7e1cf0a8622cda7c17008465336b1bb";

function createDeterministicSource(): UnlockSecretSource {
  const account = privateKeyToAccount(FIXED_KEY);
  return createSignatureUnlockSource({
    appName: APP_NAME,
    address: account.address,
    chainId: CHAIN_ID,
    signMessage: (message) => account.signMessage({ message }),
  });
}

describe("openKeyvault", () => {
  it("derives the same keyvault for the same signature source", async () => {
    const source = createDeterministicSource();
    const first = await openKeyvault(source);
    const second = await openKeyvault(source);

    expect(first.railgunSeed.mnemonic).toBe(second.railgunSeed.mnemonic);
    expect(first.railgunSeed.encryptionKey).toBe(second.railgunSeed.encryptionKey);
    expect(first.stealth.spendingPrivateKey).toBe(second.stealth.spendingPrivateKey);
    expect(first.stealth.spendingPublicKey).toBe(second.stealth.spendingPublicKey);
    expect(first.stealth.viewingPrivateKey).toBe(second.stealth.viewingPrivateKey);
    expect(first.stealth.viewingPublicKey).toBe(second.stealth.viewingPublicKey);
    expect(first.stealthMetaAddress).toBe(second.stealthMetaAddress);
  });

  it("returns a valid RAILGUN seed shape", async () => {
    const keyvault = await openKeyvault(createDeterministicSource());

    expect(keyvault.railgunSeed.encryptionKey).toMatch(/^[0-9a-f]{64}$/);
    expect(keyvault.railgunSeed.mnemonic.split(/\s+/)).toHaveLength(12);
    expect(validateMnemonic(keyvault.railgunSeed.mnemonic, wordlist)).toBe(true);
  });

  it("verifies deterministic sources and rejects changing sources", async () => {
    await expect(
      openKeyvault(createDeterministicSource(), { verifyDeterminism: true })
    ).resolves.toBeDefined();

    let counter = 0;
    const changingSource: UnlockSecretSource = {
      accountId: "changing-source",
      async getUnlockSecret() {
        counter += 1;
        return {
          bytes: new Uint8Array(65).fill(counter),
          source: "eip191-signature-v1",
        };
      },
    };

    await expect(
      openKeyvault(changingSource, { verifyDeterminism: true })
    ).rejects.toBeInstanceOf(KeyvaultDeterminismError);
  });

  it("matches golden vectors", async () => {
    const keyvault = await openKeyvault(createDeterministicSource());

    expect(keyvault.railgunSeed.mnemonic).toBe(EXPECTED_MNEMONIC);
    expect(keyvault.stealthMetaAddress).toBe(EXPECTED_STEALTH_META_ADDRESS);
  });
});
