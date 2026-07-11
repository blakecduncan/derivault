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

const EXPECTED_MNEMONIC =
  "like canoe silver spatial layer draw infant wonder gesture like hazard current";
const EXPECTED_ENCRYPTION_KEY =
  "fe7df2a9b10a16b0ce567f8062b3c8a744bb8ae3bf57cb1aea616141b6c59e40";
const EXPECTED_STEALTH_META_ADDRESS =
  "0x033f79e414edc236b27a72b4241ce37df1f1dee00985acf3354f63dd6474825bdb0223c7f9ac4aa826b687702bf0932db8f71b46ff079b85d5d24257380f0437d0cb";
const EXPECTED_WALLET_EOA = {
  privateKey:
    "0x35bb63adcb605efd9f7c1ec004ca553747c4ec5b717102255b38afe874fdeaba",
  address: "0x96E230bc289ADa12a52E5D711d3eCA8c39a63eBd",
} as const;

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
    expect(keyvault.railgunSeed.encryptionKey).toBe(EXPECTED_ENCRYPTION_KEY);
    expect(keyvault.stealthMetaAddress).toBe(EXPECTED_STEALTH_META_ADDRESS);
    // Freeze the owner EOA on the production signature path (funds-controlling).
    expect(keyvault.walletEoa).toEqual(EXPECTED_WALLET_EOA);
  });

  it("propagates accountId and derives a complete keyvault from a raw source", async () => {
    const source: UnlockSecretSource = {
      accountId: "acct-123",
      async getUnlockSecret() {
        return {
          bytes: Uint8Array.from({ length: 32 }, (_, index) => index),
          source: "eip191-signature-v1",
        };
      },
    };

    const keyvault = await openKeyvault(source);
    expect(keyvault.accountId).toBe("acct-123");
    expect(keyvault.railgunSeed.encryptionKey).toMatch(/^[0-9a-f]{64}$/);
    expect(keyvault.railgunSeed.mnemonic.split(/\s+/)).toHaveLength(12);
    expect(keyvault.stealth.spendingPublicKey).toMatch(/^0x0[23][0-9a-f]{64}$/);
    expect(keyvault.stealth.viewingPublicKey).toMatch(/^0x0[23][0-9a-f]{64}$/);
    expect(privateKeyToAccount(keyvault.walletEoa.privateKey).address).toBe(
      keyvault.walletEoa.address
    );
  });
});
