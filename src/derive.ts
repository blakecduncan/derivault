import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { hkdfBytes, hkdfScalar, INFO } from "./hkdf";
import { getPublicKey } from "./stealth";
import type { RailgunSeed, StealthKeypair, WalletEoa } from "./types";

export async function deriveRailgunSeed(km: CryptoKey): Promise<RailgunSeed> {
  const entropy = await hkdfBytes(km, INFO.railgunSeed, 16);
  const mnemonic = entropyToMnemonic(entropy, wordlist);
  const encryptionKey = toHex(await hkdfBytes(km, INFO.railgunEncKey, 32)).slice(2);
  return { mnemonic, encryptionKey };
}

export async function deriveStealthKeys(km: CryptoKey): Promise<StealthKeypair> {
  const spendingPrivateKey = toHex(await hkdfScalar(km, INFO.stealthSpending), { size: 32 });
  const viewingPrivateKey = toHex(await hkdfScalar(km, INFO.stealthViewing), { size: 32 });
  return {
    spendingPrivateKey,
    spendingPublicKey: getPublicKey(spendingPrivateKey),
    viewingPrivateKey,
    viewingPublicKey: getPublicKey(viewingPrivateKey),
  };
}

export async function deriveWalletEoa(km: CryptoKey): Promise<WalletEoa> {
  const privateKey = toHex(await hkdfScalar(km, INFO.walletEoa), { size: 32 });
  return { privateKey, address: privateKeyToAccount(privateKey).address };
}
