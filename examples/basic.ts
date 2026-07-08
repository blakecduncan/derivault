/**
 * Runnable example. From the package root:
 *
 *   pnpm example
 *   # or: pnpm tsx examples/basic.ts
 *
 * It uses a viem local account as a stand-in for an embedded-wallet signer, so
 * it runs with no network and no wallet provider. The private key below is the
 * well-known Anvil/Hardhat test key #0 — never use it for real funds.
 */
import { privateKeyToAccount } from "viem/accounts";

import {
  createSignatureUnlockSource,
  openKeyvault,
  parseStealthMetaAddress,
  generateStealthAddress,
  deriveStealthPrivateKey,
} from "../src/index";

const account = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
);

const source = createSignatureUnlockSource({
  appName: "Example App",
  address: account.address,
  chainId: 42161,
  signMessage: (message) => account.signMessage({ message }),
});

const keyvault = await openKeyvault(source, { verifyDeterminism: true });

console.log("RAILGUN mnemonic:      ", keyvault.railgunSeed.mnemonic);
console.log("RAILGUN encryptionKey: ", keyvault.railgunSeed.encryptionKey);
console.log("Stealth meta-address:  ", keyvault.stealthMetaAddress);

// A sender generates a one-time stealth address for this recipient.
const meta = parseStealthMetaAddress(keyvault.stealthMetaAddress);
const announcement = generateStealthAddress(meta);
console.log("\nSender -> stealth address:   ", announcement.stealthAddress);

// The recipient derives the private key that controls that stealth address.
const stealthPrivateKey = deriveStealthPrivateKey({
  spendingPrivateKey: keyvault.stealth.spendingPrivateKey,
  viewingPrivateKey: keyvault.stealth.viewingPrivateKey,
  ephemeralPublicKey: announcement.ephemeralPublicKey,
});
console.log("Recipient's key for it:      ", stealthPrivateKey);
console.log(
  "Controls that address:       ",
  privateKeyToAccount(stealthPrivateKey).address.toLowerCase() ===
    announcement.stealthAddress.toLowerCase()
);
