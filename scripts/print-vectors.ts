import { privateKeyToAccount } from "viem/accounts";
import { toHex, type Hex } from "viem";

import { createSignatureUnlockSource, openKeyvault } from "../src/index";
import { prfSalt } from "../src/sources/webauthn-prf";

const FIXED_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex;
const CHAIN_ID = 42161;
const APP_NAME = "Derivault Example";

const account = privateKeyToAccount(FIXED_KEY);
const source = createSignatureUnlockSource({
  appName: APP_NAME,
  address: account.address,
  chainId: CHAIN_ID,
  signMessage: (message) => account.signMessage({ message }),
});

const keyvault = await openKeyvault(source, { verifyDeterminism: true });

console.log(
  JSON.stringify(
    {
      mnemonic: keyvault.railgunSeed.mnemonic,
      encryptionKey: keyvault.railgunSeed.encryptionKey,
      stealthMetaAddress: keyvault.stealthMetaAddress,
      spendingPrivateKey: keyvault.stealth.spendingPrivateKey,
      spendingPublicKey: keyvault.stealth.spendingPublicKey,
      viewingPrivateKey: keyvault.stealth.viewingPrivateKey,
      viewingPublicKey: keyvault.stealth.viewingPublicKey,
      walletEoa: keyvault.walletEoa,
      prfSalt: toHex(await prfSalt(APP_NAME)),
    },
    null,
    2
  )
);
