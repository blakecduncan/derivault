# derivault

Deterministically derive non-custodial privacy keys for RAILGUN shielded wallets
and ERC-5564 stealth addresses from an embedded-wallet signature.

Embedded wallets provide strong onboarding UX, but they do not normally hold
protocol-specific privacy keys. The naive fix is to generate those keys and keep
them on a backend, which quietly makes the backend custodial. `derivault` avoids
that by deriving keys on demand from the wallet's own signature, so nothing
secret has to be stored.

## Install

```sh
npm i derivault viem
```

`viem` is a normal dependency of this package and is also commonly used by
consumers for wallet types, signing, and account utilities.

## Quickstart

```ts
import {
  createSignatureUnlockSource,
  deriveStealthPrivateKey,
  generateStealthAddress,
  openKeyvault,
  parseStealthMetaAddress,
} from "derivault";
import type { Address, Hex } from "viem";

const source = createSignatureUnlockSource({
  appName: "Example App",
  address: user.wallet.address as Address,
  chainId: 42161,
  signMessage: async (message) => {
    // Privy-style shape; adapt this wrapper to your wallet provider.
    const { signature } = await signMessage({ message });
    return signature as Hex;
  },
});

const keyvault = await openKeyvault(source, { verifyDeterminism: true });

// Use these with the RAILGUN SDK wallet creation/import flow.
const railgunSeed = keyvault.railgunSeed.mnemonic;
const railgunEncryptionKey = keyvault.railgunSeed.encryptionKey;

// Publish or store this as the user's ERC-5564 receiving meta-address.
const receivingMetaAddress = keyvault.stealthMetaAddress;

// Sender side: generate a stealth address from the recipient's meta-address.
const recipientMeta = parseStealthMetaAddress(receivingMetaAddress);
const announcement = generateStealthAddress(recipientMeta);

// Receiver side: derive the private key for an announced stealth address.
const stealthPrivateKey = deriveStealthPrivateKey({
  spendingPrivateKey: keyvault.stealth.spendingPrivateKey,
  viewingPrivateKey: keyvault.stealth.viewingPrivateKey,
  ephemeralPublicKey: announcement.ephemeralPublicKey,
});
```

## How It Works

The unlock source obtains an EIP-191 `personal_sign` signature over a stable,
human-readable message. Those signature bytes are used as HKDF-SHA256 key
material, then expanded with permanent domain-separated `info` labels.

```text
embedded wallet signature
  -> HKDF-SHA256 with derivault salt
  -> 16 bytes mnemonic entropy -> BIP-39 12-word RAILGUN seed
  -> 32 bytes RAILGUN encryptionKey
  -> secp256k1 stealth spending scalar
  -> secp256k1 stealth viewing scalar
  -> ERC-5564 stealth meta-address
```

The RAILGUN mnemonic uses 16 bytes of entropy, producing a 12-word phrase. The
RAILGUN `encryptionKey` is 32 bytes encoded as 64 lowercase hex characters
without a `0x` prefix. Stealth private keys are derived by reducing a 64-byte
HKDF expansion into the secp256k1 scalar field with `(value % (n - 1)) + 1`.

## Security Model

The root of trust is the embedded wallet and the user's authentication to that
wallet. A backend using this package stores no mnemonic, encryption key, stealth
private key, unlock signature, or HKDF material. The package is provider
agnostic: any signer that can produce a byte-stable EIP-191 `personal_sign`
signature can be wrapped as an `UnlockSecretSource`.

Two caveats are inherent. First, derived keys necessarily live in client memory
while they are being used for client-side privacy workflows, so a compromised
frontend can steal them. Second, continuity depends on the signer returning the
same signature bytes for the same message across sessions and devices. Mitigate
that with `verifyDeterminism` during provisioning and by requiring users to back
up the 12-word phrase before receiving funds.

See [THREAT_MODEL.md](./THREAT_MODEL.md) for the full threat model.

## Works with Kohaku

`derivault` works alongside the Ethereum Foundation's Kohaku privacy SDK (the
`@kohaku-eth/*` npm packages) and sits upstream of it. Kohaku is a wallet-level
privacy SDK for protocols such as RAILGUN and Privacy Pools. `derivault`
provides the non-custodial key-derivation layer for teams that already build on
an embedded wallet (Privy, passkeys) and do not want to adopt a separate wallet
stack.

Kohaku's RAILGUN plugin does not take a RAILGUN mnemonic directly; it derives
its keys from a `Host` keystore. The integration is therefore to use the
`derivault` mnemonic — derived non-custodially from the embedded-wallet
signature — as the seed for Kohaku's `MnemonicKeystore`.

Illustrative only. Verified against `@kohaku-eth/railgun` and
`@kohaku-eth/plugins` at `0.0.1-alpha`, which are unaudited and may introduce
breaking changes; re-check the API against the versions you install.

```ts
import { openKeyvault } from "derivault";
import { MnemonicKeystore, MemoryStorage } from "@kohaku-eth/plugins";
import { createRailgunPlugin } from "@kohaku-eth/railgun";

const keyvault = await openKeyvault(source, { verifyDeterminism: true });

// derivault derives the mnemonic from the embedded wallet, non-custodially.
// Kohaku's keystore consumes it and derives its own RAILGUN spending/viewing
// keys via HD paths, so that key material never has to be generated or stored
// by your backend.
const host = {
  keystore: new MnemonicKeystore(keyvault.railgunSeed.mnemonic),
  provider,                     // your @kohaku-eth/provider / EIP-1193 provider
  storage: new MemoryStorage(), // or a persistent Storage implementation
  // ...any other fields your Kohaku version's Host requires
};

const railgun = await createRailgunPlugin(host, { keyIndex: 0 });
```

In this model `derivault` supplies the non-custodial keystore seed and Kohaku
derives the protocol keys from it. `derivault`'s own `encryptionKey` and stealth
keys are not used on the Kohaku path.

For stealth addresses, `keyvault.stealthMetaAddress` is a standard ERC-5564
meta-address usable with any ERC-5564 tooling. Kohaku does not currently ship a
stealth-address module, so `derivault` complements it there.

## Determinism And Domain Separation

The unlock message is part of the derivation domain. Its text, `appName`, chain
ID, address, and version determine the signature, and therefore determine every
derived key. Once an app has users, changing its unlock message or `appName`
re-derives all keys.

The HKDF salt and `INFO` labels exported by this package are also permanent
commitments. Different app names intentionally derive different keys, giving
apps separate key domains even when the same wallet address is used.

## API Reference

- `buildUnlockMessage(appName, address, chainId)`: builds the stable EIP-191
  message to sign.
- `KEYVAULT_UNLOCK_VERSION`: current unlock message version.
- `createSignatureUnlockSource(options)`: wraps an EIP-191 signer as an
  `UnlockSecretSource`.
- `openKeyvault(source, opts?)`: derives the RAILGUN seed, stealth keypair, and
  stealth meta-address.
- `KeyvaultDeterminismError`: thrown when `verifyDeterminism` detects changing
  derivation output.
- `INFO`: permanent HKDF `info` labels.
- `KEYVAULT_HKDF_SALT`: permanent HKDF salt.
- `parseStealthMetaAddress(metaAddress)`: splits an ERC-5564 meta-address into
  spending and viewing public keys.
- `generateEphemeralPrivateKey()`: creates a random secp256k1 private key.
- `getPublicKey(privateKey)`: returns the compressed secp256k1 public key.
- `computeSharedSecret(privateKey, publicKey)`: computes the compressed ECDH
  shared secret without its prefix byte.
- `generateStealthAddress(metaAddress, ephemeralPrivateKey?)`: creates an
  ERC-5564 stealth address announcement.
- `createAnnouncementMetadata(viewTag, metadataHash)`: prefixes metadata with a
  view tag byte.
- `createStealthMetaAddress(spendingPublicKey, viewingPublicKey)`: concatenates
  compressed spending and viewing public keys.
- `generateStealthKeyPair()`: creates a random private/public keypair.
- `deriveStealthPrivateKey(args)`: derives the receiver's private key for a
  stealth address announcement.
- `SECP256K1_SCHEME_ID`: ERC-5564 secp256k1 scheme identifier.
- `getKeyvaultMeta(address, storage?)`: reads optional app metadata from injected
  storage or browser `localStorage`.
- `setKeyvaultMeta(address, meta, storage?)`: writes optional app metadata.
- `clearKeyvaultMeta(address, storage?)`: removes optional app metadata.
- Types: `Address`, `Hex`, `UnlockSourceKind`, `UnlockSecret`,
  `UnlockSecretSource`, `RailgunSeed`, `StealthKeypair`, `Keyvault`,
  `StealthMetaAddress`, `StealthAddress`, `KeyvaultMeta`, and
  `KeyvaultMetaStorage`.

## Extensibility

`UnlockSecretSource` is intentionally small:

```ts
interface UnlockSecretSource {
  readonly accountId: string;
  getUnlockSecret(): Promise<UnlockSecret>;
}
```

The first source is an EIP-191 signature source. Other sources can be added
without changing the derivation pipeline, such as a future WebAuthn-PRF passkey
source. No passkey source is included in v1.

## Non-Goals

`derivault` is not a wallet, not a RAILGUN SDK wrapper, not a relayer, and not a
proof or POI implementation. It does not store, sync, transmit, or back up keys.
It only derives deterministic non-custodial privacy keys from an unlock secret
and provides ERC-5564 helper functions.

## License

MIT
