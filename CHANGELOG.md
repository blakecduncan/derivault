# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.0]

### Fixed

- `registerPasskeyWithPrf` now applies the same 32-byte length guard as the
  passkey unlock path. A non-conformant authenticator returning a non-32-byte
  create-time PRF output no longer yields an unlock source whose keys a later
  `get()`-based unlock (which enforces the guard) would reject.

### Changed

- Removed `deriveWalletEoa` from the public API. Its argument was an internal
  HKDF `CryptoKey` that was never exported, so it could not reproduce
  `openKeyvault`'s owner EOA. Use `keyvault.walletEoa` — `openKeyvault` is the
  supported derivation entry point. Existing derivations are unchanged.

### Tests / Docs

- Froze the permanent WebAuthn PRF salt (`derivault:webauthn-prf:v1:`) with a
  golden vector, matching how the HKDF salt and INFO labels are frozen.
- Added direct tests for the WebAuthn PRF source (unlock request wiring, PRF
  error paths, `registerPasskeyWithPrf` support/guard logic, `prfSalt` app
  separation, credential-id base64url round-trip), an owner-EOA golden vector on
  the signature path, and an accountId / full-shape keyvault assertion.
- Corrected stale `openKeyvault` JSDoc/README and added `WebAuthnPrfRegistration`
  to the README Types list.

## [0.2.0]

### Added

- WebAuthn PRF passkey registration and unlock sources for synced,
  discoverable credentials.
- Deterministic secp256k1 wallet-owner derivation at the permanent
  `derivault:wallet:eoa:v1` HKDF label.
- PRF/signature source domain-separation and wallet-owner golden vectors.

### Compatibility

- Existing EIP-191 RAILGUN and stealth derivations are byte-identical to 0.1.0.
- `walletEoa` is an additive field on `Keyvault`.

## [0.1.0]

Initial release.

### Added

- Deterministic, non-custodial derivation of a RAILGUN seed (BIP-39 mnemonic +
  AES `encryptionKey`) and an ERC-5564 stealth keypair from an embedded-wallet
  EIP-191 signature, via HKDF-SHA256 with domain-separated labels.
- Full ERC-5564 (scheme 1) stealth helpers — including `checkStealthAddress` for
  receiver-side scanning — verified interoperable with the reference
  implementation `@scopelift/stealth-address-sdk`.
- `openKeyvault(..., { verifyDeterminism: true })` and `KeyvaultDeterminismError`.
- Optional, storage-agnostic keyvault metadata helpers.
- "Works with Kohaku" integration guidance for the `@kohaku-eth/*` SDK.

### Security

- The signature is canonicalized to 64-byte `r || low-s` before derivation, so
  the same signature derives identical keys regardless of encoding (v vs
  yParity, 65-byte vs EIP-2098 compact, non-low-s). Non-ECDSA smart-account /
  WebAuthn signatures are rejected, and the signature is verified to recover to
  the expected signer.
- The entropy source kind is bound into the HKDF derivation domain.
- Input validation on `appName`, `chainId`, and stealth public keys.
