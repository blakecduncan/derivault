# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
