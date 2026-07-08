# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Deterministic, non-custodial derivation of a RAILGUN seed (BIP-39 mnemonic +
  AES `encryptionKey`) and an ERC-5564 stealth keypair from an embedded-wallet
  EIP-191 signature, via HKDF-SHA256 with domain-separated labels.
- Full ERC-5564 (scheme 1) stealth helpers, verified interoperable with the
  reference implementation `@scopelift/stealth-address-sdk`.
- `openKeyvault(..., { verifyDeterminism: true })` and `KeyvaultDeterminismError`.
- Validation on the unlock path: signatures must be hex and at least 64 bytes;
  `appName` must be non-empty and free of newlines.
- Optional, storage-agnostic keyvault metadata helpers.
- "Works with Kohaku" integration guidance for the `@kohaku-eth/*` SDK.
