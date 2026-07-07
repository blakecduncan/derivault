# Threat Model

`derivault` derives privacy keys from an embedded-wallet signature. It does not
store keys, transmit keys, provide on-chain privacy by itself, or replace a
wallet, RAILGUN implementation, relayer, or ERC-5564 implementation.

## Assets

- RAILGUN spending authority represented by the derived 12-word mnemonic.
- RAILGUN local database `encryptionKey`.
- ERC-5564 stealth spending private key.
- ERC-5564 stealth viewing private key.

## Trust Model And Custody

The derived keys are a pure function of a wallet signature over a domain-bound
unlock message. Custody is therefore the same as custody of the embedded wallet:
whoever can make that wallet sign the unlock message can derive the privacy
keys.

A backend using this library holds zero secret material. It cannot derive the
keys unless it sees the unlock signature bytes, which should remain in the
client.

## Key Separation

The signature bytes are imported into HKDF-SHA256 once, then expanded with
separate permanent `info` labels for:

- RAILGUN mnemonic entropy.
- RAILGUN database encryption key.
- Stealth spending scalar.
- Stealth viewing scalar.

Reusing the same signature across these labels does not reuse key bytes across
protocol roles.

## Attacker Scenarios

### Compromised Or Malicious Frontend

A frontend that executes malicious code can read derived keys while they are in
client memory. This is inherent for client-side privacy protocols that need
local proving or local signing. Mitigations include provider signature
confirmation, strict deployment controls, dependency hygiene, content security
policy, minimizing key lifetime in memory, and avoiding unnecessary logging.

### XSS

XSS is equivalent to a compromised frontend during the active session. Treat the
unlock signature, mnemonic, encryption key, and stealth private keys as secrets
that must never enter logs, analytics, URLs, untrusted frames, or durable
browser storage.

### Malicious Or Changed Signer

The signer must produce byte-identical signatures for the same unlock message
across sessions and devices. If the provider changes signing behavior, the
derived keys change and funds can appear inaccessible unless the user has backed
up the mnemonic. Typical secp256k1 signers use deterministic RFC 6979 ECDSA for
stable signatures, but applications should still use `verifyDeterminism` and
require users to export or back up the phrase before receiving funds.

### Phishing The Unlock Signature

An attacker who tricks the user into signing the exact unlock message can derive
the same keys. The human-readable message includes the app name, version,
address, and chain ID so wallets can show clear signing context. Applications
should use a stable, recognizable `appName` and educate users to sign only in the
official app.

### Weak Or Low-Entropy Signatures

The derivation assumes the signer produces a full-entropy secp256k1 signature,
approximately 512 bits before encoding details. HKDF expands this secret
material into domain-separated keys; it does not compensate for a signer that
uses weak nonces, leaks private-key material, or returns predictable signatures.

### Replay And Cross-App Linkage

The unlock message includes `appName`, address, chain ID, and version. The HKDF
salt and labels are also package-specific. Different app names derive different
keys, preventing accidental key reuse across apps that use this library.

## Explicit Non-Guarantees

- On-chain privacy properties are provided by RAILGUN and ERC-5564, not by this
  library.
- This library does not defend against a compromised device.
- This library does not defend against a malicious signer or wallet provider.
- This library does not provide relaying, proof generation, POI handling,
  transaction construction, wallet UX, or key backup UX.

## Determinism Requirement

The signer must produce byte-identical signatures for the same message. If that
property does not hold, derivation is not stable. Applications should call
`openKeyvault(source, { verifyDeterminism: true })` at provisioning time and
should make phrase export a required part of onboarding before funds are sent to
derived addresses.
