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

The signer must return a stable ECDSA `(r, s)` for the same unlock message across
sessions and devices. The signature is canonicalized (64-byte `r || low-s`)
before derivation, so encoding differences — v=27/28 vs yParity=0/1, 65-byte vs
EIP-2098 compact, non-low-s — do not affect the derived keys; only `(r, s)`
stability matters, which RFC 6979 deterministic ECDSA provides. The signature
source also rejects non-ECDSA (ERC-1271 / ERC-6492 smart-account and WebAuthn)
signatures, which are frequently non-deterministic, and verifies that the
signature recovers to the expected signer. If a provider nonetheless changes its
signing key or scheme, the derived keys change and funds appear inaccessible
unless the user has backed up the mnemonic — so applications should still use
`verifyDeterminism` and require phrase backup before receiving funds.

### Phishing The Unlock Signature

An attacker who tricks the user into signing the exact unlock message can derive
the same keys. The human-readable message includes the app name, version,
address, and chain ID so wallets can show clear signing context. Applications
should use a stable, recognizable `appName` and educate users to sign only in the
official app.

### Weak Or Low-Entropy Signatures

Under RFC 6979 the signature is a deterministic function of the signing key and
the fixed unlock message, so its unpredictability is bounded by the signing key
— roughly a 256-bit secret at about 128-bit security, not the 512 bits of the
`r || s` encoding. That is ample keying material for HKDF, but HKDF cannot
compensate for a signer that uses weak or reused nonces, leaks private-key
material, or returns predictable signatures. The security of every derived key
rests on the secrecy and quality of the underlying signing key.

### Replay And Cross-App Linkage

The unlock message includes `appName`, address, chain ID, and version. The HKDF
salt and labels are also package-specific. Different app names derive different
keys, preventing accidental key reuse across apps that use this library.

## Memory Handling

Derived secrets are not — and in JavaScript cannot reliably be — zeroized. The
mnemonic and hex private keys are immutable strings, and BigInt scalars and HKDF
intermediates are garbage-collected on their own schedule, so plaintext secret
material remains in heap memory until collected and is reachable by a heap dump,
crash reporter, or swap. The imported HKDF key material is a non-extractable
`CryptoKey`, but the input-keying-material copy is not wiped. `derivault`
therefore assumes an uncompromised JavaScript realm, consistent with the
"compromised device" non-guarantee below. Keep derived keys short-lived and
avoid logging or serializing them.

## Explicit Non-Guarantees

- On-chain privacy properties are provided by RAILGUN and ERC-5564, not by this
  library.
- This library does not defend against a compromised device.
- This library does not defend against a malicious signer or wallet provider.
- This library does not provide relaying, proof generation, POI handling,
  transaction construction, wallet UX, or key backup UX.
- This library does not provide constant-time execution: JavaScript BigInt and
  JIT behavior make timing side-channel resistance impossible to guarantee (the
  same stance as @noble/curves). This is not a concern for one-shot client-side
  derivation with no remote timing oracle.

## Determinism Requirement

The signer must return a stable `(r, s)` for the same message. Signature encoding
is normalized, so byte-for-byte identity is not required, but `(r, s)` stability
is. If that property does not hold, derivation is not stable. Applications should
call `openKeyvault(source, { verifyDeterminism: true })` at provisioning time and
make phrase export a required part of onboarding before funds are sent to derived
addresses.
