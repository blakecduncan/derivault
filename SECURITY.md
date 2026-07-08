# Security Policy

`derivault` derives keys that can control funds. Please report suspected
vulnerabilities privately.

## Reporting a vulnerability

Email **blakecduncan@gmail.com** with a description and, ideally, a reproduction.
Please do **not** open a public issue for security-sensitive reports. You'll get
an acknowledgement as soon as possible, along with updates on the fix and
disclosure timeline.

## In scope

The key-derivation and ERC-5564 logic in `src/`: incorrect or non-deterministic
derivation, weak-entropy handling, HKDF key separation, and stealth-address
interoperability.

## Out of scope

- Vulnerabilities in dependencies — please report those upstream.
- The inherent properties documented in [THREAT_MODEL.md](./THREAT_MODEL.md),
  e.g. a compromised frontend reading derived keys in memory, or a malicious /
  non-deterministic signer. These are design assumptions, not defects.

## Supported versions

This is pre-1.0 software; only the latest published version is supported.
