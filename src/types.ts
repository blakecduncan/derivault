import type { Address, Hex } from "viem";

/**
 * Identifies how the unlock secret was obtained. This is bound into the HKDF
 * derivation domain (see `importUnlockKeyMaterial`), so it is a permanent part
 * of the derivation, not merely informational metadata. Additional source kinds
 * (e.g. a future WebAuthn-PRF source) can be added later without breaking
 * existing derivations, since each kind gets its own key domain.
 */
export type UnlockSourceKind = "eip191-signature-v1";

export interface UnlockSecret {
  readonly bytes: Uint8Array;
  readonly source: UnlockSourceKind;
}

export interface UnlockSecretSource {
  readonly accountId: string;
  getUnlockSecret(): Promise<UnlockSecret>;
}

export interface RailgunSeed {
  mnemonic: string;
  encryptionKey: string;
}

export interface StealthKeypair {
  spendingPrivateKey: Hex;
  spendingPublicKey: Hex;
  viewingPrivateKey: Hex;
  viewingPublicKey: Hex;
}

export interface Keyvault {
  accountId: string;
  railgunSeed: RailgunSeed;
  stealth: StealthKeypair;
  stealthMetaAddress: Hex;
}

export type { Address, Hex };
