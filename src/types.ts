import type { Address, Hex } from "viem";

export type UnlockSourceKind = "eip191-signature-v1" | "webauthn-prf-v1";

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
