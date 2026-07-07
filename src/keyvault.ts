import { deriveRailgunSeed, deriveStealthKeys } from "./derive";
import { importUnlockKeyMaterial } from "./hkdf";
import { createStealthMetaAddress } from "./stealth";
import type { Keyvault, UnlockSecretSource } from "./types";

export class KeyvaultDeterminismError extends Error {
  constructor(message = "Keyvault derivation is not deterministic") {
    super(message);
    this.name = "KeyvaultDeterminismError";
  }
}

async function deriveKeyvault(source: UnlockSecretSource): Promise<Keyvault> {
  const secret = await source.getUnlockSecret();
  const km = await importUnlockKeyMaterial(secret.bytes);
  const [railgunSeed, stealth] = await Promise.all([
    deriveRailgunSeed(km),
    deriveStealthKeys(km),
  ]);
  const stealthMetaAddress = createStealthMetaAddress(
    stealth.spendingPublicKey,
    stealth.viewingPublicKey
  );
  return { accountId: source.accountId, railgunSeed, stealth, stealthMetaAddress };
}

export async function openKeyvault(
  source: UnlockSecretSource,
  opts: { verifyDeterminism?: boolean } = {}
): Promise<Keyvault> {
  const keyvault = await deriveKeyvault(source);
  if (opts.verifyDeterminism) {
    const secondKeyvault = await deriveKeyvault(source);
    const matches =
      keyvault.railgunSeed.mnemonic === secondKeyvault.railgunSeed.mnemonic &&
      keyvault.stealthMetaAddress === secondKeyvault.stealthMetaAddress;
    if (!matches) {
      throw new KeyvaultDeterminismError();
    }
  }
  return keyvault;
}
