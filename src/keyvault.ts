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
  const km = await importUnlockKeyMaterial(secret);
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

/**
 * Derive a keyvault (RAILGUN seed, stealth keypair, and stealth meta-address)
 * from an unlock source. The derivation is a pure function of the source's
 * secret, so the same source always yields the same keyvault.
 *
 * @param opts.verifyDeterminism When true, the source is unlocked TWICE and the
 * two derivations are compared. With a signature source this triggers a SECOND
 * wallet signing prompt — surface that to the user so it does not read as
 * phishing. It only detects a randomized signer within the current session; it
 * cannot detect cross-device/cross-provider drift, so also require the user to
 * back up `railgunSeed.mnemonic`.
 */
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
