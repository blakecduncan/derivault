import { getAddress, type Address } from "viem";

export const KEYVAULT_UNLOCK_VERSION = 1;

/**
 * Builds the EIP-191 unlock message. The exact message text, appName, and
 * KEYVAULT_UNLOCK_VERSION are permanent derivation-domain commitments: changing
 * any of them re-derives every user's keys and must never happen once an app
 * has users.
 */
export function buildUnlockMessage(
  appName: string,
  address: Address,
  chainId: number
): string {
  const checksumAddress = getAddress(address);

  return [
    `${appName} Keyvault Unlock`,
    `Version: ${KEYVAULT_UNLOCK_VERSION}`,
    `Address: ${checksumAddress}`,
    `Chain ID: ${chainId}`,
    `Only sign this on the official ${appName} app.`,
  ].join("\n");
}
