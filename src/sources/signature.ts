import { hexToBytes, type Address, type Hex } from "viem";

import { buildUnlockMessage } from "../messages";
import type { UnlockSecretSource } from "../types";

export function createSignatureUnlockSource({
  appName,
  address,
  chainId,
  signMessage,
}: {
  appName: string;
  address: Address;
  chainId: number;
  signMessage: (message: string) => Promise<Hex>;
}): UnlockSecretSource {
  return {
    accountId: address,
    async getUnlockSecret() {
      const message = buildUnlockMessage(appName, address, chainId);
      const signature = await signMessage(message);
      return { bytes: hexToBytes(signature), source: "eip191-signature-v1" };
    },
  };
}
