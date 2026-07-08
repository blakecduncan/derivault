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

      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]*$/.test(signature)) {
        throw new Error(
          "createSignatureUnlockSource: signMessage must return a 0x-prefixed hex signature"
        );
      }

      const bytes = hexToBytes(signature);
      // An EIP-191 ECDSA signature is 65 bytes (r,s,v); r,s alone are 64. A
      // shorter value means a truncated/empty signature, which would derive
      // keys from weak entropy — reject it loudly rather than derive silently.
      if (bytes.length < 64) {
        throw new Error(
          `createSignatureUnlockSource: signature is too short (${bytes.length} bytes); expected a 65-byte ECDSA signature`
        );
      }

      return { bytes, source: "eip191-signature-v1" };
    },
  };
}
