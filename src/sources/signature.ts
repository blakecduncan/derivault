import {
  compactSignatureToSignature,
  getAddress,
  hexToBytes,
  parseCompactSignature,
  parseSignature,
  recoverMessageAddress,
  serializeSignature,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";

import { buildUnlockMessage } from "../messages";
import type { UnlockSecretSource } from "../types";

const SECP256K1_N = secp256k1.CURVE.n;

interface ParsedEcdsa {
  r: Hex;
  s: Hex;
  yParity: number;
}

// Parse a 64-byte (EIP-2098 compact) or 65-byte ECDSA signature into (r, s,
// yParity). Anything else — including long ERC-1271 / ERC-6492 smart-account or
// WebAuthn signatures — is rejected: those are frequently non-deterministic per
// signing and would derive unstable keys, so this source only accepts a plain
// EOA ECDSA signature.
function parseEcdsaSignature(signature: Hex): ParsedEcdsa {
  const byteLength = hexToBytes(signature).length;
  if (byteLength === 65) {
    const parsed = parseSignature(signature);
    return { r: parsed.r, s: parsed.s, yParity: parsed.yParity ?? 0 };
  }
  if (byteLength === 64) {
    const parsed = compactSignatureToSignature(parseCompactSignature(signature));
    return { r: parsed.r, s: parsed.s, yParity: parsed.yParity ?? 0 };
  }
  throw new Error(
    `createSignatureUnlockSource: expected a 64- or 65-byte ECDSA signature, received ${byteLength} bytes. ` +
      `ERC-1271 / ERC-6492 smart-account and WebAuthn signatures are not supported by this source.`
  );
}

/**
 * Canonicalize an EIP-191 ECDSA signature into a provider-stable 64-byte
 * `r ‖ low-s` secret. This strips the sources of cross-implementation encoding
 * drift — v=27/28 vs yParity=0/1, 65-byte vs EIP-2098 64-byte compact, and
 * non-low-s signers — so the same key signing the same message derives the same
 * keyvault on any wallet stack. The recovery id carries no entropy and is
 * intentionally dropped.
 */
function canonicalSignatureSecret(parsed: ParsedEcdsa): Uint8Array {
  const s = BigInt(parsed.s);
  const lowS = s > SECP256K1_N / 2n ? SECP256K1_N - s : s;
  const canonical =
    toHex(BigInt(parsed.r), { size: 32 }) + toHex(lowS, { size: 32 }).slice(2);
  return hexToBytes(canonical as Hex);
}

export function createSignatureUnlockSource({
  appName,
  address,
  chainId,
  signMessage,
}: {
  appName: string;
  address: Address;
  chainId: number;
  /** Must return a byte-stable EIP-191 ECDSA signature (RFC-6979 deterministic). */
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

      const parsed = parseEcdsaSignature(signature);

      // Verify the signature actually recovers to the expected signer over the
      // exact unlock message. A provider that signs with the wrong account or a
      // mutated message would otherwise derive a deterministic-but-wrong
      // keyvault that verifyDeterminism cannot catch.
      const reserialized = serializeSignature({
        r: parsed.r,
        s: parsed.s,
        yParity: parsed.yParity,
      });
      const recovered = await recoverMessageAddress({ message, signature: reserialized });
      if (getAddress(recovered) !== getAddress(address)) {
        throw new Error(
          "createSignatureUnlockSource: signature does not recover to the expected address"
        );
      }

      return {
        bytes: canonicalSignatureSecret(parsed),
        source: "eip191-signature-v1",
      };
    },
  };
}
