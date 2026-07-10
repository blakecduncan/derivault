import { secp256k1 } from "@noble/curves/secp256k1";

import type { UnlockSecret } from "./types";

const encoder = new TextEncoder();

// The unit-separator control byte cannot appear in an ASCII source-kind label,
// so it cleanly delimits the source label from the raw secret bytes.
const SOURCE_SEPARATOR = 0x1f;

// These labels are permanent. Never change KEYVAULT_HKDF_SALT or any INFO.*
// label without a versioned migration; doing so silently re-derives every key.
export const KEYVAULT_HKDF_SALT = "derivault:hkdf:salt:v1";

export const INFO = {
  railgunSeed: "derivault:railgun:seed:v1",
  railgunEncKey: "derivault:railgun:enc-key:v1",
  stealthSpending: "derivault:stealth:spending:v1",
  stealthViewing: "derivault:stealth:viewing:v1",
  walletEoa: "derivault:wallet:eoa:v1",
} as const;

// Prevent accidental runtime mutation of the permanent derivation labels.
Object.freeze(INFO);

const bytesToBigInt = (bytes: Uint8Array) =>
  bytes.reduce((value, byte) => (value << BigInt(8)) + BigInt(byte), BigInt(0));

export function importUnlockKeyMaterial(secret: UnlockSecret): Promise<CryptoKey> {
  // Bind the entropy source kind into the derivation domain: the source label,
  // a 0x1f separator, then the raw secret bytes form the HKDF IKM. This ensures
  // two different source kinds can never derive identical keys from
  // coincidentally equal bytes, and the separator prevents one source label
  // being a prefix of another.
  const label = encoder.encode(secret.source);
  const ikm = new Uint8Array(label.length + 1 + secret.bytes.length);
  ikm.set(label, 0);
  ikm[label.length] = SOURCE_SEPARATOR;
  ikm.set(secret.bytes, label.length + 1);
  return crypto.subtle.importKey("raw", ikm.buffer as ArrayBuffer, "HKDF", false, [
    "deriveBits",
  ]);
}

export async function hkdfBytes(
  km: CryptoKey,
  info: string,
  byteLength: number
): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(KEYVAULT_HKDF_SALT),
      info: encoder.encode(info),
    },
    km,
    byteLength * 8
  );
  return new Uint8Array(bits);
}

export async function hkdfScalar(km: CryptoKey, info: string): Promise<bigint> {
  const expanded = await hkdfBytes(km, info, 64);
  const value = bytesToBigInt(expanded);
  const n = secp256k1.CURVE.n;
  const one = BigInt(1);
  return (value % (n - one)) + one;
}
