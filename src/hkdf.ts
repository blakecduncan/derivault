import { secp256k1 } from "@noble/curves/secp256k1";

const encoder = new TextEncoder();

// These labels are permanent. Never change KEYVAULT_HKDF_SALT or any INFO.*
// label without a versioned migration; doing so silently re-derives every key.
export const KEYVAULT_HKDF_SALT = "derivault:hkdf:salt:v1";

export const INFO = {
  railgunSeed: "derivault:railgun:seed:v1",
  railgunEncKey: "derivault:railgun:enc-key:v1",
  stealthSpending: "derivault:stealth:spending:v1",
  stealthViewing: "derivault:stealth:viewing:v1",
} as const;

const bytesToBigInt = (bytes: Uint8Array) =>
  bytes.reduce((value, byte) => (value << BigInt(8)) + BigInt(byte), BigInt(0));

export function importUnlockKeyMaterial(secret: Uint8Array): Promise<CryptoKey> {
  const bytes = Uint8Array.from(secret);
  return crypto.subtle.importKey("raw", bytes.buffer as ArrayBuffer, "HKDF", false, [
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
