import {
  keccak256,
  toBytes,
  toHex,
  concat,
  type Address,
  type Hex,
} from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";

export const SECP256K1_SCHEME_ID = BigInt(1);

export interface StealthMetaAddress {
  spendingPubKey: Hex;
  viewingPubKey: Hex;
}

export interface StealthAddress {
  stealthAddress: Address;
  ephemeralPublicKey: Hex;
  viewTag: number;
}

export function parseStealthMetaAddress(metaAddressBytes: Hex): StealthMetaAddress {
  const bytes = toBytes(metaAddressBytes);
  if (bytes.length !== 66) {
    throw new Error("Invalid stealth meta address length");
  }
  const spendingPubKey = toHex(bytes.slice(0, 33));
  const viewingPubKey = toHex(bytes.slice(33, 66));
  return { spendingPubKey, viewingPubKey };
}

export function generateEphemeralPrivateKey(): Hex {
  const privateKey = secp256k1.utils.randomPrivateKey();
  return toHex(privateKey);
}

export function getPublicKey(privateKey: Hex): Hex {
  const pubKey = secp256k1.getPublicKey(toBytes(privateKey), true); // compressed
  return toHex(pubKey);
}

export function computeSharedSecret(privateKey: Hex, publicKey: Hex): Hex {
  const sharedPoint = secp256k1.getSharedSecret(
    toBytes(privateKey),
    toBytes(publicKey),
    true
  );
  return toHex(sharedPoint.slice(1)); // Remove 0x02/0x03 prefix
}

export function generateStealthAddress(
  metaAddress: StealthMetaAddress,
  ephemeralPrivateKey?: Hex
): StealthAddress & { ephemeralPrivateKey: Hex } {
  const ephPrivKey = ephemeralPrivateKey || generateEphemeralPrivateKey();
  const ephemeralPublicKey = getPublicKey(ephPrivKey);
  const sharedSecret = computeSharedSecret(ephPrivKey, metaAddress.viewingPubKey);
  const hashedSecret1 = keccak256(concat([sharedSecret, toHex(new Uint8Array([1]))]));
  const hashedSecret2 = keccak256(concat([sharedSecret, toHex(new Uint8Array([2]))]));
  const spendingPubKeyPoint = secp256k1.ProjectivePoint.fromHex(
    metaAddress.spendingPubKey.slice(2)
  );
  const hashedSecret2Point = secp256k1.ProjectivePoint.fromPrivateKey(
    toBytes(hashedSecret2)
  );
  const stealthSpendingPubKey = spendingPubKeyPoint.add(hashedSecret2Point);
  const stealthSpendingPubKeyUncompressed = stealthSpendingPubKey.toRawBytes(false);
  const addressHash = keccak256(stealthSpendingPubKeyUncompressed.slice(1));
  const stealthAddress = `0x${addressHash.slice(-40)}` as Address;
  const viewTag = toBytes(hashedSecret1)[0]!;
  return { stealthAddress, ephemeralPublicKey, viewTag, ephemeralPrivateKey: ephPrivKey };
}

export function createAnnouncementMetadata(viewTag: number, metadataHash: Hex): Hex {
  const viewTagByte = toHex(new Uint8Array([viewTag]));
  return concat([viewTagByte, metadataHash]);
}

export function createStealthMetaAddress(
  spendingPublicKey: Hex,
  viewingPublicKey: Hex
): Hex {
  const spendingBytes = toBytes(spendingPublicKey);
  const viewingBytes = toBytes(viewingPublicKey);
  return toHex(new Uint8Array([...spendingBytes, ...viewingBytes]));
}

export function generateStealthKeyPair(): { privateKey: Hex; publicKey: Hex } {
  const privateKey = generateEphemeralPrivateKey();
  const publicKey = getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function deriveStealthPrivateKey({
  spendingPrivateKey,
  viewingPrivateKey,
  ephemeralPublicKey,
}: {
  spendingPrivateKey: Hex;
  viewingPrivateKey: Hex;
  ephemeralPublicKey: Hex;
}): Hex {
  const sharedSecret = computeSharedSecret(viewingPrivateKey, ephemeralPublicKey);
  const hashedSecret2 = keccak256(concat([sharedSecret, toHex(new Uint8Array([2]))]));
  const spending = BigInt(spendingPrivateKey);
  const tweak = BigInt(hashedSecret2);
  const derived = (spending + tweak) % secp256k1.CURVE.n;
  return toHex(derived, { size: 32 });
}
