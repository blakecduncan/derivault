import {
  keccak256,
  getAddress,
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

function assertCompressedPubKey(key: Hex, context: string): void {
  const bytes = toBytes(key);
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
    throw new Error(`${context}: expected a 33-byte compressed secp256k1 public key`);
  }
}

/**
 * Parse an ERC-5564 stealth meta-address (spending pubkey ‖ viewing pubkey,
 * 33 compressed bytes each) into its two component public keys.
 */
export function parseStealthMetaAddress(metaAddressBytes: Hex): StealthMetaAddress {
  const bytes = toBytes(metaAddressBytes);
  if (bytes.length !== 66) {
    throw new Error("Invalid stealth meta address length");
  }
  const spendingPubKey = toHex(bytes.slice(0, 33));
  const viewingPubKey = toHex(bytes.slice(33, 66));
  assertCompressedPubKey(spendingPubKey, "parseStealthMetaAddress (spending key)");
  assertCompressedPubKey(viewingPubKey, "parseStealthMetaAddress (viewing key)");
  return { spendingPubKey, viewingPubKey };
}

export function generateEphemeralPrivateKey(): Hex {
  return toHex(secp256k1.utils.randomPrivateKey());
}

export function getPublicKey(privateKey: Hex): Hex {
  return toHex(secp256k1.getPublicKey(toBytes(privateKey), true)); // compressed
}

/**
 * ERC-5564 (scheme 1) shared secret: the *compressed* ECDH point (33 bytes,
 * including the 0x02/0x03 prefix), matching the value hashed by the canonical
 * ERC-5564 construction. Interoperable with standard ERC-5564 tooling.
 */
export function computeSharedSecret(privateKey: Hex, publicKey: Hex): Hex {
  return toHex(
    secp256k1.getSharedSecret(toBytes(privateKey), toBytes(publicKey), true)
  );
}

// keccak256 of the compressed shared-secret point — a single hash used for both
// the point tweak and the view tag, per ERC-5564 scheme 1.
function hashSharedSecret(privateKey: Hex, publicKey: Hex): Hex {
  return keccak256(computeSharedSecret(privateKey, publicKey));
}

// Uncompressed secp256k1 public key (65 bytes) -> checksummed EIP-55 address.
function publicKeyToAddress(uncompressedPubKey: Uint8Array): Address {
  const addressHash = keccak256(uncompressedPubKey.slice(1));
  return getAddress(`0x${addressHash.slice(-40)}`);
}

/**
 * ERC-5564 scheme 1: generate a one-time stealth address for a recipient's
 * meta-address. Interoperable with the reference implementation
 * (@scopelift/stealth-address-sdk); verified by tests.
 *
 * The returned object is the *publishable* announcement — it deliberately does
 * NOT include the ephemeral private key. If you supplied `ephemeralPrivateKey`,
 * you already hold it; never publish it, as it would let anyone recompute the
 * shared secret and de-anonymize the payment.
 */
export function generateStealthAddress(
  metaAddress: StealthMetaAddress,
  ephemeralPrivateKey?: Hex
): StealthAddress {
  const ephPrivKey = ephemeralPrivateKey ?? generateEphemeralPrivateKey();
  const ephemeralPublicKey = getPublicKey(ephPrivKey);

  const hashed = hashSharedSecret(ephPrivKey, metaAddress.viewingPubKey);
  const hashedBytes = toBytes(hashed);

  // stealthPub = spendingPub + hashedSharedSecret * G
  const stealthPubKeyPoint = secp256k1.ProjectivePoint.fromHex(
    metaAddress.spendingPubKey.slice(2)
  ).add(secp256k1.ProjectivePoint.fromPrivateKey(hashedBytes));

  const stealthAddress = publicKeyToAddress(stealthPubKeyPoint.toRawBytes(false));
  const viewTag = hashedBytes[0]!; // most significant byte of the hash

  return { stealthAddress, ephemeralPublicKey, viewTag };
}

/**
 * Create ERC-5564 announcement metadata: the view-tag byte followed by the
 * metadata hash. The first byte MUST be the view tag per ERC-5564.
 */
export function createAnnouncementMetadata(viewTag: number, metadataHash: Hex): Hex {
  if (!Number.isInteger(viewTag) || viewTag < 0 || viewTag > 255) {
    throw new Error("createAnnouncementMetadata: viewTag must be a byte (0-255)");
  }
  const viewTagByte = toHex(new Uint8Array([viewTag]));
  return concat([viewTagByte, metadataHash]);
}

/** Concatenate compressed spending + viewing public keys into a meta-address. */
export function createStealthMetaAddress(
  spendingPublicKey: Hex,
  viewingPublicKey: Hex
): Hex {
  assertCompressedPubKey(spendingPublicKey, "createStealthMetaAddress (spending key)");
  assertCompressedPubKey(viewingPublicKey, "createStealthMetaAddress (viewing key)");
  const spendingBytes = toBytes(spendingPublicKey);
  const viewingBytes = toBytes(viewingPublicKey);
  return toHex(new Uint8Array([...spendingBytes, ...viewingBytes]));
}

export function generateStealthKeyPair(): { privateKey: Hex; publicKey: Hex } {
  const privateKey = generateEphemeralPrivateKey();
  return { privateKey, publicKey: getPublicKey(privateKey) };
}

/**
 * ERC-5564 scheme 1: receiver-side derivation of the private key controlling an
 * announced stealth address. stealthPriv = (spendingPriv + hashedSharedSecret) mod n.
 */
export function deriveStealthPrivateKey({
  spendingPrivateKey,
  viewingPrivateKey,
  ephemeralPublicKey,
}: {
  spendingPrivateKey: Hex;
  viewingPrivateKey: Hex;
  ephemeralPublicKey: Hex;
}): Hex {
  const hashed = hashSharedSecret(viewingPrivateKey, ephemeralPublicKey);
  const derived = (BigInt(spendingPrivateKey) + BigInt(hashed)) % secp256k1.CURVE.n;
  return toHex(derived, { size: 32 });
}

/**
 * ERC-5564 scheme 1: receiver-side check of whether an announced stealth address
 * belongs to you, using your viewing private key and spending public key. The
 * view tag (if provided) is a cheap fast-reject filter; the address comparison
 * is authoritative. Returns true iff the announcement resolves to
 * `stealthAddress` under your keys.
 */
export function checkStealthAddress({
  ephemeralPublicKey,
  spendingPublicKey,
  viewingPrivateKey,
  stealthAddress,
  viewTag,
}: {
  ephemeralPublicKey: Hex;
  spendingPublicKey: Hex;
  viewingPrivateKey: Hex;
  stealthAddress: Address;
  viewTag?: number;
}): boolean {
  const hashed = hashSharedSecret(viewingPrivateKey, ephemeralPublicKey);
  const hashedBytes = toBytes(hashed);
  if (viewTag !== undefined && hashedBytes[0] !== viewTag) {
    return false;
  }
  const stealthPubKeyPoint = secp256k1.ProjectivePoint.fromHex(
    spendingPublicKey.slice(2)
  ).add(secp256k1.ProjectivePoint.fromPrivateKey(hashedBytes));
  const derivedAddress = publicKeyToAddress(stealthPubKeyPoint.toRawBytes(false));
  return getAddress(derivedAddress) === getAddress(stealthAddress);
}
