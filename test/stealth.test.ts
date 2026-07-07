import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

import {
  createStealthMetaAddress,
  deriveStealthPrivateKey,
  generateStealthAddress,
  getPublicKey,
  parseStealthMetaAddress,
} from "../src/index";

const SPENDING_PRIVATE_KEY = `0x${"11".repeat(32)}` as Hex;
const VIEWING_PRIVATE_KEY = `0x${"22".repeat(32)}` as Hex;
const EPHEMERAL_PRIVATE_KEY = `0x${"33".repeat(32)}` as Hex;

describe("stealth address helpers", () => {
  it("round-trips an ERC-5564 stealth address derivation", () => {
    const spendingPublicKey = getPublicKey(SPENDING_PRIVATE_KEY);
    const viewingPublicKey = getPublicKey(VIEWING_PRIVATE_KEY);
    const metaAddress = createStealthMetaAddress(spendingPublicKey, viewingPublicKey);
    const meta = parseStealthMetaAddress(metaAddress);
    const stealth = generateStealthAddress(meta, EPHEMERAL_PRIVATE_KEY);
    const derivedPrivateKey = deriveStealthPrivateKey({
      spendingPrivateKey: SPENDING_PRIVATE_KEY,
      viewingPrivateKey: VIEWING_PRIVATE_KEY,
      ephemeralPublicKey: stealth.ephemeralPublicKey,
    });

    expect(privateKeyToAccount(derivedPrivateKey).address.toLowerCase()).toBe(
      stealth.stealthAddress.toLowerCase()
    );
  });
});
