import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  generateStealthAddress as scopeliftGenerate,
  computeStealthKey as scopeliftComputeKey,
  VALID_SCHEME_ID,
} from "@scopelift/stealth-address-sdk";

import {
  createStealthMetaAddress,
  parseStealthMetaAddress,
  getPublicKey,
  generateStealthAddress,
  deriveStealthPrivateKey,
} from "../src/index";

// Proves derivault's ERC-5564 (scheme 1) implementation is interoperable with
// the reference implementation, not merely self-consistent.
const SPENDING_PRIVATE_KEY =
  "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex;
const VIEWING_PRIVATE_KEY =
  "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex;
const EPHEMERAL_PRIVATE_KEY =
  "0x3333333333333333333333333333333333333333333333333333333333333333" as Hex;

const metaAddress = createStealthMetaAddress(
  getPublicKey(SPENDING_PRIVATE_KEY),
  getPublicKey(VIEWING_PRIVATE_KEY)
);

describe("ERC-5564 interop with @scopelift/stealth-address-sdk", () => {
  it("derivault derives the spending key for a ScopeLift-generated stealth address", () => {
    const generated = scopeliftGenerate({
      stealthMetaAddressURI: metaAddress,
      schemeId: VALID_SCHEME_ID.SCHEME_ID_1,
    });

    const derivedPrivateKey = deriveStealthPrivateKey({
      spendingPrivateKey: SPENDING_PRIVATE_KEY,
      viewingPrivateKey: VIEWING_PRIVATE_KEY,
      ephemeralPublicKey: generated.ephemeralPublicKey,
    });

    expect(privateKeyToAccount(derivedPrivateKey).address.toLowerCase()).toBe(
      generated.stealthAddress.toLowerCase()
    );
  });

  it("ScopeLift derives the spending key for a derivault-generated stealth address", () => {
    const generated = generateStealthAddress(
      parseStealthMetaAddress(metaAddress),
      EPHEMERAL_PRIVATE_KEY
    );

    const scopeliftPrivateKey = scopeliftComputeKey({
      ephemeralPublicKey: generated.ephemeralPublicKey,
      schemeId: VALID_SCHEME_ID.SCHEME_ID_1,
      spendingPrivateKey: SPENDING_PRIVATE_KEY,
      viewingPrivateKey: VIEWING_PRIVATE_KEY,
    });

    expect(privateKeyToAccount(scopeliftPrivateKey).address.toLowerCase()).toBe(
      generated.stealthAddress.toLowerCase()
    );
  });
});
