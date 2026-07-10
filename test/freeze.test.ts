import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

import {
  buildUnlockMessage,
  KEYVAULT_HKDF_SALT,
  KEYVAULT_UNLOCK_VERSION,
  INFO,
} from "../src/index";

// These assertions FREEZE the permanent derivation domain. If one fails, the
// change silently re-derives every existing user's keys — treat it as a
// breaking change requiring a versioned migration, NOT a test to update.
const FIXED_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex;
const account = privateKeyToAccount(FIXED_KEY);

describe("frozen derivation domain", () => {
  it("pins the exact unlock message text", () => {
    expect(buildUnlockMessage("Derivault Example", account.address, 42161)).toBe(
      [
        "Derivault Example Keyvault Unlock",
        "Version: 1",
        "Address: 0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
        "Chain ID: 42161",
        "Only sign this on the official Derivault Example app.",
      ].join("\n")
    );
  });

  it("pins the unlock message version", () => {
    expect(KEYVAULT_UNLOCK_VERSION).toBe(1);
  });

  it("pins the HKDF salt", () => {
    expect(KEYVAULT_HKDF_SALT).toBe("derivault:hkdf:salt:v1");
  });

  it("pins the HKDF info labels", () => {
    expect({ ...INFO }).toEqual({
      railgunSeed: "derivault:railgun:seed:v1",
      railgunEncKey: "derivault:railgun:enc-key:v1",
      stealthSpending: "derivault:stealth:spending:v1",
      stealthViewing: "derivault:stealth:viewing:v1",
      walletEoa: "derivault:wallet:eoa:v1",
    });
  });
});
