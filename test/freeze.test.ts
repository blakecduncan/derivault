import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { toHex, type Hex } from "viem";

import {
  buildUnlockMessage,
  KEYVAULT_HKDF_SALT,
  KEYVAULT_UNLOCK_VERSION,
  INFO,
} from "../src/index";
import {
  prfSalt,
  WEBAUTHN_PRF_SALT_PREFIX,
} from "../src/sources/webauthn-prf";

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

  it("pins the permanent WebAuthn PRF salt", async () => {
    // The authenticator's PRF output is a pure function of this salt, so it is a
    // fund-controlling permanent domain like the HKDF salt / INFO labels above.
    expect(WEBAUTHN_PRF_SALT_PREFIX).toBe("derivault:webauthn-prf:v1:");
    expect(toHex(await prfSalt("Derivault Example"))).toBe(
      "0x27ce2f658dbe800392a6b2607e552769b9fa4e3fe50737aa2226a285803b5736"
    );
  });
});
