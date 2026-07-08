import { describe, expect, it } from "vitest";
import type { Hex } from "viem";

import {
  getPublicKey,
  createStealthMetaAddress,
  parseStealthMetaAddress,
  generateStealthAddress,
  checkStealthAddress,
  createAnnouncementMetadata,
} from "../src/index";

const SPENDING =
  "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex;
const VIEWING =
  "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex;
const EPHEMERAL =
  "0x3333333333333333333333333333333333333333333333333333333333333333" as Hex;
const OTHER_VIEWING =
  "0x4444444444444444444444444444444444444444444444444444444444444444" as Hex;

const spendingPub = getPublicKey(SPENDING);
const viewingPub = getPublicKey(VIEWING);
const meta = parseStealthMetaAddress(createStealthMetaAddress(spendingPub, viewingPub));

describe("checkStealthAddress", () => {
  it("returns true for an announcement addressed to the receiver", () => {
    const announcement = generateStealthAddress(meta, EPHEMERAL);
    expect(
      checkStealthAddress({
        ephemeralPublicKey: announcement.ephemeralPublicKey,
        spendingPublicKey: spendingPub,
        viewingPrivateKey: VIEWING,
        stealthAddress: announcement.stealthAddress,
        viewTag: announcement.viewTag,
      })
    ).toBe(true);
  });

  it("fast-rejects on a wrong view tag", () => {
    const announcement = generateStealthAddress(meta, EPHEMERAL);
    expect(
      checkStealthAddress({
        ephemeralPublicKey: announcement.ephemeralPublicKey,
        spendingPublicKey: spendingPub,
        viewingPrivateKey: VIEWING,
        stealthAddress: announcement.stealthAddress,
        viewTag: (announcement.viewTag + 1) % 256,
      })
    ).toBe(false);
  });

  it("returns false for a different receiver's viewing key", () => {
    const announcement = generateStealthAddress(meta, EPHEMERAL);
    expect(
      checkStealthAddress({
        ephemeralPublicKey: announcement.ephemeralPublicKey,
        spendingPublicKey: spendingPub,
        viewingPrivateKey: OTHER_VIEWING,
        stealthAddress: announcement.stealthAddress,
      })
    ).toBe(false);
  });
});

describe("stealth input validation", () => {
  it("createAnnouncementMetadata rejects an out-of-range view tag", () => {
    expect(() => createAnnouncementMetadata(256, "0x00")).toThrow();
    expect(() => createAnnouncementMetadata(-1, "0x00")).toThrow();
    expect(() => createAnnouncementMetadata(3.5, "0x00")).toThrow();
  });

  it("createStealthMetaAddress rejects non-compressed public keys", () => {
    const uncompressed = ("0x04" + "11".repeat(64)) as Hex;
    expect(() => createStealthMetaAddress(uncompressed, viewingPub)).toThrow();
  });

  it("parseStealthMetaAddress rejects a wrong-length input", () => {
    expect(() => parseStealthMetaAddress("0x1234" as Hex)).toThrow();
  });
});
