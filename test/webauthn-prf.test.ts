import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createWebAuthnPrfUnlockSource,
  decodeCredentialId,
  encodeCredentialId,
  prfSalt,
  registerPasskeyWithPrf,
} from "../src/sources/webauthn-prf";

const HOST = "wallet.example.com";
const APP = "Rivo";

let getMock: ReturnType<typeof vi.fn>;
let createMock: ReturnType<typeof vi.fn>;

function prfBuffer(length: number, fill = 7): ArrayBuffer {
  return new Uint8Array(length).fill(fill).buffer;
}

beforeEach(() => {
  getMock = vi.fn();
  createMock = vi.fn();
  vi.stubGlobal("window", { location: { hostname: HOST } });
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  vi.stubGlobal("navigator", { credentials: { get: getMock, create: createMock } });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("createWebAuthnPrfUnlockSource (unlock)", () => {
  it("reads a 32-byte PRF secret and wires the get() request correctly", async () => {
    const first = new Uint8Array(32).fill(7);
    getMock.mockResolvedValue({
      rawId: new Uint8Array([9, 9]).buffer,
      getClientExtensionResults: () => ({ prf: { results: { first: first.buffer } } }),
    });
    const credentialId = encodeCredentialId(new Uint8Array([0xaa, 0xbb, 0xcc]));

    const source = createWebAuthnPrfUnlockSource({ appName: APP, credentialId });
    expect(source.accountId).toBe(credentialId);

    const secret = await source.getUnlockSecret();
    expect(secret.source).toBe("webauthn-prf-v1");
    expect(secret.bytes).toEqual(first);

    const opts = getMock.mock.calls[0]![0].publicKey;
    expect(opts.userVerification).toBe("required");
    expect(opts.rpId).toBe(HOST);
    expect(opts.extensions.prf.eval.first).toEqual(await prfSalt(APP));
    expect(opts.allowCredentials[0].id).toEqual(decodeCredentialId(credentialId));
    expect(opts.allowCredentials[0].type).toBe("public-key");
  });

  it("requests a discoverable credential when no credentialId is given", async () => {
    getMock.mockResolvedValue({
      rawId: new Uint8Array([1]).buffer,
      getClientExtensionResults: () => ({ prf: { results: { first: prfBuffer(32) } } }),
    });
    const source = createWebAuthnPrfUnlockSource({ appName: APP });
    expect(source.accountId).toBe("webauthn-discoverable");
    await source.getUnlockSecret();
    expect(getMock.mock.calls[0]![0].publicKey.allowCredentials).toBeUndefined();
  });

  it("throws when the authenticator returns no PRF output", async () => {
    getMock.mockResolvedValue({
      rawId: new Uint8Array([1]).buffer,
      getClientExtensionResults: () => ({}),
    });
    await expect(
      createWebAuthnPrfUnlockSource({ appName: APP }).getUnlockSecret()
    ).rejects.toThrow(/PRF extension/);
  });

  it("rejects a PRF secret that is not exactly 32 bytes", async () => {
    getMock.mockResolvedValue({
      rawId: new Uint8Array([1]).buffer,
      getClientExtensionResults: () => ({ prf: { results: { first: prfBuffer(31) } } }),
    });
    await expect(
      createWebAuthnPrfUnlockSource({ appName: APP }).getUnlockSecret()
    ).rejects.toThrow(/invalid secret length/);
  });

  it("throws when the passkey prompt is cancelled", async () => {
    getMock.mockResolvedValue(null);
    await expect(
      createWebAuthnPrfUnlockSource({ appName: APP }).getUnlockSecret()
    ).rejects.toThrow(/cancelled/);
  });

  it("throws when WebAuthn is unavailable", async () => {
    vi.stubGlobal("window", undefined);
    await expect(
      createWebAuthnPrfUnlockSource({ appName: APP }).getUnlockSecret()
    ).rejects.toThrow(/unavailable/);
  });
});

describe("registerPasskeyWithPrf (create)", () => {
  function stubCreate(prf: unknown, rawId = new Uint8Array([1, 2, 3, 4, 5])) {
    createMock.mockResolvedValue({
      rawId: rawId.buffer,
      getClientExtensionResults: () => ({ prf }),
    });
    return rawId;
  }

  it("returns a usable unlock source when a 32-byte PRF secret is present", async () => {
    const first = new Uint8Array(32).fill(3);
    const rawId = stubCreate({ enabled: true, results: { first: first.buffer } });

    const reg = await registerPasskeyWithPrf({ appName: APP, userName: "a@b.com" });
    expect(reg.prfSupported).toBe(true);
    expect(reg.credentialId).toBe(encodeCredentialId(rawId));
    expect(reg.unlockSource).toBeDefined();

    const secret = await reg.unlockSource!.getUnlockSecret();
    expect(secret.source).toBe("webauthn-prf-v1");
    expect(secret.bytes).toEqual(first);

    const opts = createMock.mock.calls[0]![0].publicKey;
    expect(opts.authenticatorSelection.residentKey).toBe("required");
    expect(opts.authenticatorSelection.userVerification).toBe("required");
    expect(opts.extensions.prf.eval.first).toEqual(await prfSalt(APP));
  });

  it("reports unsupported and no unlock source when PRF is absent", async () => {
    stubCreate({ enabled: false });
    const reg = await registerPasskeyWithPrf({ appName: APP, userName: "a@b.com" });
    expect(reg.prfSupported).toBe(false);
    expect(reg.unlockSource).toBeUndefined();
  });

  it("does NOT build an unlock source from a non-32-byte create-time PRF", async () => {
    // Guards the asymmetry with the get() path: a non-conformant authenticator
    // must not derive keys at registration that a later get() unlock rejects.
    stubCreate({ enabled: true, results: { first: prfBuffer(64) } });
    const reg = await registerPasskeyWithPrf({ appName: APP, userName: "a@b.com" });
    expect(reg.prfSupported).toBe(true);
    expect(reg.unlockSource).toBeUndefined();
  });

  it("rejects an empty userName", async () => {
    await expect(
      registerPasskeyWithPrf({ appName: APP, userName: "   " })
    ).rejects.toThrow(/userName/);
  });
});

describe("prfSalt", () => {
  it("is stable per appName and separates distinct appNames", async () => {
    expect(await prfSalt("App A")).toEqual(await prfSalt("App A"));
    expect(await prfSalt("App A")).not.toEqual(await prfSalt("App B"));
  });

  it("rejects an empty or whitespace appName", async () => {
    await expect(prfSalt("")).rejects.toThrow(/appName/);
    await expect(prfSalt("   ")).rejects.toThrow(/appName/);
  });
});

describe("credential id base64url round-trip", () => {
  it("round-trips every length class and emits url-safe output", () => {
    for (const length of [0, 1, 2, 3, 16, 17, 18, 19, 32, 33]) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) bytes[i] = (i * 7 + 0x3e) & 0xff;
      const encoded = encodeCredentialId(bytes);
      expect(encoded).not.toMatch(/[=+/]/);
      expect(decodeCredentialId(encoded)).toEqual(bytes);
    }
  });

  it("maps the +/ base64 chars to the -_ url-safe alphabet", () => {
    // 0xff,0xff,0xff -> base64 "////" -> base64url "____"
    expect(encodeCredentialId(new Uint8Array([0xff, 0xff, 0xff]))).toBe("____");
    expect(decodeCredentialId("____")).toEqual(new Uint8Array([0xff, 0xff, 0xff]));
    // 0xfb,0xff,0xbf -> base64 "+/+/" -> base64url "-_-_"
    expect(encodeCredentialId(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe("-_-_");
    expect(decodeCredentialId("-_-_")).toEqual(new Uint8Array([0xfb, 0xff, 0xbf]));
  });
});
