import { describe, expect, it } from "vitest";

import { openKeyvault, type UnlockSecretSource } from "../src/index";

const SECRET = Uint8Array.from({ length: 32 }, (_, index) => index);

function source(kind: "eip191-signature-v1" | "webauthn-prf-v1"):
  UnlockSecretSource {
  return {
    accountId: `test:${kind}`,
    async getUnlockSecret() {
      return { bytes: new Uint8Array(SECRET), source: kind };
    },
  };
}

describe("WebAuthn PRF derivation", () => {
  it("matches the wallet EOA golden vector", async () => {
    const keyvault = await openKeyvault(source("webauthn-prf-v1"));
    expect(keyvault.walletEoa).toEqual({
      privateKey:
        "0x57fea2fb55f85248234c9388d86abb9429d0d1eb1b1556011142f98c73092043",
      address: "0x838ec536c450F65ea1Ba66f0e103Db6E97e3E496",
    });
  });

  it("domain-separates PRF and signature sources with identical bytes", async () => {
    const [prf, signature] = await Promise.all([
      openKeyvault(source("webauthn-prf-v1")),
      openKeyvault(source("eip191-signature-v1")),
    ]);
    expect(prf.walletEoa.privateKey).not.toBe(signature.walletEoa.privateKey);
    expect(prf.railgunSeed.mnemonic).not.toBe(signature.railgunSeed.mnemonic);
    expect(prf.stealthMetaAddress).not.toBe(signature.stealthMetaAddress);
  });
});
