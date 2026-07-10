import type { UnlockSecretSource } from "../types";

const encoder = new TextEncoder();

type PrfExtensionResults = AuthenticationExtensionsClientOutputs & {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer };
  };
};

export interface WebAuthnPrfRegistration {
  credentialId: string;
  prfSupported: boolean;
  /** Present when the authenticator returned PRF output during creation. */
  unlockSource?: UnlockSecretSource;
}

function assertWebAuthn(): void {
  if (
    typeof window === "undefined" ||
    typeof PublicKeyCredential === "undefined" ||
    !navigator.credentials
  ) {
    throw new Error("WebAuthn passkeys are unavailable in this environment");
  }
}

function encodeCredentialId(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

function decodeCredentialId(value: string): Uint8Array {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function prfSalt(appName: string): Promise<Uint8Array> {
  if (!appName.trim()) throw new Error("appName must not be empty");
  // Permanent domain commitment. Never change this prefix or encoding.
  const input = encoder.encode(`derivault:webauthn-prf:v1:${appName}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

export function createWebAuthnPrfUnlockSource({
  appName,
  credentialId,
}: {
  appName: string;
  credentialId?: string;
}): UnlockSecretSource {
  return {
    accountId: credentialId ?? "webauthn-discoverable",
    async getUnlockSecret() {
      assertWebAuthn();
      const salt = await prfSalt(appName);
      const publicKey = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: credentialId
          ? [{ id: decodeCredentialId(credentialId), type: "public-key" as const }]
          : undefined,
        userVerification: "required" as const,
        timeout: 60_000,
        extensions: { prf: { eval: { first: salt } } },
      } as PublicKeyCredentialRequestOptions;
      const credential = (await navigator.credentials.get({ publicKey })) as
        | PublicKeyCredential
        | null;
      if (!credential) throw new Error("Passkey unlock was cancelled");
      const extensionResults =
        credential.getClientExtensionResults() as PrfExtensionResults;
      const first = extensionResults.prf?.results?.first;
      if (!first) {
        throw new Error("This passkey does not support the WebAuthn PRF extension");
      }
      const bytes = new Uint8Array(first);
      if (bytes.byteLength !== 32) {
        throw new Error("WebAuthn PRF returned an invalid secret length");
      }
      return { bytes, source: "webauthn-prf-v1" };
    },
  };
}

export async function registerPasskeyWithPrf({
  appName,
  userName,
}: {
  appName: string;
  userName: string;
}): Promise<WebAuthnPrfRegistration> {
  assertWebAuthn();
  if (!userName.trim()) throw new Error("userName must not be empty");
  const salt = await prfSalt(appName);
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: appName, id: window.location.hostname },
    user: {
      id: crypto.getRandomValues(new Uint8Array(32)),
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" as const },
      { alg: -257, type: "public-key" as const },
    ],
    authenticatorSelection: {
      residentKey: "required" as const,
      requireResidentKey: true,
      userVerification: "required" as const,
    },
    attestation: "none" as const,
    timeout: 60_000,
    extensions: { prf: { eval: { first: salt } } },
  } as PublicKeyCredentialCreationOptions;
  const credential = (await navigator.credentials.create({ publicKey })) as
    | PublicKeyCredential
    | null;
  if (!credential) throw new Error("Passkey creation was cancelled");
  const extensionResults =
    credential.getClientExtensionResults() as PrfExtensionResults;
  const credentialId = encodeCredentialId(new Uint8Array(credential.rawId));
  const first = extensionResults.prf?.results?.first;
  return {
    credentialId,
    prfSupported: extensionResults.prf?.enabled === true || Boolean(first),
    unlockSource: first
      ? {
          accountId: credentialId,
          async getUnlockSecret() {
            return {
              bytes: new Uint8Array(first),
              source: "webauthn-prf-v1",
            };
          },
        }
      : undefined,
  };
}
