import {
  encoder,
  fromBase64,
  getSubtleCrypto,
  hkdfToAesKey,
  randomBytes,
  sha256Hex,
  toBase64,
} from "../secureCrypto";

import { WRAP_INFO } from "./constants";
import type { SecureIdentityPayload, SecureSessionInvitePayload } from "./types";

const toBase64Url = (bytes: Uint8Array) =>
  toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const createSessionId = () => `sess_${toBase64Url(randomBytes(16))}`;

export const getLegacySessionId = (conversationKey: string) =>
  `legacy_${conversationKey}`;

export const buildIdentitySigningText = (
  payload: Omit<SecureIdentityPayload, "signature">,
) =>
  JSON.stringify({
    type: payload.type,
    userID: payload.userID,
    fingerprint: payload.fingerprint,
    agreementPublicKey: payload.agreementPublicKey,
    signingPublicKey: payload.signingPublicKey,
    timestamp: payload.timestamp,
    needReply: payload.needReply ?? false,
    isReply: payload.isReply ?? false,
  });

export const buildSessionSigningText = (
  payload: Omit<SecureSessionInvitePayload, "signature">,
) =>
  JSON.stringify({
    type: payload.type,
    ...(payload.sessionId ? { sessionId: payload.sessionId } : {}),
    userID: payload.userID,
    fingerprint: payload.fingerprint,
    ephemeralPublicKey: payload.ephemeralPublicKey,
    wrappedSessionKey: payload.wrappedSessionKey,
    iv: payload.iv,
    salt: payload.salt,
    timestamp: payload.timestamp,
  });

const importAgreementPrivateKey = async (jwk: JsonWebKey) =>
  getSubtleCrypto().importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

const importAgreementPublicKey = async (jwk: JsonWebKey) =>
  getSubtleCrypto().importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

const importSigningPrivateKey = async (jwk: JsonWebKey) =>
  getSubtleCrypto().importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );

const importSigningPublicKey = async (jwk: JsonWebKey) =>
  getSubtleCrypto().importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );

export const signText = async (signingPrivateKey: JsonWebKey, text: string) => {
  const signature = await getSubtleCrypto().sign(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPrivateKey(signingPrivateKey),
    encoder.encode(text),
  );

  return toBase64(signature);
};

export const verifyText = async (
  signingPublicKey: JsonWebKey,
  text: string,
  signature: string,
) =>
  getSubtleCrypto().verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPublicKey(signingPublicKey),
    fromBase64(signature),
    encoder.encode(text),
  );

export const exportFingerprint = async (
  userID: string,
  agreementPublicKey: JsonWebKey,
  signingPublicKey: JsonWebKey,
) => {
  const fingerprint = await sha256Hex(
    JSON.stringify({
      userID,
      agreementPublicKey,
      signingPublicKey,
    }),
  );

  return fingerprint.slice(0, 16).toUpperCase();
};

export const deriveWrapKey = async (
  privateKey: JsonWebKey,
  publicKey: JsonWebKey,
  salt: Uint8Array,
) => {
  const sharedSecret = await getSubtleCrypto().deriveBits(
    {
      name: "ECDH",
      public: await importAgreementPublicKey(publicKey),
    },
    await importAgreementPrivateKey(privateKey),
    256,
  );

  return hkdfToAesKey(new Uint8Array(sharedSecret), salt, WRAP_INFO);
};
