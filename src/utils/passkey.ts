import * as localForage from "localforage";

const PASSKEY_RECORDS_KEY = "IM_PASSKEY_RECORDS";
const PASSKEY_RP_NAME = "OpenCorp";
const WEBAUTHN_TIMEOUT = 60000;

export type PasskeyRecord = {
  credentialID: string;
  enabled: boolean;
  boundAt: number;
  transports?: AuthenticatorTransport[];
};

const passkeyStore = localForage.createInstance({
  name: "OpenCorp-Passkey",
});

const getRecords = async () =>
  (await passkeyStore.getItem<Record<string, PasskeyRecord>>(PASSKEY_RECORDS_KEY)) ??
  {};

const setRecords = (records: Record<string, PasskeyRecord>) =>
  passkeyStore.setItem(PASSKEY_RECORDS_KEY, records);

const assertWebAuthnAvailable = () => {
  if (
    !window.isSecureContext ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    throw new Error("Passkey requires a secure context with WebAuthn support");
  }
};

const randomBytes = (length: number) => {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return bytes;
};

const userIDToBuffer = async (userID: string) => {
  const hash = await window.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(userID),
  );
  return new Uint8Array(hash);
};

const arrayBufferToBase64Url = (buffer: ArrayBuffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64UrlToBuffer = (value: string) => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let idx = 0; idx < binary.length; idx += 1) {
    bytes[idx] = binary.charCodeAt(idx);
  }

  return bytes;
};

export const isPasskeySupported = async () => {
  if (
    !window.isSecureContext ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  ) {
    return false;
  }

  const PublicKeyCredentialWithAvailability =
    window.PublicKeyCredential as typeof PublicKeyCredential & {
      isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
    };

  return PublicKeyCredentialWithAvailability.isUserVerifyingPlatformAuthenticatorAvailable
    ? PublicKeyCredentialWithAvailability.isUserVerifyingPlatformAuthenticatorAvailable()
    : true;
};

export const getPasskeyRecord = async (userID: string) => {
  const records = await getRecords();
  return records[userID] ?? null;
};

export const hasEnabledPasskey = async (userID: string) => {
  const record = await getPasskeyRecord(userID);
  return Boolean(record?.enabled);
};

export const registerUserPasskey = async (userID: string, account: string) => {
  assertWebAuthnAvailable();

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: {
        name: PASSKEY_RP_NAME,
      },
      user: {
        id: await userIDToBuffer(userID),
        name: account,
        displayName: account,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required",
      },
      attestation: "none",
      timeout: WEBAUTHN_TIMEOUT,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey registration was canceled");

  const response = credential.response as AuthenticatorAttestationResponse & {
    getTransports?: () => AuthenticatorTransport[];
  };
  const records = await getRecords();
  records[userID] = {
    credentialID: arrayBufferToBase64Url(credential.rawId),
    enabled: true,
    boundAt: Date.now(),
    transports: response.getTransports?.(),
  };
  await setRecords(records);
};

export const verifyUserPasskey = async (userID: string) => {
  assertWebAuthnAvailable();

  const record = await getPasskeyRecord(userID);
  if (!record?.enabled) return false;

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [
        {
          id: base64UrlToBuffer(record.credentialID),
          type: "public-key",
          transports: record.transports,
        },
      ],
      userVerification: "required",
      timeout: WEBAUTHN_TIMEOUT,
    },
  });

  return Boolean(assertion);
};

export const removePasskeyRecord = async (userID: string) => {
  const records = await getRecords();
  delete records[userID];
  await setRecords(records);
};
