import * as localForage from "localforage";

const MFA_RECORDS_KEY = "IM_MFA_RECORDS";
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type MfaRecord = {
  secret: string;
  enabled: boolean;
  boundAt: number;
};

const mfaStore = localForage.createInstance({
  name: "OpenCorp-MFA",
});

const getSubtleCrypto = () => {
  if (!window.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  return window.crypto.subtle;
};

const getRecords = async () =>
  (await mfaStore.getItem<Record<string, MfaRecord>>(MFA_RECORDS_KEY)) ?? {};

const setRecords = (records: Record<string, MfaRecord>) =>
  mfaStore.setItem(MFA_RECORDS_KEY, records);

const normalizeCode = (code: string) => code.replace(/\D/g, "").slice(0, TOTP_DIGITS);

const base32Decode = (secret: string) => {
  const cleanSecret = secret.replace(/=|\s/g, "").toUpperCase();
  let bits = "";
  const bytes: number[] = [];

  for (const char of cleanSecret) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) throw new Error("Invalid MFA secret");
    bits += value.toString(2).padStart(5, "0");
  }

  for (let idx = 0; idx + 8 <= bits.length; idx += 8) {
    bytes.push(parseInt(bits.slice(idx, idx + 8), 2));
  }

  return new Uint8Array(bytes);
};

const counterToBuffer = (counter: number) => {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;

  view.setUint32(0, high);
  view.setUint32(4, low);

  return buffer;
};

const generateTotpAt = async (secret: string, counter: number) => {
  const key = await getSubtleCrypto().importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await getSubtleCrypto().sign("HMAC", key, counterToBuffer(counter)),
  );
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
};

export const generateMfaSecret = () => {
  const bytes = new Uint8Array(20);
  window.crypto.getRandomValues(bytes);

  let bits = "";
  let secret = "";
  bytes.forEach((byte) => {
    bits += byte.toString(2).padStart(8, "0");
  });

  for (let idx = 0; idx < bits.length; idx += 5) {
    const chunk = bits.slice(idx, idx + 5).padEnd(5, "0");
    secret += BASE32_ALPHABET[parseInt(chunk, 2)];
  }

  return secret;
};

export const getMfaRecord = async (userID: string) => {
  const records = await getRecords();
  return records[userID] ?? null;
};

export const hasEnabledMfa = async (userID: string) => {
  const record = await getMfaRecord(userID);
  return Boolean(record?.enabled);
};

export const setMfaRecord = async (userID: string, secret: string) => {
  const records = await getRecords();
  records[userID] = {
    secret,
    enabled: true,
    boundAt: Date.now(),
  };
  await setRecords(records);
};

export const removeMfaRecord = async (userID: string) => {
  const records = await getRecords();
  delete records[userID];
  await setRecords(records);
};

export const buildMfaOtpAuthUrl = ({
  account,
  issuer = "OpenCorp",
  secret,
}: {
  account: string;
  issuer?: string;
  secret: string;
}) => {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const query = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD),
  });

  return `otpauth://totp/${label}?${query.toString()}`;
};

export const verifyTotp = async (secret: string, code: string) => {
  const normalizedCode = normalizeCode(code);
  if (normalizedCode.length !== TOTP_DIGITS) return false;

  const currentCounter = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const counters = [currentCounter - 1, currentCounter, currentCounter + 1];
  const validCodes = await Promise.all(
    counters.map((counter) => generateTotpAt(secret, counter)),
  );

  return validCodes.includes(normalizedCode);
};

export const verifyUserMfaCode = async (userID: string, code: string) => {
  const record = await getMfaRecord(userID);
  if (!record?.enabled) return false;

  return verifyTotp(record.secret, code);
};
