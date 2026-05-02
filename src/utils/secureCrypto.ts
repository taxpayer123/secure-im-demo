const PBKDF2_ITERATIONS = 210000;
const PBKDF2_HASH = "SHA-256";

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export const getSubtleCrypto = () => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  return globalThis.crypto.subtle;
};

export const randomBytes = (length: number) =>
  globalThis.crypto.getRandomValues(new Uint8Array(length));

export const toBase64 = (value: Uint8Array | ArrayBuffer) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
};

export const fromBase64 = (value: string) => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
};

export const derivePasswordKey = async (password: string, salt: Uint8Array) => {
  const subtle = getSubtleCrypto();
  const baseKey = await subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"],
  );
};

export const importAesKey = async (rawKey: Uint8Array) =>
  getSubtleCrypto().importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);

export const hkdfToAesKey = async (
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: string,
) => {
  const subtle = getSubtleCrypto();
  const baseKey = await subtle.importKey("raw", inputKeyMaterial, "HKDF", false, [
    "deriveKey",
  ]);

  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode(info),
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"],
  );
};

export const sha256Hex = async (value: string) => {
  const digest = await getSubtleCrypto().digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (item) =>
    item.toString(16).padStart(2, "0"),
  ).join("");
};
