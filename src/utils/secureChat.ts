import { MessageType } from "@openim/wasm-client-sdk";
import type { MessageItem } from "@openim/wasm-client-sdk/lib/types/entity";
import { t } from "i18next";

const SECURE_MESSAGE_TYPE = "secure_text_v1";
const SECURE_MESSAGE_ALGORITHM = "AES-256-GCM";
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 210000;
const PBKDF2_HASH = "SHA-256";
const BLOCKED_WORDS = ["暴力", "违禁"];

export type SecurePayload = {
  type: "secure_text_v1";
  alg: "AES-256-GCM";
  iv: string;
  ciphertext: string;
  salt: string;
  timestamp: number;
  burnAfterRead?: boolean;
};

type SecureChatErrorCode =
  | "SECURE_CHAT_MISSING_PSK"
  | "SECURE_CHAT_BLOCKED_CONTENT"
  | "SECURE_CHAT_UNAVAILABLE";

export class SecureChatError extends Error {
  constructor(
    public readonly code: SecureChatErrorCode,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "SecureChatError";
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const getSubtleCrypto = () => {
  if (!globalThis.crypto?.subtle) {
    throw new SecureChatError("SECURE_CHAT_UNAVAILABLE");
  }
  return globalThis.crypto.subtle;
};

const getSecureChatPassword = () => {
  const password = import.meta.env.VITE_E2EE_PSK?.trim();
  if (!password) {
    throw new SecureChatError("SECURE_CHAT_MISSING_PSK");
  }
  return password;
};

const randomBytes = (length: number) => globalThis.crypto.getRandomValues(new Uint8Array(length));

const toBase64 = (value: Uint8Array | ArrayBuffer) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
};

const fromBase64 = (value: string) => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
};

const isSecurePayload = (value: unknown): value is SecurePayload => {
  if (!value || typeof value !== "object") {
    return false;
  }

  const payload = value as Record<string, unknown>;
  return (
    payload.type === SECURE_MESSAGE_TYPE &&
    payload.alg === SECURE_MESSAGE_ALGORITHM &&
    typeof payload.iv === "string" &&
    typeof payload.ciphertext === "string" &&
    typeof payload.salt === "string" &&
    typeof payload.timestamp === "number" &&
    (payload.burnAfterRead === undefined || typeof payload.burnAfterRead === "boolean")
  );
};

const parseSecurePayload = (content?: string | null) => {
  if (!content) {
    return null;
  }

  try {
    const payload = JSON.parse(content);
    return isSecurePayload(payload) ? payload : null;
  } catch {
    return null;
  }
};

const withTextContent = (message: MessageItem, content: string): MessageItem => ({
  ...message,
  textElem: {
    ...message.textElem,
    content,
  },
});

export const isSecureChatEnabled = () => Boolean(import.meta.env.VITE_E2EE_PSK?.trim());

export const getSecureChatErrorMessage = (error: unknown) => {
  if (!(error instanceof SecureChatError)) {
    return t("toast.accessFailed");
  }

  switch (error.code) {
    case "SECURE_CHAT_MISSING_PSK":
      return t("toast.secureChatMissingConfig");
    case "SECURE_CHAT_BLOCKED_CONTENT":
      return t("toast.secureMessageBlocked");
    case "SECURE_CHAT_UNAVAILABLE":
      return t("toast.secureChatUnavailable");
    default:
      return t("toast.accessFailed");
  }
};

export const validateSensitiveWords = (plaintext: string) => {
  const hitWord = BLOCKED_WORDS.find((word) => plaintext.includes(word));
  if (hitWord) {
    throw new SecureChatError("SECURE_CHAT_BLOCKED_CONTENT", hitWord);
  }
};

export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
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
}

export async function encrypt(
  plaintext: string,
  key: CryptoKey,
  salt: Uint8Array,
  burnAfterRead?: boolean,
): Promise<SecurePayload> {
  const subtle = getSubtleCrypto();
  const iv = randomBytes(IV_LENGTH);
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encoder.encode(plaintext),
  );

  return {
    type: SECURE_MESSAGE_TYPE,
    alg: SECURE_MESSAGE_ALGORITHM,
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    salt: toBase64(salt),
    timestamp: Date.now(),
    ...(burnAfterRead === undefined ? {} : { burnAfterRead }),
  };
}

export async function decrypt(payload: SecurePayload, key: CryptoKey): Promise<string> {
  const subtle = getSubtleCrypto();
  const plaintext = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: fromBase64(payload.iv),
    },
    key,
    fromBase64(payload.ciphertext),
  );

  return decoder.decode(plaintext);
}

export async function encryptMessage(
  plaintext: string,
  options?: {
    burnAfterRead?: boolean;
  },
): Promise<string> {
  validateSensitiveWords(plaintext);
  const salt = randomBytes(SALT_LENGTH);
  const key = await deriveKey(getSecureChatPassword(), salt);
  const payload = await encrypt(plaintext, key, salt, options?.burnAfterRead);
  return JSON.stringify(payload);
}

export async function decryptMessage(message: MessageItem): Promise<string | null> {
  if (message.contentType !== MessageType.TextMessage) {
    return null;
  }

  const payload = parseSecurePayload(message.textElem?.content);
  if (!payload) {
    return null;
  }

  const key = await deriveKey(getSecureChatPassword(), fromBase64(payload.salt));
  return decrypt(payload, key);
}

export const isSecureTextMessage = (message: MessageItem) =>
  message.contentType === MessageType.TextMessage &&
  Boolean(parseSecurePayload(message.textElem?.content));

export async function normalizeMessageForRender(
  message: MessageItem,
): Promise<MessageItem> {
  if (!isSecureTextMessage(message)) {
    return message;
  }

  try {
    const plaintext = await decryptMessage(message);
    return withTextContent(message, plaintext ?? "");
  } catch {
    return withTextContent(message, t("placeholder.secureDecryptFailed"));
  }
}
