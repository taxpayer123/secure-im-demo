import { MessageType } from "@openim/wasm-client-sdk";
import type {
  ConversationItem,
  MessageItem,
} from "@openim/wasm-client-sdk/lib/types/entity";
import { t } from "i18next";

import {
  decoder,
  encoder,
  fromBase64,
  getSubtleCrypto,
  importAesKey,
  randomBytes,
  toBase64,
} from "./secureCrypto";
import {
  ensureConversationSession,
  getMessageSessionKey,
  getSecureSessionErrorMessage,
  readSessionKeyBytes,
  SecureSessionError,
} from "./secureSession";

const SECURE_MESSAGE_TYPE = "secure_text_v1";
const SECURE_MESSAGE_ALGORITHM = "AES-256-GCM";
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const BLOCKED_WORDS = ["暴力", "违禁"];

export type SecurePayload = {
  type: "secure_text_v1";
  version?: 2;
  sessionId?: string;
  alg: "AES-256-GCM";
  iv: string;
  ciphertext: string;
  salt: string;
  timestamp: number;
  burnAfterRead?: boolean;
};

type SecureChatErrorCode = "SECURE_CHAT_BLOCKED_CONTENT" | "SECURE_CHAT_UNAVAILABLE";

export class SecureChatError extends Error {
  constructor(public readonly code: SecureChatErrorCode, message?: string) {
    super(message ?? code);
    this.name = "SecureChatError";
  }
}

const isSecurePayload = (value: unknown): value is SecurePayload => {
  if (!value || typeof value !== "object") {
    return false;
  }

  const payload = value as Record<string, unknown>;
  return (
    payload.type === SECURE_MESSAGE_TYPE &&
    (payload.version === undefined || payload.version === 2) &&
    (payload.version !== 2 || typeof payload.sessionId === "string") &&
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

const encryptWithSharedKey = async (
  plaintext: string,
  sharedKey: Uint8Array,
  sessionId: string,
  burnAfterRead?: boolean,
): Promise<SecurePayload> => {
  const subtle = getSubtleCrypto();
  const iv = randomBytes(IV_LENGTH);
  const salt = randomBytes(SALT_LENGTH);
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    await importAesKey(sharedKey),
    encoder.encode(plaintext),
  );

  return {
    type: SECURE_MESSAGE_TYPE,
    version: 2,
    sessionId,
    alg: SECURE_MESSAGE_ALGORITHM,
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    salt: toBase64(salt),
    timestamp: Date.now(),
    ...(burnAfterRead === undefined ? {} : { burnAfterRead }),
  };
};

const decryptWithSharedKey = async (payload: SecurePayload, sharedKey: Uint8Array) => {
  const subtle = getSubtleCrypto();
  const plaintext = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: fromBase64(payload.iv),
    },
    await importAesKey(sharedKey),
    fromBase64(payload.ciphertext),
  );

  return decoder.decode(plaintext);
};

export const getSecureChatErrorMessage = (error: unknown) => {
  if (error instanceof SecureSessionError) {
    return getSecureSessionErrorMessage(error);
  }

  if (!(error instanceof SecureChatError)) {
    return t("toast.accessFailed");
  }

  switch (error.code) {
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

export async function encryptMessage(
  plaintext: string,
  conversation?: ConversationItem,
  options?: {
    burnAfterRead?: boolean;
  },
): Promise<string> {
  validateSensitiveWords(plaintext);
  if (!globalThis.crypto?.subtle) {
    throw new SecureChatError("SECURE_CHAT_UNAVAILABLE");
  }

  const session = await ensureConversationSession(conversation);
  const payload = await encryptWithSharedKey(
    plaintext,
    readSessionKeyBytes(session),
    session.sessionId,
    options?.burnAfterRead,
  );
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

  const session = await getMessageSessionKey(message, payload.sessionId);
  if (!session) {
    throw new SecureSessionError(
      payload.sessionId ? "SECURE_SESSION_MISSING_KEY" : "SECURE_SESSION_NOT_READY",
    );
  }

  return decryptWithSharedKey(payload, readSessionKeyBytes(session));
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
  } catch (error) {
    if (
      error instanceof SecureSessionError &&
      error.code === "SECURE_SESSION_MISSING_KEY"
    ) {
      return withTextContent(message, t("placeholder.secureSessionMissingKey"));
    }
    return withTextContent(message, t("placeholder.secureDecryptFailed"));
  }
}
