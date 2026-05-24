import { SessionType } from "@openim/wasm-client-sdk";
import type {
  ConversationItem,
  MessageItem,
} from "@openim/wasm-client-sdk/lib/types/entity";
import { t } from "i18next";

import { CustomType } from "@/constants";
import { emit } from "@/utils/events";

import { fromBase64, getSubtleCrypto, randomBytes, toBase64 } from "../secureCrypto";
import {
  SECURE_SESSION_VERSION,
  SESSION_KEY_LENGTH,
  WRAP_IV_LENGTH,
  WRAP_SALT_LENGTH,
} from "./constants";
import {
  buildSessionSigningText,
  createSessionId,
  deriveWrapKey,
  signText,
} from "./crypto";
import {
  buildIdentityPayload,
  ensureLocalIdentity,
  primeSecureConversation,
  resolveSelfUserID,
} from "./identity";
import { sendCustomSignal } from "./signal";
import {
  getActiveSession,
  getConversationKey,
  getStoredPeerIdentities,
  getStoredSessions,
  savePeerIdentities,
  saveSessions,
} from "./store";
import {
  type ConversationSessionRecord,
  SecureSessionError,
  type SecureSessionInvitePayload,
  type SecureSessionStatus,
  type SessionRecord,
} from "./types";

export const getConversationSecureStatus = async (
  conversation?: ConversationItem,
): Promise<SecureSessionStatus> => {
  if (!conversation) {
    return "not_ready";
  }
  if (conversation.conversationType !== SessionType.Single) {
    return "group_unsupported";
  }

  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[conversation.userID];
  if (!peerIdentity) {
    return "identity_pending";
  }
  if (peerIdentity.keyChangedAt) {
    return "peer_key_changed";
  }

  // “ready” 的判定以当前会话是否有可用激活 session 为准，而不是仅仅拿到过身份。
  const selfUserID = await resolveSelfUserID();
  const conversationKey = getConversationKey(selfUserID, conversation.userID);
  const sessions = await getStoredSessions();
  return getActiveSession(sessions[conversationKey]) ? "ready" : "not_ready";
};

export const getSecureSessionErrorMessage = (error: unknown) => {
  if (!(error instanceof SecureSessionError)) {
    return t("toast.accessFailed");
  }

  switch (error.code) {
    case "SECURE_SESSION_GROUP_UNSUPPORTED":
      return t("toast.secureSessionGroupUnsupported");
    case "SECURE_SESSION_PENDING_IDENTITY":
      return t("toast.secureSessionPendingIdentity");
    case "SECURE_SESSION_PEER_KEY_CHANGED":
      return t("toast.secureSessionPeerKeyChanged");
    case "SECURE_SESSION_NOT_READY":
      return t("toast.secureSessionNotReady");
    case "SECURE_SESSION_MISSING_KEY":
      return t("toast.secureSessionMissingKey");
    case "SECURE_SESSION_CRYPTO_UNAVAILABLE":
      return t("toast.secureChatUnavailable");
    default:
      return t("toast.accessFailed");
  }
};

export const ensureConversationSession = async (conversation?: ConversationItem) => {
  if (!conversation) {
    throw new SecureSessionError("SECURE_SESSION_NOT_READY");
  }
  if (conversation.conversationType !== SessionType.Single) {
    throw new SecureSessionError("SECURE_SESSION_GROUP_UNSUPPORTED");
  }

  const peerUserID = conversation.userID;
  const localIdentity = await ensureLocalIdentity();
  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[peerUserID];
  if (!peerIdentity) {
    // 对端身份未知时先发身份探测，再让调用方感知“还不能发起安全会话”。
    await sendCustomSignal(
      peerUserID,
      CustomType.SecureIdentity,
      await buildIdentityPayload(localIdentity, { needReply: true }),
    );
    throw new SecureSessionError("SECURE_SESSION_PENDING_IDENTITY");
  }
  if (peerIdentity.keyChangedAt) {
    throw new SecureSessionError("SECURE_SESSION_PEER_KEY_CHANGED");
  }

  const conversationKey = getConversationKey(localIdentity.userID, peerUserID);
  const sessions = await getStoredSessions();
  const existingSessionStore = sessions[conversationKey];
  const existingSession = getActiveSession(existingSessionStore);
  if (existingSession?.peerFingerprint === peerIdentity.fingerprint) {
    // 激活 session 和当前对端指纹一致时直接复用，避免重复协商。
    return existingSession;
  }

  const sessionId = createSessionId();
  const sessionKey = randomBytes(SESSION_KEY_LENGTH);
  const subtle = getSubtleCrypto();
  // 发起方生成一次性 ECDH 密钥，与对端长期公钥协商出 wrap key 来包装 session key。
  const ephemeralKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const ephemeralPublicKey = await subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
  const ephemeralPrivateKey = await subtle.exportKey(
    "jwk",
    ephemeralKeyPair.privateKey,
  );
  const salt = randomBytes(WRAP_SALT_LENGTH);
  const wrapKey = await deriveWrapKey(
    ephemeralPrivateKey,
    peerIdentity.agreementPublicKey,
    salt,
  );
  const iv = randomBytes(WRAP_IV_LENGTH);
  const wrappedSessionKey = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    wrapKey,
    sessionKey,
  );

  const payloadWithoutSignature: Omit<SecureSessionInvitePayload, "signature"> = {
    type: SECURE_SESSION_VERSION,
    sessionId,
    userID: localIdentity.userID,
    fingerprint: localIdentity.fingerprint,
    ephemeralPublicKey,
    wrappedSessionKey: toBase64(wrappedSessionKey),
    iv: toBase64(iv),
    salt: toBase64(salt),
    timestamp: Date.now(),
  };
  const payload: SecureSessionInvitePayload = {
    ...payloadWithoutSignature,
    signature: await signText(
      localIdentity.signingPrivateKey,
      buildSessionSigningText(payloadWithoutSignature),
    ),
  };

  // 发出 invite 前先把本地 session 准备好，这样发送成功后 UI 和收发逻辑能立刻切到新密钥。
  const nextSession: SessionRecord = {
    sessionId,
    conversationKey,
    peerUserID,
    peerFingerprint: peerIdentity.fingerprint,
    sessionKey: toBase64(sessionKey),
    active: true,
    createdByUserID: localIdentity.userID,
    inviteTimestamp: payload.timestamp,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  await sendCustomSignal(peerUserID, CustomType.SecureSessionInvite, payload);

  const nextSessionStore: ConversationSessionRecord = existingSessionStore ?? {
    conversationKey,
    peerUserID,
    sessions: {},
  };
  // 同一会话只允许一个激活 session，旧 session 保留用于历史消息解密。
  Object.values(nextSessionStore.sessions).forEach((session) => {
    session.active = false;
  });
  nextSessionStore.sessions[sessionId] = nextSession;
  nextSessionStore.activeSessionId = sessionId;
  sessions[conversationKey] = nextSessionStore;
  await saveSessions(sessions);
  emit("SECURE_SESSION_UPDATED");
  return nextSession;
};

export const resetConversationSecureSession = async (
  conversation?: ConversationItem,
) => {
  if (!conversation) {
    throw new SecureSessionError("SECURE_SESSION_NOT_READY");
  }
  if (conversation.conversationType !== SessionType.Single) {
    throw new SecureSessionError("SECURE_SESSION_GROUP_UNSUPPORTED");
  }

  const peerUserID = conversation.userID;
  const selfUserID = await resolveSelfUserID();
  if (!selfUserID || !peerUserID) {
    throw new SecureSessionError("SECURE_SESSION_NOT_READY");
  }

  const conversationKey = getConversationKey(selfUserID, peerUserID);
  const sessions = await getStoredSessions();
  const sessionStore = sessions[conversationKey];
  if (sessionStore) {
    // reset 先清空当前激活态，避免旧密钥继续被用于新消息。
    sessionStore.activeSessionId = undefined;
    Object.values(sessionStore.sessions).forEach((session) => {
      session.active = false;
    });
  }
  await saveSessions(sessions);

  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[peerUserID];
  if (peerIdentity?.keyChangedAt) {
    // 用户确认重置后，视为重新信任当前对端身份，并重新允许建链。
    const { keyChangedAt, ...trustedPeerIdentity } = peerIdentity;
    peerIdentities[peerUserID] = {
      ...trustedPeerIdentity,
      trustedAt: Date.now(),
      lastSeenAt: Date.now(),
    };
    await savePeerIdentities(peerIdentities);
  }

  emit("SECURE_SESSION_UPDATED");

  if (peerIdentities[peerUserID]) {
    await ensureConversationSession(conversation);
    return;
  }

  await primeSecureConversation(conversation);
};

export const getConversationSessionKey = async (conversation?: ConversationItem) => {
  if (!conversation || conversation.conversationType !== SessionType.Single) {
    return null;
  }
  const selfUserID = await resolveSelfUserID();
  const sessions = await getStoredSessions();
  return (
    getActiveSession(sessions[getConversationKey(selfUserID, conversation.userID)]) ??
    null
  );
};

export const getMessageSessionKey = async (message: MessageItem, sessionId: string) => {
  if (message.sessionType !== SessionType.Single) {
    return null;
  }

  const selfUserID = await resolveSelfUserID();
  const peerUserID = message.sendID === selfUserID ? message.recvID : message.sendID;
  const sessions = await getStoredSessions();
  const sessionStore = sessions[getConversationKey(selfUserID, peerUserID)];
  return sessionStore?.sessions[sessionId] ?? null;
};

export const readSessionKeyBytes = (session: SessionRecord) =>
  fromBase64(session.sessionKey);
