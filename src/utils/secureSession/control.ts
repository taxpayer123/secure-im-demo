import { handleGroupSessionInvite } from "./groupControl";
import type { MessageItem } from "@openim/wasm-client-sdk/lib/types/entity";

import { CustomType } from "@/constants";
import { emit } from "@/utils/events";

import { fromBase64, getSubtleCrypto, toBase64 } from "../secureCrypto";
import {
  buildSessionSigningText,
  buildIdentitySigningText,
  deriveWrapKey,
  getLegacySessionId,
  verifyText,
} from "./crypto";
import {
  buildIdentityPayload,
  ensureLocalIdentity,
  resolveSelfUserID,
  storePeerIdentity,
} from "./identity";
import { getSecureCustomPayload, sendCustomSignal } from "./signal";
import {
  getConversationKey,
  getStoredPeerIdentities,
  getStoredSessions,
  saveSessions,
  setActiveSession,
} from "./store";
import type {
  ConversationSessionRecord,
  SecureIdentityPayload,
  SecureSessionInvitePayload,
  SessionRecord,
} from "./types";

export const isSecureControlMessage = (message: MessageItem) =>
  Boolean(getSecureCustomPayload(message));

const getSecureControlCustomType = (message: MessageItem) =>
  getSecureCustomPayload(message)?.customType;

export const handleSecureControlMessages = async (messages: MessageItem[]) => {
  // 先落身份消息，再处理会话邀请，避免 invite 先到时本地还没有可用的对端公钥。
  const identityMessages = messages.filter(
    (message) => getSecureControlCustomType(message) === CustomType.SecureIdentity,
  );
  const sessionInviteMessages = messages.filter(
    (message) => getSecureControlCustomType(message) === CustomType.SecureSessionInvite,
  );
  const groupSessionInviteMessages = messages.filter(
    (message) => getSecureControlCustomType(message) === CustomType.SecureGroupSessionInvite,
  );

  const handleControlMessage = async (message: MessageItem) => {
    try {
      await handleSecureControlMessage(message);
    } catch (error) {
      console.error(error);
    }
  };

  for (const message of identityMessages) {
    await handleControlMessage(message);
  }
  for (const message of sessionInviteMessages) {
    await handleControlMessage(message);
  }
  for (const message of groupSessionInviteMessages) {
    await handleControlMessage(message);
  }
};

const shouldIgnoreSessionInvite = (
  existingSession: SessionRecord | undefined,
  incomingPayload: SecureSessionInvitePayload,
) =>
  Boolean(
    existingSession?.inviteTimestamp &&
      incomingPayload.timestamp <= existingSession.inviteTimestamp,
  );

const shouldActivateSessionInvite = (
  sessionStore: ConversationSessionRecord | undefined,
  incomingPayload: SecureSessionInvitePayload,
) => {
  if (!sessionStore?.activeSessionId) {
    return true;
  }

  const activeSession = sessionStore.sessions[sessionStore.activeSessionId];
  return (
    !activeSession?.inviteTimestamp ||
    incomingPayload.timestamp >= activeSession.inviteTimestamp
  );
};

export const handleSecureControlMessage = async (message: MessageItem) => {
  const payload = getSecureCustomPayload(message);
  if (!payload || !payload.data) {
    return false;
  }

  const localIdentity = await ensureLocalIdentity();
  if (payload.customType === CustomType.SecureIdentity) {
    const identityPayload = payload.data as SecureIdentityPayload;
    // 身份广播自带签名公钥，先验证“这把公钥是否真的认可这份身份声明”。
    const verified = await verifyText(
      identityPayload.signingPublicKey,
      buildIdentitySigningText({
        type: identityPayload.type,
        userID: identityPayload.userID,
        fingerprint: identityPayload.fingerprint,
        agreementPublicKey: identityPayload.agreementPublicKey,
        signingPublicKey: identityPayload.signingPublicKey,
        timestamp: identityPayload.timestamp,
        needReply: identityPayload.needReply,
        isReply: identityPayload.isReply,
      }),
      identityPayload.signature,
    );
    if (!verified) {
      return true;
    }

    await storePeerIdentity(identityPayload);
    if (identityPayload.needReply && !identityPayload.isReply) {
      // 对端显式请求回包时，补发本端身份，完成最基础的双向身份同步。
      await sendCustomSignal(
        identityPayload.userID,
        CustomType.SecureIdentity,
        await buildIdentityPayload(localIdentity, { isReply: true }),
      );
    }
    return true;
  }

  const sessionPayload = payload.data as SecureSessionInvitePayload;
  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[sessionPayload.userID];
  // invite 只能接受来自当前已信任身份的消息，避免陌生公钥直接注入会话。
  if (!peerIdentity || peerIdentity.fingerprint !== sessionPayload.fingerprint) {
    return true;
  }

  // 会话参数由已保存的签名公钥兜底验签，防止 wrapped key 被篡改。
  const verified = await verifyText(
    peerIdentity.signingPublicKey,
    buildSessionSigningText({
      type: sessionPayload.type,
      sessionId: sessionPayload.sessionId,
      userID: sessionPayload.userID,
      fingerprint: sessionPayload.fingerprint,
      ephemeralPublicKey: sessionPayload.ephemeralPublicKey,
      wrappedSessionKey: sessionPayload.wrappedSessionKey,
      iv: sessionPayload.iv,
      salt: sessionPayload.salt,
      timestamp: sessionPayload.timestamp,
    }),
    sessionPayload.signature,
  );
  if (!verified) {
    return true;
  }

  // 只有持有本端长期 ECDH 私钥的一方才能解出 invite 里包装过的 session key。
  const wrapKey = await deriveWrapKey(
    localIdentity.agreementPrivateKey,
    sessionPayload.ephemeralPublicKey,
    fromBase64(sessionPayload.salt),
  );
  let sessionKeyBuffer: ArrayBuffer;
  try {
    sessionKeyBuffer = await getSubtleCrypto().decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64(sessionPayload.iv),
      },
      wrapKey,
      fromBase64(sessionPayload.wrappedSessionKey),
    );
  } catch (error) {
    console.error(error);
    return true;
  }

  const selfUserID = await resolveSelfUserID();
  const conversationKey = getConversationKey(selfUserID, sessionPayload.userID);
  const sessionId =
    sessionPayload.sessionId ||
    `${getLegacySessionId(conversationKey)}_${sessionPayload.timestamp}`;
  const sessions = await getStoredSessions();
  const sessionStore = sessions[conversationKey];
  // 同一 sessionId 只接受更新的 invite，避免旧消息回放覆盖新密钥。
  if (shouldIgnoreSessionInvite(sessionStore?.sessions[sessionId], sessionPayload)) {
    return true;
  }

  const nextSessionStore: ConversationSessionRecord = sessionStore ?? {
    conversationKey,
    peerUserID: sessionPayload.userID,
    sessions: {},
  };
  nextSessionStore.sessions[sessionId] = {
    sessionId,
    conversationKey,
    peerUserID: sessionPayload.userID,
    peerFingerprint: sessionPayload.fingerprint,
    sessionKey: toBase64(sessionKeyBuffer),
    active: false,
    createdByUserID: sessionPayload.userID,
    inviteTimestamp: sessionPayload.timestamp,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  // 只有在当前没有激活 session，或当前 invite 更新时，才切换到新会话。
  if (shouldActivateSessionInvite(sessionStore, sessionPayload)) {
    setActiveSession(nextSessionStore, sessionId);
  }

  sessions[conversationKey] = nextSessionStore;
  await saveSessions(sessions);
  emit("SECURE_SESSION_UPDATED");
  return true;
};
