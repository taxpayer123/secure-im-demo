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
  const identityMessages = messages.filter(
    (message) => getSecureControlCustomType(message) === CustomType.SecureIdentity,
  );
  const sessionInviteMessages = messages.filter(
    (message) => getSecureControlCustomType(message) === CustomType.SecureSessionInvite,
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
  if (!peerIdentity || peerIdentity.fingerprint !== sessionPayload.fingerprint) {
    return true;
  }

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

  if (shouldActivateSessionInvite(sessionStore, sessionPayload)) {
    setActiveSession(nextSessionStore, sessionId);
  }

  sessions[conversationKey] = nextSessionStore;
  await saveSessions(sessions);
  emit("SECURE_SESSION_UPDATED");
  return true;
};
