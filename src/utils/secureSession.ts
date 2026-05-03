import { MessageType, SessionType } from "@openim/wasm-client-sdk";
import type {
  ConversationItem,
  MessageItem,
} from "@openim/wasm-client-sdk/lib/types/entity";
import { t } from "i18next";
import * as localForage from "localforage";

import { CustomType } from "@/constants";
import { IMSDK } from "@/layout/MainContentWrap";
import { useUserStore } from "@/store";
import { emit } from "@/utils/events";

import {
  decoder,
  encoder,
  fromBase64,
  getSubtleCrypto,
  hkdfToAesKey,
  randomBytes,
  sha256Hex,
  toBase64,
} from "./secureCrypto";
import { getIMUserID } from "./storage";

localForage.config({
  name: "OpenCorp-Config",
});

const SECURE_IDENTITY_VERSION = "secure_identity_v1";
const SECURE_SESSION_VERSION = "secure_session_invite_v2";
const WRAP_INFO = "openim-secure-session-wrap-v1";
const WRAP_SALT_LENGTH = 16;
const WRAP_IV_LENGTH = 12;
const SESSION_KEY_LENGTH = 32;

const LOCAL_IDENTITY_KEY = "SECURE_LOCAL_IDENTITY_V1";
const PEER_IDENTITY_KEY = "SECURE_PEER_IDENTITIES_V1";
const SESSION_STORE_KEY = "SECURE_SESSION_RECORDS_V1";

export type SecureSessionStatus =
  | "group_unsupported"
  | "not_ready"
  | "identity_pending"
  | "peer_key_changed"
  | "ready";

type LocalIdentityRecord = {
  userID: string;
  fingerprint: string;
  agreementPublicKey: JsonWebKey;
  agreementPrivateKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  signingPrivateKey: JsonWebKey;
  createdAt: number;
};

type PeerIdentityRecord = {
  userID: string;
  fingerprint: string;
  agreementPublicKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  trustedAt: number;
  lastSeenAt: number;
  keyChangedAt?: number;
};

type SessionRecord = {
  sessionId: string;
  conversationKey: string;
  peerUserID: string;
  peerFingerprint: string;
  sessionKey: string;
  active: boolean;
  createdByUserID?: string;
  inviteTimestamp?: number;
  createdAt: number;
  updatedAt: number;
};

type ConversationSessionRecord = {
  conversationKey: string;
  peerUserID: string;
  activeSessionId?: string;
  sessions: Record<string, SessionRecord>;
};

type SecureIdentityPayload = {
  type: "secure_identity_v1";
  userID: string;
  fingerprint: string;
  agreementPublicKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  timestamp: number;
  needReply?: boolean;
  isReply?: boolean;
  signature: string;
};

type SecureSessionInvitePayload = {
  type: "secure_session_invite_v1" | "secure_session_invite_v2";
  sessionId?: string;
  userID: string;
  fingerprint: string;
  ephemeralPublicKey: JsonWebKey;
  wrappedSessionKey: string;
  iv: string;
  salt: string;
  timestamp: number;
  signature: string;
};

export class SecureSessionError extends Error {
  constructor(
    public readonly code:
      | "SECURE_SESSION_GROUP_UNSUPPORTED"
      | "SECURE_SESSION_PENDING_IDENTITY"
      | "SECURE_SESSION_PEER_KEY_CHANGED"
      | "SECURE_SESSION_NOT_READY"
      | "SECURE_SESSION_MISSING_KEY"
      | "SECURE_SESSION_CRYPTO_UNAVAILABLE",
  ) {
    super(code);
    this.name = "SecureSessionError";
  }
}

const getConversationKey = (userID: string, peerUserID: string) =>
  `single:${[userID, peerUserID].sort().join(":")}`;

const toBase64Url = (bytes: Uint8Array) =>
  toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const createSessionId = () => `sess_${toBase64Url(randomBytes(16))}`;

const getLegacySessionId = (conversationKey: string) => `legacy_${conversationKey}`;

const buildIdentitySigningText = (payload: Omit<SecureIdentityPayload, "signature">) =>
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

const buildSessionSigningText = (
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

const getStoredPeerIdentities = async () =>
  (await localForage.getItem<Record<string, PeerIdentityRecord>>(PEER_IDENTITY_KEY)) ??
  {};

const normalizeSessionStoreRecord = (
  conversationKey: string,
  record: ConversationSessionRecord | SessionRecord,
): ConversationSessionRecord => {
  if ("sessions" in record) {
    return record;
  }

  const sessionId = record.sessionId || getLegacySessionId(conversationKey);
  return {
    conversationKey,
    peerUserID: record.peerUserID,
    activeSessionId: sessionId,
    sessions: {
      [sessionId]: {
        ...record,
        sessionId,
        conversationKey,
        active: true,
      },
    },
  };
};

const getStoredSessions = async () => {
  const records =
    (await localForage.getItem<
      Record<string, ConversationSessionRecord | SessionRecord>
    >(SESSION_STORE_KEY)) ?? {};

  return Object.entries(records).reduce<Record<string, ConversationSessionRecord>>(
    (sessionStores, [conversationKey, record]) => ({
      ...sessionStores,
      [conversationKey]: normalizeSessionStoreRecord(conversationKey, record),
    }),
    {},
  );
};

const savePeerIdentities = async (records: Record<string, PeerIdentityRecord>) =>
  localForage.setItem(PEER_IDENTITY_KEY, records);

const saveSessions = async (records: Record<string, ConversationSessionRecord>) =>
  localForage.setItem(SESSION_STORE_KEY, records);

const resolveSelfUserID = async () =>
  useUserStore.getState().selfInfo.userID || ((await getIMUserID()) as string) || "";

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

const signText = async (signingPrivateKey: JsonWebKey, text: string) => {
  const signature = await getSubtleCrypto().sign(
    { name: "ECDSA", hash: "SHA-256" },
    await importSigningPrivateKey(signingPrivateKey),
    encoder.encode(text),
  );

  return toBase64(signature);
};

const verifyText = async (
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

const exportFingerprint = async (
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

const getLocalIdentity = async () =>
  (await localForage.getItem<LocalIdentityRecord>(LOCAL_IDENTITY_KEY)) ?? null;

const saveLocalIdentity = async (record: LocalIdentityRecord) =>
  localForage.setItem(LOCAL_IDENTITY_KEY, record);

const buildCustomMessagePayload = (
  customType: CustomType,
  data: SecureIdentityPayload | SecureSessionInvitePayload,
) =>
  JSON.stringify({
    customType,
    data,
  });

const getSecureCustomPayload = (message: MessageItem) => {
  if (message.contentType !== MessageType.CustomMessage || !message.customElem?.data) {
    return null;
  }

  try {
    const payload = JSON.parse(message.customElem.data) as {
      customType?: number;
      data?: SecureIdentityPayload | SecureSessionInvitePayload;
    };
    if (
      payload.customType !== CustomType.SecureIdentity &&
      payload.customType !== CustomType.SecureSessionInvite
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
};

const sendCustomSignal = async (
  recvID: string,
  customType: CustomType,
  data: SecureIdentityPayload | SecureSessionInvitePayload,
) => {
  const { data: message } = await IMSDK.createCustomMessage({
    data: buildCustomMessagePayload(customType, data),
    extension: "",
    description: "",
  });

  await IMSDK.sendMessage({
    recvID,
    groupID: "",
    message,
  });
};

const storePeerIdentity = async (payload: SecureIdentityPayload) => {
  const records = await getStoredPeerIdentities();
  const current = records[payload.userID];
  const nextRecord: PeerIdentityRecord = {
    userID: payload.userID,
    fingerprint: payload.fingerprint,
    agreementPublicKey: payload.agreementPublicKey,
    signingPublicKey: payload.signingPublicKey,
    trustedAt: current?.trustedAt ?? Date.now(),
    lastSeenAt: Date.now(),
    ...(current && current.fingerprint !== payload.fingerprint
      ? { keyChangedAt: Date.now() }
      : { keyChangedAt: current?.keyChangedAt }),
  };

  records[payload.userID] = nextRecord;
  await savePeerIdentities(records);
  if (current && current.fingerprint !== payload.fingerprint) {
    const sessions = await getStoredSessions();
    Object.keys(sessions).forEach((conversationKey) => {
      const sessionStore = sessions[conversationKey];
      if (sessionStore.peerUserID === payload.userID) {
        sessionStore.activeSessionId = undefined;
        Object.values(sessionStore.sessions).forEach((session) => {
          session.active = false;
        });
      }
    });
    await saveSessions(sessions);
  }
  emit("SECURE_SESSION_UPDATED");

  return nextRecord;
};

const deriveWrapKey = async (
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

const buildIdentityPayload = async (
  identity: LocalIdentityRecord,
  options?: {
    needReply?: boolean;
    isReply?: boolean;
  },
) => {
  const payloadWithoutSignature: Omit<SecureIdentityPayload, "signature"> = {
    type: SECURE_IDENTITY_VERSION,
    userID: identity.userID,
    fingerprint: identity.fingerprint,
    agreementPublicKey: identity.agreementPublicKey,
    signingPublicKey: identity.signingPublicKey,
    timestamp: Date.now(),
    ...(options?.needReply ? { needReply: true } : {}),
    ...(options?.isReply ? { isReply: true } : {}),
  };

  return {
    ...payloadWithoutSignature,
    signature: await signText(
      identity.signingPrivateKey,
      buildIdentitySigningText(payloadWithoutSignature),
    ),
  } satisfies SecureIdentityPayload;
};

export const ensureLocalIdentity = async () => {
  const currentUserID = await resolveSelfUserID();
  if (!currentUserID) {
    throw new SecureSessionError("SECURE_SESSION_NOT_READY");
  }

  const existing = await getLocalIdentity();
  if (existing?.userID === currentUserID) {
    return existing;
  }

  const subtle = getSubtleCrypto();
  const agreementKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const signingKeyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const agreementPublicKey = await subtle.exportKey("jwk", agreementKeyPair.publicKey);
  const agreementPrivateKey = await subtle.exportKey(
    "jwk",
    agreementKeyPair.privateKey,
  );
  const signingPublicKey = await subtle.exportKey("jwk", signingKeyPair.publicKey);
  const signingPrivateKey = await subtle.exportKey("jwk", signingKeyPair.privateKey);

  const record: LocalIdentityRecord = {
    userID: currentUserID,
    fingerprint: await exportFingerprint(
      currentUserID,
      agreementPublicKey,
      signingPublicKey,
    ),
    agreementPublicKey,
    agreementPrivateKey,
    signingPublicKey,
    signingPrivateKey,
    createdAt: Date.now(),
  };

  await saveLocalIdentity(record);
  return record;
};

export const primeSecureConversation = async (conversation?: ConversationItem) => {
  if (!conversation || conversation.conversationType !== SessionType.Single) {
    return;
  }

  const peerUserID = conversation.userID;
  if (!peerUserID) {
    return;
  }

  const localIdentity = await ensureLocalIdentity();
  const peerIdentities = await getStoredPeerIdentities();
  if (peerIdentities[peerUserID]) {
    return;
  }

  await sendCustomSignal(
    peerUserID,
    CustomType.SecureIdentity,
    await buildIdentityPayload(localIdentity, { needReply: true }),
  );
};

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

const setActiveSession = (
  sessionStore: ConversationSessionRecord,
  sessionId: string,
) => {
  Object.values(sessionStore.sessions).forEach((session) => {
    session.active = session.sessionId === sessionId;
  });
  sessionStore.activeSessionId = sessionId;
};

const getActiveSession = (sessionStore?: ConversationSessionRecord) =>
  sessionStore?.activeSessionId
    ? sessionStore.sessions[sessionStore.activeSessionId]
    : undefined;

const getFallbackSession = (sessionStore?: ConversationSessionRecord) => {
  if (!sessionStore) {
    return undefined;
  }

  const activeSession = getActiveSession(sessionStore);
  if (activeSession) {
    return activeSession;
  }

  const sessionList = Object.values(sessionStore.sessions);
  return sessionList.length === 1 ? sessionList[0] : undefined;
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
    return existingSession;
  }

  const sessionId = createSessionId();
  const sessionKey = randomBytes(SESSION_KEY_LENGTH);
  const subtle = getSubtleCrypto();
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
    sessionStore.activeSessionId = undefined;
    Object.values(sessionStore.sessions).forEach((session) => {
      session.active = false;
    });
  }
  await saveSessions(sessions);

  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[peerUserID];
  if (peerIdentity?.keyChangedAt) {
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

export const getMessageSessionKey = async (
  message: MessageItem,
  sessionId?: string,
) => {
  if (message.sessionType !== SessionType.Single) {
    return null;
  }

  const selfUserID = await resolveSelfUserID();
  const peerUserID = message.sendID === selfUserID ? message.recvID : message.sendID;
  const sessions = await getStoredSessions();
  const sessionStore = sessions[getConversationKey(selfUserID, peerUserID)];
  if (sessionId) {
    return sessionStore?.sessions[sessionId] ?? null;
  }

  return getFallbackSession(sessionStore) ?? null;
};

export const readSessionKeyBytes = (session: SessionRecord) =>
  fromBase64(session.sessionKey);
