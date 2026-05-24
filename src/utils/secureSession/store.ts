import * as localForage from "localforage";

import { LOCAL_IDENTITY_KEY, PEER_IDENTITY_KEY, SESSION_STORE_KEY } from "./constants";
import { getLegacySessionId } from "./crypto";
import type {
  ConversationSessionRecord,
  LocalIdentityRecord,
  PeerIdentityRecord,
  SessionRecord,
} from "./types";

localForage.config({
  name: "OpenCorp-Config",
});

export const getConversationKey = (userID: string, peerUserID: string) =>
  `single:${[userID, peerUserID].sort().join(":")}`;

const normalizeSessionStoreRecord = (
  conversationKey: string,
  record: ConversationSessionRecord | SessionRecord,
): ConversationSessionRecord => {
  if ("sessions" in record) {
    return record;
  }

  // 兼容早期单 session 结构，读取时统一升级成当前的多 session 存储模型。
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

export const getStoredPeerIdentities = async () =>
  (await localForage.getItem<Record<string, PeerIdentityRecord>>(PEER_IDENTITY_KEY)) ??
  {};

export const savePeerIdentities = async (records: Record<string, PeerIdentityRecord>) =>
  localForage.setItem(PEER_IDENTITY_KEY, records);

export const getStoredSessions = async () => {
  const records =
    (await localForage.getItem<
      Record<string, ConversationSessionRecord | SessionRecord>
    >(SESSION_STORE_KEY)) ?? {};

  // 在读取阶段做一次归一化，后续主流程就不需要再分支兼容旧数据结构。
  return Object.entries(records).reduce<Record<string, ConversationSessionRecord>>(
    (sessionStores, [conversationKey, record]) => ({
      ...sessionStores,
      [conversationKey]: normalizeSessionStoreRecord(conversationKey, record),
    }),
    {},
  );
};

export const saveSessions = async (
  records: Record<string, ConversationSessionRecord>,
) => localForage.setItem(SESSION_STORE_KEY, records);

export const getLocalIdentity = async () =>
  (await localForage.getItem<LocalIdentityRecord>(LOCAL_IDENTITY_KEY)) ?? null;

export const saveLocalIdentity = async (record: LocalIdentityRecord) =>
  localForage.setItem(LOCAL_IDENTITY_KEY, record);

export const setActiveSession = (
  sessionStore: ConversationSessionRecord,
  sessionId: string,
) => {
  // active flag 和 activeSessionId 必须同时更新，避免 UI 和加解密读取到不同会话。
  Object.values(sessionStore.sessions).forEach((session) => {
    session.active = session.sessionId === sessionId;
  });
  sessionStore.activeSessionId = sessionId;
};

export const getActiveSession = (sessionStore?: ConversationSessionRecord) =>
  sessionStore?.activeSessionId
    ? sessionStore.sessions[sessionStore.activeSessionId]
    : undefined;
