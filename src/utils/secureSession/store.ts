import * as localForage from "localforage";

import { GROUP_SESSION_STORE_KEY, LOCAL_IDENTITY_KEY, PEER_IDENTITY_KEY, SESSION_STORE_KEY } from "./constants";
import { getLegacySessionId } from "./crypto";
import type {
  ConversationSessionRecord,
  GroupSessionRecord,
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
    >(SESSION_STORE_KEY)) ??
  {};

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
  Object.values(sessionStore.sessions).forEach((session) => {
    session.active = session.sessionId === sessionId;
  });
  sessionStore.activeSessionId = sessionId;
};

export const getActiveSession = (sessionStore?: ConversationSessionRecord) =>
  sessionStore?.activeSessionId
    ? sessionStore.sessions[sessionStore.activeSessionId]
    : undefined;

export const getStoredGroupSessions = async () =>
  (await localForage.getItem<Record<string, GroupSessionRecord>>(GROUP_SESSION_STORE_KEY)) ??
  {};

export const saveGroupSessions = async (records: Record<string, GroupSessionRecord>) =>
  localForage.setItem(GROUP_SESSION_STORE_KEY, records);

export const getGroupSession = async (groupID: string) => {
  const sessions = await getStoredGroupSessions();
  return sessions[groupID] ?? null;
};

export const saveGroupSession = async (record: GroupSessionRecord) => {
  const sessions = await getStoredGroupSessions();
  sessions[record.groupID] = record;
  await saveGroupSessions(sessions);
};

export const clearAllSecureData = async () => {
  await localForage.removeItem(PEER_IDENTITY_KEY);
  await localForage.removeItem(SESSION_STORE_KEY);
  await localForage.removeItem(LOCAL_IDENTITY_KEY);
  await localForage.removeItem(GROUP_SESSION_STORE_KEY);
};