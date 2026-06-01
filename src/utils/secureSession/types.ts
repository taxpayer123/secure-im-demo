export type SecureSessionStatus =
  | "group_unsupported"
  | "not_ready"
  | "identity_pending"
  | "peer_key_changed"
  | "ready";

export type LocalIdentityRecord = {
  userID: string;
  fingerprint: string;
  agreementPublicKey: JsonWebKey;
  agreementPrivateKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  signingPrivateKey: JsonWebKey;
  createdAt: number;
};

export type PeerIdentityRecord = {
  userID: string;
  fingerprint: string;
  agreementPublicKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  trustedAt: number;
  lastSeenAt: number;
  keyChangedAt?: number;
};

export type SessionRecord = {
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

export type ConversationSessionRecord = {
  conversationKey: string;
  peerUserID: string;
  activeSessionId?: string;
  sessions: Record<string, SessionRecord>;
};

export type SecureIdentityPayload = {
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

export type SecureSessionInvitePayload = {
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


export type GroupSessionRecord = {
  groupID: string;
  sessionKey: string;
  version: number;
  createdBy: string;
  memberFingerprints: string[];
  createdAt: number;
  updatedAt: number;
};


export type SecureGroupSessionInvitePayload = {
  type: "secure_group_session_invite_v1";
  groupID: string;
  version: number;
  userID: string;
  fingerprint: string;
  ephemeralPublicKey: JsonWebKey;
  wrappedGroupKey: string;
  iv: string;
  salt: string;
  timestamp: number;
  signature: string;
};
