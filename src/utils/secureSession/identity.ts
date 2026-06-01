import { SessionType } from "@openim/wasm-client-sdk";
import type { ConversationItem } from "@openim/wasm-client-sdk/lib/types/entity";

import { CustomType } from "@/constants";
import { useUserStore } from "@/store";
import { emit } from "@/utils/events";

import { getSubtleCrypto } from "../secureCrypto";
import { getIMUserID } from "../storage";
import { SECURE_IDENTITY_VERSION } from "./constants";
import { buildIdentitySigningText, exportFingerprint, signText } from "./crypto";
import { sendCustomSignal } from "./signal";
import {
  getLocalIdentity,
  getStoredPeerIdentities,
  getStoredSessions,
  saveLocalIdentity,
  savePeerIdentities,
  saveSessions,
} from "./store";
import {
  SecureSessionError,
  type LocalIdentityRecord,
  type PeerIdentityRecord,
  type SecureIdentityPayload,
} from "./types";

export const resolveSelfUserID = async () =>
  useUserStore.getState().selfInfo.userID || ((await getIMUserID()) as string) || "";

export const storePeerIdentity = async (payload: SecureIdentityPayload) => {
  const records = await getStoredPeerIdentities();
  const current = records[payload.userID];
  // 首次信任时间保留，后续只刷新最近看到的身份；指纹变化则显式标记换钥。
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
    // 对端换钥后，旧 session 不再安全，全部降级为非激活状态，等待重新协商。
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

export const buildIdentityPayload = async (
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
    // 签名文本必须由稳定字段构成，收发两端才能得到完全一致的验签输入。
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

  // 本地身份和当前登录用户绑定，切账号后必须重新生成一套长期密钥。
  const existing = await getLocalIdentity();
  if (existing?.userID === currentUserID) {
    return existing;
  }

  const subtle = getSubtleCrypto();
  // ECDH 用来协商会话密钥，ECDSA 用来给身份和 invite 做签名。
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
