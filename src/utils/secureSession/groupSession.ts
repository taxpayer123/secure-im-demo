import { CustomType } from "@/constants";
import { IMSDK } from "@/layout/MainContentWrap";
import { emit } from "@/utils/events";

import { fromBase64, getSubtleCrypto, randomBytes, toBase64 } from "../secureCrypto";
import {
  SECURE_GROUP_SESSION_VERSION,
  SESSION_KEY_LENGTH,
  WRAP_IV_LENGTH,
  WRAP_SALT_LENGTH,
} from "./constants";
import { createSessionId, deriveWrapKey, signText } from "./crypto";
import { ensureLocalIdentity, resolveSelfUserID } from "./identity";
import { sendCustomSignal } from "./signal";
import { getGroupSession, getStoredPeerIdentities, saveGroupSession } from "./store";
import type { GroupSessionRecord, SecureGroupSessionInvitePayload } from "./types";

export const buildGroupSessionSigningText = (
  payload: Omit<SecureGroupSessionInvitePayload, "signature">,
) =>
  JSON.stringify({
    type: payload.type,
    groupID: payload.groupID,
    version: payload.version,
    userID: payload.userID,
    fingerprint: payload.fingerprint,
    ephemeralPublicKey: payload.ephemeralPublicKey,
    wrappedGroupKey: payload.wrappedGroupKey,
    iv: payload.iv,
    salt: payload.salt,
    timestamp: payload.timestamp,
  });

export const getGroupSecureStatus = async (
  groupID: string,
): Promise<"not_ready" | "ready"> => {
  const session = await getGroupSession(groupID);
  return session ? "ready" : "not_ready";
};

export const enableGroupEncryption = async (groupID: string) => {
  const localIdentity = await ensureLocalIdentity();
  const selfUserID = await resolveSelfUserID();

  // Get group member list
  const { data: memberList } = await IMSDK.getGroupMemberList({
    groupID,
    filter: 0,
    offset: 0,
    count: 100,
  });

  if (!memberList || memberList.length === 0) {
    throw new Error("No group members found");
  }

  // Get peer identities for all members (except self)
  const peerIdentities = await getStoredPeerIdentities();
  const otherMembers = memberList.filter((m: any) => m.userID !== selfUserID);

  // Check that we have identity for each member
  const missingMembers: string[] = [];
  for (const member of otherMembers) {
    if (!peerIdentities[member.userID]) {
      missingMembers.push(member.nickname || member.userID);
    }
  }
  if (missingMembers.length > 0) {
    throw new Error(
      `Missing identity for: ${missingMembers.join(", ")}. Please establish single-chat secure session with them first.`,
    );
  }

  // Generate group key
  const groupKey = randomBytes(SESSION_KEY_LENGTH);
  const version = Date.now();

  // Distribute group key to each member via pairwise ECDH
  const subtle = getSubtleCrypto();
  for (const member of otherMembers) {
    const peerIdentity = peerIdentities[member.userID];

    const ephemeralKeyPair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const ephemeralPublicKey = await subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
    const ephemeralPrivateKey = await subtle.exportKey("jwk", ephemeralKeyPair.privateKey);

    const salt = randomBytes(WRAP_SALT_LENGTH);
    const wrapKey = await deriveWrapKey(ephemeralPrivateKey, peerIdentity.agreementPublicKey, salt);
    const iv = randomBytes(WRAP_IV_LENGTH);

    const wrappedGroupKey = await subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, groupKey);

    const payloadWithoutSignature: Omit<SecureGroupSessionInvitePayload, "signature"> = {
      type: SECURE_GROUP_SESSION_VERSION,
      groupID,
      version,
      userID: localIdentity.userID,
      fingerprint: localIdentity.fingerprint,
      ephemeralPublicKey,
      wrappedGroupKey: toBase64(wrappedGroupKey),
      iv: toBase64(iv),
      salt: toBase64(salt),
      timestamp: Date.now(),
    };

    const payload: SecureGroupSessionInvitePayload = {
      ...payloadWithoutSignature,
      signature: await signText(
        localIdentity.signingPrivateKey,
        buildGroupSessionSigningText(payloadWithoutSignature),
      ),
    };

    await sendCustomSignal(member.userID, CustomType.SecureGroupSessionInvite, payload);
  }

  // Store group session locally
  const record: GroupSessionRecord = {
    groupID,
    sessionKey: toBase64(groupKey),
    version,
    createdBy: localIdentity.userID,
    memberFingerprints: otherMembers.map((m: any) => peerIdentities[m.userID].fingerprint),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  await saveGroupSession(record);
  emit("SECURE_SESSION_UPDATED");

  return record;
};

export const getGroupSessionKeyBytes = async (groupID: string) => {
  const session = await getGroupSession(groupID);
  return session ? fromBase64(session.sessionKey) : null;
};