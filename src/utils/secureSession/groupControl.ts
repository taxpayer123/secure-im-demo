import type { MessageItem } from "@openim/wasm-client-sdk/lib/types/entity";

import { CustomType } from "@/constants";
import { emit } from "@/utils/events";

import { fromBase64, getSubtleCrypto, toBase64 } from "../secureCrypto";
import { deriveWrapKey, verifyText } from "./crypto";
import { buildGroupSessionSigningText } from "./groupSession";
import { ensureLocalIdentity } from "./identity";
import { getSecureCustomPayload } from "./signal";
import { getGroupSession, getStoredPeerIdentities, saveGroupSession } from "./store";
import type { GroupSessionRecord, SecureGroupSessionInvitePayload } from "./types";

export const handleGroupSessionInvite = async (message: MessageItem): Promise<boolean> => {
  const payload = getSecureCustomPayload(message);
  if (!payload || payload.customType !== CustomType.SecureGroupSessionInvite || !payload.data) {
    return false;
  }

  const groupPayload = payload.data as SecureGroupSessionInvitePayload;
  const localIdentity = await ensureLocalIdentity();

  // Verify sender identity
  const peerIdentities = await getStoredPeerIdentities();
  const peerIdentity = peerIdentities[groupPayload.userID];
  if (!peerIdentity || peerIdentity.fingerprint !== groupPayload.fingerprint) {
    console.warn("[GroupControl] Unknown peer identity:", groupPayload.userID);
    return true;
  }

  // Verify signature
  const verified = await verifyText(
    peerIdentity.signingPublicKey,
    buildGroupSessionSigningText({
      type: groupPayload.type,
      groupID: groupPayload.groupID,
      version: groupPayload.version,
      userID: groupPayload.userID,
      fingerprint: groupPayload.fingerprint,
      ephemeralPublicKey: groupPayload.ephemeralPublicKey,
      wrappedGroupKey: groupPayload.wrappedGroupKey,
      iv: groupPayload.iv,
      salt: groupPayload.salt,
      timestamp: groupPayload.timestamp,
    }),
    groupPayload.signature,
  );
  if (!verified) {
    console.warn("[GroupControl] Invalid signature for group invite");
    return true;
  }

  // Decrypt group key
  const wrapKey = await deriveWrapKey(
    localIdentity.agreementPrivateKey,
    groupPayload.ephemeralPublicKey,
    fromBase64(groupPayload.salt),
  );

  let groupKeyBuffer: ArrayBuffer;
  try {
    groupKeyBuffer = await getSubtleCrypto().decrypt(
      { name: "AES-GCM", iv: fromBase64(groupPayload.iv) },
      wrapKey,
      fromBase64(groupPayload.wrappedGroupKey),
    );
  } catch (error) {
    console.error("[GroupControl] Failed to decrypt group key:", error);
    return true;
  }

  // Only accept newer versions
  const existing = await getGroupSession(groupPayload.groupID);
  if (existing && existing.version >= groupPayload.version) {
    return true;
  }

  // Save group session
  const record: GroupSessionRecord = {
    groupID: groupPayload.groupID,
    sessionKey: toBase64(groupKeyBuffer),
    version: groupPayload.version,
    createdBy: groupPayload.userID,
    memberFingerprints: [peerIdentity.fingerprint],
    createdAt: existing?.createdAt ?? Date.now(),
    updatedAt: Date.now(),
  };
  await saveGroupSession(record);
  emit("SECURE_SESSION_UPDATED");

  return true;
};