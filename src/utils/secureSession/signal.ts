import { MessageType } from "@openim/wasm-client-sdk";
import type { MessageItem } from "@openim/wasm-client-sdk/lib/types/entity";

import { CustomType } from "@/constants";
import { IMSDK } from "@/layout/MainContentWrap";

import type { SecureIdentityPayload, SecureSessionInvitePayload } from "./types";

const buildCustomMessagePayload = (
  customType: CustomType,
  data: SecureIdentityPayload | SecureSessionInvitePayload,
) =>
  JSON.stringify({
    customType,
    data,
  });

export const getSecureCustomPayload = (message: MessageItem) => {
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

export const sendCustomSignal = async (
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
