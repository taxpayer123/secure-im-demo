import { MessageType } from "@openim/wasm-client-sdk";
import type { MessageItem } from "@openim/wasm-client-sdk/lib/types/entity";

import { CustomType } from "@/constants";
import { IMSDK } from "@/layout/MainContentWrap";

import type {
  SecureIdentityPayload,
  SecureSessionInvitePayload,
  SecureGroupSessionInvitePayload,
} from "./types";

const buildCustomMessagePayload = (
  customType: CustomType,
  data: SecureIdentityPayload | SecureSessionInvitePayload | SecureGroupSessionInvitePayload,
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
    // secureSession 控制信令复用 custom message 通道，先过滤出本模块定义的 payload。
    const payload = JSON.parse(message.customElem.data) as {
      customType?: number;
      data?: SecureIdentityPayload | SecureSessionInvitePayload;
    };
    if (
      payload.customType !== CustomType.SecureIdentity &&
  payload.customType !== CustomType.SecureSessionInvite &&
  payload.customType !== CustomType.SecureGroupSessionInvite
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
  // 控制消息不进入群组逻辑，统一按单聊信令发送。
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
