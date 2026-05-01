import { MessageStatus } from "@openim/wasm-client-sdk";
import { MessageItem, WsResponse } from "@openim/wasm-client-sdk/lib/types/entity";
import { SendMsgParams } from "@openim/wasm-client-sdk/lib/types/params";
import { useCallback } from "react";

import { IMSDK } from "@/layout/MainContentWrap";
import { useConversationStore } from "@/store";
import { emit } from "@/utils/events";
import { normalizeMessageForRender } from "@/utils/secureChat";

import { pushNewMessage, updateOneMessage } from "../useHistoryMessageList";

export type SendMessageParams = Partial<Omit<SendMsgParams, "message">> & {
  message: MessageItem;
  displayMessage?: MessageItem;
  needPush?: boolean;
};

export function useSendMessage() {
  const sendMessage = useCallback(
    async ({ recvID, groupID, message, displayMessage, needPush }: SendMessageParams) => {
      const currentConversation = useConversationStore.getState().currentConversation;
      const sourceID = recvID || groupID;
      const inCurrentConversation =
        currentConversation?.userID === sourceID ||
        currentConversation?.groupID === sourceID ||
        !sourceID;
      needPush = needPush ?? inCurrentConversation;
      const renderableMessage =
        displayMessage ?? (await normalizeMessageForRender(message));

      if (needPush) {
        pushNewMessage(renderableMessage);
        emit("CHAT_LIST_SCROLL_TO_BOTTOM");
      }

      const options = {
        recvID: recvID ?? currentConversation?.userID ?? "",
        groupID: groupID ?? currentConversation?.groupID ?? "",
        message,
      };

      try {
        const { data: successMessage } = await IMSDK.sendMessage(options);
        updateOneMessage(await normalizeMessageForRender(successMessage));
      } catch (error) {
        updateOneMessage({
          ...renderableMessage,
          status: MessageStatus.Failed,
        });
      }
    },
    [],
  );

  return {
    sendMessage,
  };
}
