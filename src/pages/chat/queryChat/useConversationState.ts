import { useLatest, useThrottleFn, useUpdateEffect } from "ahooks";
import { useCallback, useEffect } from "react";
import { useParams } from "react-router-dom";

import { IMSDK } from "@/layout/MainContentWrap";
import { useConversationStore, useUserStore } from "@/store";
import { feedbackToast } from "@/utils/common";

export default function useConversationState() {
  const { conversationID } = useParams();
  const syncState = useUserStore((state) => state.syncState);
  const latestSyncState = useLatest(syncState);
  const conversationList = useConversationStore((state) => state.conversationList);
  const currentConversation = useConversationStore(
    (state) => state.currentConversation,
  );
  const updateCurrentConversation = useConversationStore(
    (state) => state.updateCurrentConversation,
  );
  const latestCurrentConversation = useLatest(currentConversation);

  const checkConversationState = useCallback(() => {
    if (!latestCurrentConversation.current || latestSyncState.current === "loading")
      return;

    if (latestCurrentConversation.current.unreadCount > 0) {
      void IMSDK.markConversationMessageAsRead(
        latestCurrentConversation.current.conversationID,
      );
    }
  }, [latestCurrentConversation, latestSyncState]);

  const throttleCheckConversationState = (
    useThrottleFn(checkConversationState, {
      wait: 2000,
      leading: false,
    }) as { run: () => void }
  ).run;

  useUpdateEffect(() => {
    if (syncState !== "loading") {
      checkConversationState();
    }
  }, [checkConversationState, syncState]);

  useUpdateEffect(() => {
    throttleCheckConversationState();
  }, [currentConversation?.unreadCount, throttleCheckConversationState]);

  useEffect(() => {
    checkConversationState();
  }, [checkConversationState, currentConversation?.conversationID]);

  useEffect(() => {
    if (!conversationID || currentConversation?.conversationID === conversationID) {
      return;
    }

    let disposed = false;

    const syncCurrentConversation = async () => {
      let conversation = conversationList.find(
        (item) => item.conversationID === conversationID,
      );

      if (!conversation) {
        try {
          const { data } = await IMSDK.getMultipleConversation([conversationID]);
          conversation = data[0];
        } catch (error) {
          feedbackToast({ error });
          return;
        }
      }

      if (!disposed && conversation) {
        await updateCurrentConversation({ ...conversation });
      }
    };

    void syncCurrentConversation();

    return () => {
      disposed = true;
    };
  }, [
    conversationID,
    conversationList,
    currentConversation?.conversationID,
    updateCurrentConversation,
  ]);

  return {
    currentConversation,
  };
}
