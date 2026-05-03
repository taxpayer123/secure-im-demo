import { SafetyCertificateFilled } from "@ant-design/icons";
import { SessionType } from "@openim/wasm-client-sdk";
import { Layout, Tooltip } from "antd";
import clsx from "clsx";
import i18n, { t } from "i18next";
import { memo, useEffect, useRef, useState } from "react";

import group_member from "@/assets/images/chatHeader/group_member.png";
import launch_group from "@/assets/images/chatHeader/launch_group.png";
import settings from "@/assets/images/chatHeader/settings.png";
import OIMAvatar from "@/components/OIMAvatar";
import { OverlayVisibleHandle } from "@/hooks/useOverlayVisible";
import { useConversationStore, useUserStore } from "@/store";
import emitter, { emit } from "@/utils/events";
import { isGroupSession as isGroupConversation } from "@/utils/imCommon";
import {
  getConversationSecureStatus,
  primeSecureConversation,
  type SecureSessionStatus,
} from "@/utils/secureSession";

import GroupSetting from "../GroupSetting";
import SingleSetting from "../SingleSetting";

const menuList = [
  {
    title: t("placeholder.createGroup"),
    icon: launch_group,
    idx: 0,
  },
  {
    title: t("placeholder.invitation"),
    icon: launch_group,
    idx: 1,
  },
  {
    title: t("placeholder.setting"),
    icon: settings,
    idx: 2,
  },
];

i18n.on("languageChanged", () => {
  menuList[0].title = t("placeholder.createGroup");
  menuList[1].title = t("placeholder.invitation");
  menuList[2].title = t("placeholder.setting");
});

const ChatHeader = () => {
  const singleSettingRef = useRef<OverlayVisibleHandle>(null);
  const groupSettingRef = useRef<OverlayVisibleHandle>(null);

  const currentConversation = useConversationStore(
    (state) => state.currentConversation,
  );
  const currentGroupInfo = useConversationStore((state) => state.currentGroupInfo);
  const currentUserIsInGroup = useConversationStore((state) =>
    Boolean(state.currentMemberInGroup?.userID),
  );
  const inGroup = useConversationStore((state) =>
    Boolean(state.currentMemberInGroup?.groupID),
  );
  const [secureSessionStatus, setSecureSessionStatus] =
    useState<SecureSessionStatus>("not_ready");

  // locale re render
  useUserStore((state) => state.appSettings.locale);

  useEffect(() => {
    let disposed = false;
    if (singleSettingRef.current?.isOverlayOpen) {
      singleSettingRef.current?.closeOverlay();
    }
    if (groupSettingRef.current?.isOverlayOpen) {
      groupSettingRef.current?.closeOverlay();
    }

    const syncSecureStatus = async () => {
      try {
        await primeSecureConversation(currentConversation);
      } catch (error) {
        console.error(error);
      }

      const status = await getConversationSecureStatus(currentConversation);
      if (!disposed) {
        setSecureSessionStatus(status);
      }
    };

    const handleSecureSessionUpdated = () => {
      void syncSecureStatus();
    };

    void syncSecureStatus();
    emitter.on("SECURE_SESSION_UPDATED", handleSecureSessionUpdated);
    return () => {
      disposed = true;
      emitter.off("SECURE_SESSION_UPDATED", handleSecureSessionUpdated);
    };
  }, [currentConversation]);

  const menuClick = (idx: number) => {
    switch (idx) {
      case 0:
      case 1:
        emit("OPEN_CHOOSE_MODAL", {
          type: isSingleSession ? "CRATE_GROUP" : "INVITE_TO_GROUP",
          extraData: isSingleSession
            ? [{ ...currentConversation }]
            : currentConversation?.groupID,
        });
        break;
      case 2:
        if (isGroupSession) {
          groupSettingRef.current?.openOverlay();
        } else {
          singleSettingRef.current?.openOverlay();
        }
        break;
      default:
        break;
    }
  };

  const isSingleSession = currentConversation?.conversationType === SessionType.Single;
  const isGroupSession = isGroupConversation(currentConversation?.conversationType);
  const showReadyBadge = secureSessionStatus === "ready";
  const showPendingBadge =
    isSingleSession &&
    (secureSessionStatus === "identity_pending" || secureSessionStatus === "not_ready");
  const showRiskBadge = secureSessionStatus === "peer_key_changed";

  return (
    <Layout.Header className="relative border-b border-b-[var(--gap-text)] !bg-white !px-3">
      <div className="flex h-full items-center leading-none">
        <div className="flex flex-1 items-center overflow-hidden">
          <OIMAvatar
            src={currentConversation?.faceURL}
            text={currentConversation?.showName}
            isgroup={Boolean(currentConversation?.groupID)}
          />
          <div
            className={clsx(
              "ml-3 flex !h-10.5 flex-1 flex-col justify-between overflow-hidden",
            )}
          >
            <div className="truncate text-base font-semibold">
              {currentConversation?.showName}
            </div>
            <div className="flex min-h-[20px] items-center gap-2 text-xs text-[var(--sub-text)]">
              {isGroupSession && currentUserIsInGroup && (
                <div className="flex items-center">
                  <img width={20} src={group_member} alt="member" />
                  <span>{currentGroupInfo?.memberCount}</span>
                </div>
              )}
              {showReadyBadge && (
                <span className="inline-flex items-center gap-1 rounded bg-[#f6ffed] px-2 py-0.5 text-[#389e0d]">
                  <SafetyCertificateFilled />
                  <span>{t("placeholder.encryptedSession")}</span>
                </span>
              )}
              {showPendingBadge && (
                <span className="inline-flex items-center gap-1 rounded bg-[#fff7e6] px-2 py-0.5 text-[#d46b08]">
                  <SafetyCertificateFilled />
                  <span>{t("placeholder.secureSessionPreparing")}</span>
                </span>
              )}
              {showRiskBadge && (
                <span className="inline-flex items-center gap-1 rounded bg-[#fff1f0] px-2 py-0.5 text-[#cf1322]">
                  <SafetyCertificateFilled />
                  <span>{t("placeholder.secureSessionKeyChanged")}</span>
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="mr-5 flex">
          {menuList.map((menu) => {
            if (menu.idx === 1 && (isSingleSession || (!inGroup && !isSingleSession))) {
              return null;
            }
            if (menu.idx === 0 && !isSingleSession) {
              return null;
            }

            return (
              <Tooltip title={menu.title} key={menu.idx}>
                <img
                  className="ml-5 cursor-pointer"
                  width={20}
                  src={menu.icon}
                  alt=""
                  onClick={() => menuClick(menu.idx)}
                />
              </Tooltip>
            );
          })}
        </div>
      </div>
      <SingleSetting ref={singleSettingRef} />
      <GroupSetting ref={groupSettingRef} />
    </Layout.Header>
  );
};

export default memo(ChatHeader);
