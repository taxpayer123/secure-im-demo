import { CloseOutlined, RightOutlined } from "@ant-design/icons";
import { Button, Checkbox, Divider, Input, Modal, QRCode } from "antd";
import { t } from "i18next";
import {
  forwardRef,
  ForwardRefRenderFunction,
  memo,
  useEffect,
  useRef,
  useState,
} from "react";

import i18n from "@/i18n";
import { useUserStore } from "@/store";
import { LocaleString } from "@/store/type";
import { feedbackToast } from "@/utils/common";
import {
  buildMfaOtpAuthUrl,
  generateMfaSecret,
  getMfaRecord,
  MfaRecord,
  removeMfaRecord,
  setMfaRecord,
  verifyTotp,
} from "@/utils/mfa";
import {
  getPasskeyRecord,
  isPasskeySupported,
  PasskeyRecord,
  registerUserPasskey,
  removePasskeyRecord,
  verifyUserPasskey,
} from "@/utils/passkey";

import { OverlayVisibleHandle, useOverlayVisible } from "../../hooks/useOverlayVisible";
import BlackList from "./BlackList";

const PersonalSettings: ForwardRefRenderFunction<OverlayVisibleHandle, unknown> = (
  _,
  ref,
) => {
  const { isOverlayOpen, closeOverlay } = useOverlayVisible(ref);

  return (
    <Modal
      title={null}
      footer={null}
      closable={false}
      open={isOverlayOpen}
      onCancel={closeOverlay}
      centered
      destroyOnClose
      styles={{
        mask: {
          opacity: 0,
          transition: "none",
        },
      }}
      width={360}
      className="no-padding-modal max-w-[70vw]"
      maskTransitionName=""
    >
      <PersonalSettingsContent closeOverlay={closeOverlay} />
    </Modal>
  );
};

export default memo(forwardRef(PersonalSettings));

export const PersonalSettingsContent = ({
  closeOverlay,
}: {
  closeOverlay?: () => void;
}) => {
  const localeStr = useUserStore((state) => state.appSettings.locale);
  const closeAction = useUserStore((state) => state.appSettings.closeAction);
  const selfInfo = useUserStore((state) => state.selfInfo);
  const updateAppSettings = useUserStore((state) => state.updateAppSettings);

  const backListRef = useRef<OverlayVisibleHandle>(null);
  const [mfaOpen, setMfaOpen] = useState(false);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [passkeyOpen, setPasskeyOpen] = useState(false);
  const [passkeyEnabled, setPasskeyEnabled] = useState(false);

  useEffect(() => {
    if (!selfInfo?.userID) return;
    Promise.all([
      getMfaRecord(selfInfo.userID),
      getPasskeyRecord(selfInfo.userID),
    ]).then(([mfaRecord, passkeyRecord]) => {
      setMfaEnabled(Boolean(mfaRecord?.enabled));
      setPasskeyEnabled(Boolean(passkeyRecord?.enabled));
    });
  }, [selfInfo?.userID]);

  const localeChange = (checked: boolean, locale: LocaleString) => {
    if (!checked) return;
    window.electronAPI?.ipcInvoke("changeLanguage", locale);
    i18n.changeLanguage(locale);
    updateAppSettings({
      locale,
    });
  };

  const closeActionChange = (checked: boolean, action: "miniSize" | "quit") => {
    if (checked) {
      window.electronAPI?.ipcInvoke("setKeyStore", {
        key: "closeAction",
        data: action,
      });
      updateAppSettings({
        closeAction: action,
      });
    }
  };

  const toBlackList = () => {
    backListRef.current?.openOverlay();
  };

  const accountLabel =
    selfInfo.account || selfInfo.phoneNumber || selfInfo.email || selfInfo.userID;

  return (
    <div className="flex flex-col bg-[var(--chat-bubble)]">
      <BlackList ref={backListRef} />
      <MfaSettingsModal
        open={mfaOpen}
        userID={selfInfo.userID}
        account={accountLabel}
        onClose={() => setMfaOpen(false)}
        onStatusChange={setMfaEnabled}
      />
      <PasskeySettingsModal
        open={passkeyOpen}
        userID={selfInfo.userID}
        account={accountLabel}
        onClose={() => setPasskeyOpen(false)}
        onStatusChange={setPasskeyEnabled}
      />
      <div className="app-drag flex items-center justify-between bg-[var(--gap-text)] p-5">
        <span className="text-base font-medium">{t("placeholder.accountSetting")}</span>
        <CloseOutlined
          className="app-no-drag cursor-pointer text-[#8e9aaf]"
          rev={undefined}
          onClick={closeOverlay}
        />
      </div>
      <div className="flex-1 overflow-y-auto">
        <div className="px-6">
          <div>
            <div className="pb-5 pt-4 text-base font-medium">
              {t("placeholder.personalSetting")}
            </div>
            <div className="pb-8 pl-1">
              <div className="pb-3 font-medium">{t("placeholder.chooseLanguage")}</div>
              <div>
                <Checkbox
                  checked={localeStr === "zh-CN"}
                  className="mr-4"
                  onChange={(e) => localeChange(e.target.checked, "zh-CN")}
                >
                  简体中文
                </Checkbox>
                <Checkbox
                  checked={localeStr === "en-US"}
                  onChange={(e) => localeChange(e.target.checked, "en-US")}
                >
                  English
                </Checkbox>
              </div>
            </div>
            {Boolean(window.electronAPI) && (
              <div className="pb-8 pl-1">
                <div className="pb-3 font-medium">
                  {t("placeholder.closeButtonEvent")}
                </div>
                <div>
                  <Checkbox
                    checked={closeAction === "quit"}
                    className="mr-4"
                    onChange={(e) => closeActionChange(e.target.checked, "quit")}
                  >
                    {t("placeholder.exitApplication")}
                  </Checkbox>
                  <Checkbox
                    checked={closeAction === "miniSize"}
                    onChange={(e) => closeActionChange(e.target.checked, "miniSize")}
                  >
                    {t("placeholder.minimize")}
                  </Checkbox>
                </div>
              </div>
            )}
          </div>
        </div>
        <Divider className="m-0 border-4 border-[var(--gap-text)]" />
        <div
          className="flex cursor-pointer items-center justify-between px-6 py-4"
          onClick={() => setPasskeyOpen(true)}
        >
          <div>
            <div className="text-base font-medium">{t("placeholder.passkeyTitle")}</div>
            <div className="mt-1 text-xs text-gray-400">
              {passkeyEnabled
                ? t("placeholder.passkeyStatusEnabled")
                : t("placeholder.passkeyStatusDisabled")}
            </div>
          </div>
          <RightOutlined rev={undefined} />
        </div>
        <Divider className="m-0 border-4 border-[var(--gap-text)]" />
        <div
          className="flex cursor-pointer items-center justify-between px-6 py-4"
          onClick={() => setMfaOpen(true)}
        >
          <div>
            <div className="text-base font-medium">{t("placeholder.mfaTitle")}</div>
            <div className="mt-1 text-xs text-gray-400">
              {mfaEnabled
                ? t("placeholder.mfaStatusEnabled")
                : t("placeholder.mfaStatusDisabled")}
            </div>
          </div>
          <RightOutlined rev={undefined} />
        </div>
        <Divider className="m-0 border-4 border-[var(--gap-text)]" />
        <div
          className="flex cursor-pointer items-center justify-between px-6 py-4"
          onClick={toBlackList}
        >
          <div className="text-base font-medium">{t("placeholder.blackList")}</div>
          <RightOutlined rev={undefined} />
        </div>
        <Divider className="m-0 border-4 border-[var(--gap-text)]" />
      </div>
    </div>
  );
};

const PasskeySettingsModal = ({
  account,
  onClose,
  onStatusChange,
  open,
  userID,
}: {
  account: string;
  onClose: () => void;
  onStatusChange: (enabled: boolean) => void;
  open: boolean;
  userID: string;
}) => {
  const [record, setRecord] = useState<PasskeyRecord | null>(null);
  const [supported, setSupported] = useState(true);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !userID) return;

    Promise.all([getPasskeyRecord(userID), isPasskeySupported()]).then(
      ([storedRecord, passkeySupported]) => {
        setRecord(storedRecord);
        setSupported(passkeySupported);
      },
    );
  }, [open, userID]);

  const enablePasskey = async () => {
    if (!userID) return;

    setLoading(true);
    try {
      await registerUserPasskey(userID, account);
      const nextRecord = await getPasskeyRecord(userID);
      setRecord(nextRecord);
      onStatusChange(true);
      feedbackToast({ msg: t("toast.passkeyEnabled") });
    } catch (error) {
      feedbackToast({
        error:
          error instanceof Error ? error : new Error(t("toast.passkeyRegisterFailed")),
      });
    } finally {
      setLoading(false);
    }
  };

  const disablePasskey = async () => {
    if (!record || !userID) return;

    setLoading(true);
    try {
      const verified = await verifyUserPasskey(userID);
      if (!verified) {
        feedbackToast({ error: new Error(t("toast.passkeyVerifyFailed")) });
        return;
      }
      await removePasskeyRecord(userID);
      setRecord(null);
      onStatusChange(false);
      feedbackToast({ msg: t("toast.passkeyDisabled") });
    } catch (error) {
      feedbackToast({
        error:
          error instanceof Error ? error : new Error(t("toast.passkeyVerifyFailed")),
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      title={t("placeholder.passkeyTitle")}
      open={open}
      onCancel={onClose}
      footer={null}
      destroyOnClose
    >
      {record?.enabled ? (
        <>
          <div className="mb-4 text-sm text-gray-500">
            {t("placeholder.passkeyDisableDesc")}
          </div>
          <Button
            danger
            block
            loading={loading}
            disabled={!supported}
            onClick={() => {
              void disablePasskey();
            }}
          >
            {t("placeholder.disablePasskey")}
          </Button>
        </>
      ) : (
        <>
          <div className="mb-4 text-sm text-gray-500">
            {supported
              ? t("placeholder.passkeySetupDesc")
              : t("placeholder.passkeyUnsupported")}
          </div>
          <Button
            type="primary"
            block
            loading={loading}
            disabled={!supported}
            onClick={() => {
              void enablePasskey();
            }}
          >
            {t("placeholder.enablePasskey")}
          </Button>
        </>
      )}
    </Modal>
  );
};

const MfaSettingsModal = ({
  account,
  onClose,
  onStatusChange,
  open,
  userID,
}: {
  account: string;
  onClose: () => void;
  onStatusChange: (enabled: boolean) => void;
  open: boolean;
  userID: string;
}) => {
  const [record, setRecord] = useState<MfaRecord | null>(null);
  const [pendingSecret, setPendingSecret] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !userID) return;

    getMfaRecord(userID).then((storedRecord) => {
      setRecord(storedRecord);
      setPendingSecret(storedRecord?.enabled ? "" : generateMfaSecret());
      setCode("");
    });
  }, [open, userID]);

  const otpAuthUrl = pendingSecret
    ? buildMfaOtpAuthUrl({
        account,
        secret: pendingSecret,
      })
    : "";

  const codeChange = (value: string) => {
    setCode(value.replace(/\D/g, "").slice(0, 6));
  };

  const enableMfa = async () => {
    if (!pendingSecret || !userID) return;

    setLoading(true);
    try {
      const verified = await verifyTotp(pendingSecret, code);
      if (!verified) {
        feedbackToast({ error: new Error(t("toast.mfaCodeInvalid")) });
        return;
      }
      await setMfaRecord(userID, pendingSecret);
      const nextRecord = await getMfaRecord(userID);
      setRecord(nextRecord);
      setPendingSecret("");
      setCode("");
      onStatusChange(true);
      feedbackToast({ msg: t("toast.mfaEnabled") });
    } finally {
      setLoading(false);
    }
  };

  const disableMfa = async () => {
    if (!record || !userID) return;

    setLoading(true);
    try {
      const verified = await verifyTotp(record.secret, code);
      if (!verified) {
        feedbackToast({ error: new Error(t("toast.mfaCodeInvalid")) });
        return;
      }
      await removeMfaRecord(userID);
      setRecord(null);
      setPendingSecret(generateMfaSecret());
      setCode("");
      onStatusChange(false);
      feedbackToast({ msg: t("toast.mfaDisabled") });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      title={t("placeholder.mfaTitle")}
      open={open}
      onCancel={onClose}
      footer={null}
      destroyOnClose
    >
      {record?.enabled ? (
        <>
          <div className="mb-4 text-sm text-gray-500">
            {t("placeholder.mfaDisableDesc")}
          </div>
          <Input
            maxLength={6}
            value={code}
            inputMode="numeric"
            placeholder={t("placeholder.mfaInputCode")}
            onChange={(e) => codeChange(e.target.value)}
            onPressEnter={() => {
              void disableMfa();
            }}
          />
          <Button
            danger
            block
            className="mt-4"
            loading={loading}
            disabled={code.length !== 6}
            onClick={() => {
              void disableMfa();
            }}
          >
            {t("placeholder.disableMfa")}
          </Button>
        </>
      ) : (
        <>
          <div className="mb-4 text-sm text-gray-500">
            {t("placeholder.mfaSetupDesc")}
          </div>
          <div className="mb-4 flex justify-center">
            <QRCode value={otpAuthUrl || " "} size={180} />
          </div>
          <div className="mb-4 break-all rounded bg-[var(--gap-text)] p-3 text-xs text-gray-500">
            {t("placeholder.mfaManualSecret")}: {pendingSecret}
          </div>
          <Input
            maxLength={6}
            value={code}
            inputMode="numeric"
            placeholder={t("placeholder.mfaInputCode")}
            onChange={(e) => codeChange(e.target.value)}
            onPressEnter={() => {
              void enableMfa();
            }}
          />
          <Button
            type="primary"
            block
            className="mt-4"
            loading={loading}
            disabled={code.length !== 6}
            onClick={() => {
              void enableMfa();
            }}
          >
            {t("placeholder.enableMfa")}
          </Button>
        </>
      )}
    </Modal>
  );
};
