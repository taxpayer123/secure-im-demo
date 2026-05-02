import { Button, Form, Input, Modal, Select, Space, Tabs } from "antd";
import { t } from "i18next";
import md5 from "md5";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useLogin, useSendSms } from "@/api/login";
import { feedbackToast } from "@/utils/common";
import { hasEnabledMfa, verifyUserMfaCode } from "@/utils/mfa";
import { hasEnabledPasskey, verifyUserPasskey } from "@/utils/passkey";
import {
  getEmail,
  getPhoneNumber,
  setAreaCode,
  setEmail,
  setIMProfile,
  setPhoneNumber,
} from "@/utils/storage";

import { areaCode } from "./areaCode";
import type { FormType } from "./index";
import styles from "./index.module.scss";

// 0login 1resetPassword 2register
enum LoginType {
  Password,
  VerifyCode,
}

type LoginFormProps = {
  setFormType: (type: FormType) => void;
  loginMethod: "phone" | "email";
  updateLoginMethod: (method: "phone" | "email") => void;
};

type LoginProfile = {
  chatToken: string;
  imToken: string;
  userID: string;
};

const LoginForm = ({ loginMethod, setFormType, updateLoginMethod }: LoginFormProps) => {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [loginType, setLoginType] = useState<LoginType>(LoginType.Password);
  const { mutate: login, isLoading: loginLoading } = useLogin();
  const { mutate: semdSms } = useSendSms();

  const [countdown, setCountdown] = useState(0);
  const [pendingProfile, setPendingProfile] = useState<LoginProfile | null>(null);
  const [pendingPasskeyProfile, setPendingPasskeyProfile] =
    useState<LoginProfile | null>(null);
  const [passkeyVerifying, setPasskeyVerifying] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaVerifying, setMfaVerifying] = useState(false);

  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => {
        setCountdown((prevCountdown) => prevCountdown - 1);
        if (countdown === 1) {
          clearTimeout(timer);
          setCountdown(0);
        }
      }, 1000);

      return () => clearTimeout(timer);
    }
  }, [countdown]);

  const completeLogin = (profile: LoginProfile) => {
    setIMProfile(profile);
    navigate("/chat");
  };

  const onFinish = (params: API.Login.LoginParams) => {
    if (loginType === 0) {
      params.password = md5(params.password ?? "");
    }
    if (params.phoneNumber) {
      setAreaCode(params.areaCode);
      setPhoneNumber(params.phoneNumber);
    }
    if (params.email) {
      setEmail(params.email);
    }
    login(params, {
      onSuccess: async (data) => {
        const { chatToken, imToken, userID } = data.data;
        const profile = { chatToken, imToken, userID };
        const [needsPasskey, needsMfa] = await Promise.all([
          hasEnabledPasskey(userID),
          hasEnabledMfa(userID),
        ]);

        if (needsPasskey) {
          setPendingPasskeyProfile(profile);
          setMfaCode("");
          return;
        }
        if (needsMfa) {
          setPendingProfile(profile);
          setMfaCode("");
          return;
        }
        completeLogin(profile);
      },
    });
  };

  const verifyPasskeyHandle = async () => {
    if (!pendingPasskeyProfile) return;
    setPasskeyVerifying(true);
    try {
      const verified = await verifyUserPasskey(pendingPasskeyProfile.userID);
      if (!verified) {
        feedbackToast({ error: new Error(t("toast.passkeyVerifyFailed")) });
        return;
      }

      const profile = pendingPasskeyProfile;
      setPendingPasskeyProfile(null);
      completeLogin(profile);
    } catch (error) {
      feedbackToast({
        error:
          error instanceof Error ? error : new Error(t("toast.passkeyVerifyFailed")),
      });
    } finally {
      setPasskeyVerifying(false);
    }
  };

  const verifyMfaHandle = async () => {
    if (!pendingProfile) return;
    setMfaVerifying(true);
    try {
      const verified = await verifyUserMfaCode(pendingProfile.userID, mfaCode);
      if (!verified) {
        feedbackToast({ error: new Error(t("toast.mfaCodeInvalid")) });
        return;
      }
      completeLogin(pendingProfile);
    } finally {
      setMfaVerifying(false);
    }
  };

  const cancelPasskeyHandle = () => {
    setPendingPasskeyProfile(null);
  };

  const cancelMfaHandle = () => {
    setPendingProfile(null);
    setMfaCode("");
  };

  const sendSmsHandle = () => {
    const options: Partial<API.Login.SendSmsParams> = {
      phoneNumber: form.getFieldValue("phoneNumber") as string,
      email: form.getFieldValue("email") as string,
      areaCode: form.getFieldValue("areaCode") as string,
      usedFor: 3 as API.Login.UsedFor,
    };
    if (loginMethod === "phone") {
      delete options.email;
    }
    if (loginMethod === "email") {
      delete options.phoneNumber;
      delete options.areaCode;
    }

    semdSms(options as API.Login.SendSmsParams, {
      onSuccess() {
        setCountdown(60);
      },
    });
  };

  const onLoginMethodChange = (key: string) => {
    updateLoginMethod(key as "phone" | "email");
  };

  return (
    <>
      <div className="flex flex-row items-center justify-between">
        <div className="text-xl font-medium">{t("placeholder.welcome")}</div>
      </div>
      <Tabs
        className={styles["login-method-tab"]}
        activeKey={loginMethod}
        items={[
          { key: "phone", label: t("placeholder.phoneNumber") },
          { key: "email", label: t("placeholder.email") },
        ]}
        onChange={onLoginMethodChange}
      />
      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        autoComplete="off"
        labelCol={{ prefixCls: "custom-form-item" }}
        initialValues={{
          areaCode: "+86",
          phoneNumber: getPhoneNumber() ?? "",
          email: getEmail() ?? "",
        }}
      >
        {loginMethod === "phone" ? (
          <Form.Item label={t("placeholder.phoneNumber")}>
            <Space.Compact className="w-full">
              <Form.Item name="areaCode" noStyle>
                <Select options={areaCode} className="!w-28" />
              </Form.Item>
              <Form.Item name="phoneNumber" noStyle>
                <Input allowClear placeholder={t("toast.inputPhoneNumber")} />
              </Form.Item>
            </Space.Compact>
          </Form.Item>
        ) : (
          <Form.Item
            label={t("placeholder.email")}
            name="email"
            rules={[{ type: "email", message: t("toast.inputCorrectEmail") }]}
          >
            <Input allowClear placeholder={t("toast.inputEmail")} />
          </Form.Item>
        )}

        {loginType === LoginType.VerifyCode ? (
          <Form.Item label={t("placeholder.verifyCode")} name="verifyCode">
            <Space.Compact className="w-full">
              <Input
                allowClear
                placeholder={t("toast.inputVerifyCode")}
                className="w-full"
              />
              <Button type="primary" onClick={sendSmsHandle} loading={countdown > 0}>
                {countdown > 0
                  ? t("date.second", { num: countdown })
                  : t("placeholder.sendVerifyCode")}
              </Button>
            </Space.Compact>
          </Form.Item>
        ) : (
          <Form.Item label={t("placeholder.password")} name="password">
            <Input.Password allowClear placeholder={t("toast.inputPassword")} />
          </Form.Item>
        )}

        <div className="mb-10 flex flex-row justify-between">
          <span
            className="cursor-pointer text-sm text-gray-400"
            onClick={() => setFormType(1)}
          >
            {t("placeholder.forgetPassword")}
          </span>
          <span
            className="cursor-pointer text-sm text-[var(--primary)]"
            onClick={() =>
              setLoginType(
                loginType === LoginType.Password
                  ? LoginType.VerifyCode
                  : LoginType.Password,
              )
            }
          >
            {`${
              loginType === LoginType.Password
                ? t("placeholder.verifyCode")
                : t("placeholder.password")
            }${t("placeholder.login")}`}
          </span>
        </div>

        <Form.Item className="mb-4">
          <Button type="primary" htmlType="submit" block loading={loginLoading}>
            {t("placeholder.login")}
          </Button>
        </Form.Item>

        <div className="flex flex-row items-center justify-center">
          <span className="text-sm text-gray-400">
            {t("placeholder.registerToast")}
          </span>
          <span
            className="cursor-pointer text-sm text-blue-500"
            onClick={() => setFormType(2)}
          >
            {t("placeholder.toRegister")}
          </span>
        </div>
      </Form>
      <Modal
        title={t("placeholder.passkeyVerifyTitle")}
        open={Boolean(pendingPasskeyProfile)}
        onCancel={cancelPasskeyHandle}
        footer={[
          <Button key="cancel" onClick={cancelPasskeyHandle}>
            {t("cancel")}
          </Button>,
          <Button
            key="verify"
            type="primary"
            loading={passkeyVerifying}
            onClick={() => {
              void verifyPasskeyHandle();
            }}
          >
            {t("placeholder.verifyPasskey")}
          </Button>,
        ]}
        destroyOnClose
      >
        <div className="text-sm text-gray-500">{t("placeholder.passkeyLoginDesc")}</div>
      </Modal>
      <Modal
        title={t("placeholder.mfaVerifyTitle")}
        open={Boolean(pendingProfile)}
        onCancel={cancelMfaHandle}
        footer={[
          <Button key="cancel" onClick={cancelMfaHandle}>
            {t("cancel")}
          </Button>,
          <Button
            key="verify"
            type="primary"
            loading={mfaVerifying}
            disabled={mfaCode.length !== 6}
            onClick={() => {
              void verifyMfaHandle();
            }}
          >
            {t("confirm")}
          </Button>,
        ]}
        destroyOnClose
      >
        <div className="mb-4 text-sm text-gray-500">
          {t("placeholder.mfaLoginDesc")}
        </div>
        <Input
          autoFocus
          maxLength={6}
          value={mfaCode}
          inputMode="numeric"
          placeholder={t("placeholder.mfaInputCode")}
          onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          onPressEnter={() => {
            void verifyMfaHandle();
          }}
        />
      </Modal>
    </>
  );
};

export default LoginForm;
