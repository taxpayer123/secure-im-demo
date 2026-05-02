# Passkey 认证方案
Passkey 定位为客户端演示版 WebAuthn 方案，用于降低密码泄露后的本机登录风险。该方案不修改 OpenIM SDK 和服务端：`/account/login` 返回 token 后，客户端先暂存登录结果并要求用户完成本机 Passkey 验证；验证通过后才写入 `chatToken` / `imToken` 并进入聊天页。

- 认证方式
  - 使用浏览器 / Electron 环境提供的 WebAuthn API
  - 支持系统认证器、平台 PIN、指纹、面容和外接安全密钥，具体能力由运行环境决定
- 首次绑定
  - 用户已登录后在账号设置中开启 Passkey
  - 客户端调用 `navigator.credentials.create` 创建本机凭据
  - 绑定成功后只在本地保存 credential id、绑定状态和传输方式，不硬编码任何凭据
  - Passkey 和 TOTP MFA 的本地绑定记录可以同时保留，登录时优先使用 Passkey
- 登录校验
  - 密码或短信验证码登录成功后，不立即调用 `setIMProfile`
  - 若当前用户已启用 Passkey，则暂存接口返回的 `chatToken`、`imToken`、`userID`
  - 弹出 Passkey 验证框，调用 `navigator.credentials.get`
  - 验证通过后直接写入 token 并跳转 `/chat`，不会继续要求 TOTP MFA
  - 若同时绑定了 Passkey 和 TOTP MFA，则只使用 Passkey；MFA 记录保留但本次登录不触发
  - 若当前用户未绑定 Passkey，则沿用现有登录流程
- 失败策略
  - Passkey 验证失败、用户取消或当前环境不支持 WebAuthn 时直接阻断进入主界面并提示错误
  - 不做静默降级，认证问题应尽早暴露
- 代码落点
  - `LoginForm.tsx`：将“登录成功即写 token”调整为“需要 Passkey 时先进入本机验证状态”
  - 登录设置页：增加 Passkey 绑定、验证、关闭入口
  - 本地存储工具：保存 Passkey 绑定状态和 credential id，后续接入加密存储

安全边界需要明确：客户端 Passkey 适合课程设计展示和本机客户端加固，但无法防止攻击者绕过客户端直接调用 `/account/login` 获取 token。生产级 Passkey 必须由服务端生成 challenge、保存公钥并验证签名，例如增加 `POST /account/passkey/challenge`、`POST /account/passkey/register` 和 `POST /account/passkey/verify`，并在服务端验证通过后才签发 `chatToken` / `imToken`。
