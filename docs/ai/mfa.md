# MFA 多因子认证方案
MFA 定位为客户端演示版 TOTP 方案，用于降低密码泄露后的本机登录风险。该方案不修改 OpenIM SDK 和服务端：`/account/login` 返回 token 后，客户端先暂存登录结果并要求用户输入 6 位动态码；校验通过后才写入 `chatToken` / `imToken` 并进入聊天页。

- 认证方式
  - 使用 TOTP 6 位动态码，兼容 Google Authenticator / Microsoft Authenticator 等认证器
  - 技术实现可使用 `otplib` 生成和校验 TOTP，二维码优先复用 Ant Design 的 `QRCode`
- 首次绑定
  - 客户端为当前用户生成随机 Secret
  - 展示 `otpauth://` 二维码，用户使用认证器扫码绑定
  - 用户输入认证器中的 6 位动态码，校验通过后才确认绑定
  - Secret 仅本地保存，后续应放入加密存储；演示版不得硬编码 Secret
  - TOTP MFA 和 Passkey 的本地绑定记录可以同时保留，登录时优先使用 Passkey
- 登录校验
  - 密码或短信验证码登录成功后，不立即调用 `setIMProfile`
  - 若当前用户已启用 MFA，则暂存接口返回的 `chatToken`、`imToken`、`userID`
  - 弹出 MFA 输入框，动态码校验通过后再写入本地 token 并跳转 `/chat`
  - 若当前用户同时启用了 Passkey，则登录时优先使用 Passkey，不触发本次 MFA 输入
  - 若当前用户未绑定 MFA，则沿用现有登录流程
- 失败策略
  - 动态码错误时直接阻断进入主界面并提示错误
  - 不做复杂兜底和静默降级，认证问题应尽早暴露
- 代码落点
  - `LoginForm.tsx`：将“登录成功即写 token”调整为“需要 MFA 时先进入二次验证状态”
  - 登录设置页：增加 MFA 绑定、验证、关闭入口
  - 本地存储工具：保存 MFA 绑定状态和 Secret，后续接入加密存储

安全边界需要明确：客户端 MFA 适合课程设计展示和本机客户端加固，但无法防止攻击者绕过客户端直接调用 `/account/login` 获取 token。生产级 MFA 必须由服务端参与二段校验，例如增加 `POST /account/mfa/challenge` 和 `POST /account/mfa/verify`，并在服务端验证通过后才签发 `chatToken` / `imToken`。
