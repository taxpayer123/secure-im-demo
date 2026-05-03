# OpenIM Electron Demo

本项目基于 `open-im-sdk` / OpenIM Electron Demo 二次开发。  
目标是在保留现有即时通讯能力的基础上，增加客户端侧安全增强，目前重点是实现文本消息的端到端加密原型。

## 项目介绍

- 基础项目：OpenIM Electron Demo
- 开发方向：客户端安全加固
- 当前重点：文本消息端到端加密链路
- 核心原则：加密逻辑只放在客户端，不修改 OpenIM SDK 和服务端

## 当前实现的端到端加密方案

当前版本已从“全局预共享口令”切换到“单聊多会话密钥”方案，定位为演示可用级别：

- 首次本地生成长期身份密钥
  - `ECDH P-256`：用于协商会话密钥
  - `ECDSA P-256`：用于签名身份卡和会话邀请
- 单聊首次建立安全会话时，通过 OpenIM 自定义消息交换两类控制消息
  - `secure_identity_v1`：交换身份公钥与指纹
  - `secure_session_invite_v2`：携带 `sessionId`，发送加密后的会话密钥
- 文本消息使用 `AES-256-GCM` 加密，并在载荷中绑定 `sessionId`
  - 发送端使用当前 active session 的 `sessionKey`
  - 接收端按消息里的 `sessionId` 查找对应历史 `sessionKey`
  - 找不到历史密钥时显示“缺少历史会话密钥，无法解密”
- 客户端本地维护 `peerUserID -> sessionId -> sessionKey`，同时记录每个单聊的 `activeSessionId`
- 手动重置安全会话时不会覆盖旧 key
  - 旧 session 标记为 inactive，继续用于历史消息解密
  - 新建 `sessionId` 和 `sessionKey`
  - 新 session 设为 active，并通过 `secure_session_invite_v2` 通知对方
- 当前采用 `TOFU`（首次见即信任）思路
  - 首次收到对方身份时本地记录指纹
  - 若后续检测到对方身份指纹变化，则停用当前 active session 并提示风险

协议细节见：

- [data_contract.md](docs/ai/data_contract.md)
- [flow_e2ee.md](docs/ai/flow_e2ee.md)

## MFA 多因子认证方案

[mfa.md](docs/ai/mfa.md)

## Passkey 认证方案

[passkey.md](docs/ai/passkey.md)

## 当前进展

- 已完成
  - 单聊文本消息的客户端密钥协商与多 session 密钥存储
  - 消息载荷绑定 `sessionId`，按历史 session key 解密
  - 手动重置安全会话并保留旧 session key
  - 握手控制消息的收发与隐藏处理
  - 会话头部安全状态提示
  - 发送前本地敏感词过滤
- 当前边界
  - 密钥协商仅支持单聊，群聊尚未接入该方案
  - 当前为演示级实现，未实现双棘轮等生产级前向保密机制
  - 身份校验采用 TOFU，后续可继续补扫码/指纹比对界面
  - 旧版未携带 `sessionId` 的安全文本只能回退到 active 或唯一 session 解密
  - 如果接收端本地缺少某个历史 `sessionId` 对应的 invite/key，该消息会显示为缺少历史会话密钥

## 进度规划

1. 基线接入

   - 复用现有的登录、会话和消息收发流程
   - 尽量保持原有界面和交互稳定

2. E2EE 原型

   - 在客户端完成消息加密和解密
   - 统一安全消息载荷格式
   - 将单聊密钥管理从全局口令升级为可保留历史的会话密钥表
   - 发送前增加本地敏感词过滤

3. 安全提示

   - 在聊天头部显示安全会话状态
   - 对拦截消息、身份未就绪、身份变化和解密失败给出明确提示

4. 后续增强
   - 按需要扩展到群聊和更多消息类型
   - 引入更强的会话轮换与前向保密机制
   - 对缺失历史 session key 的场景增加更主动的历史控制消息回补
   - 增加阅后即焚等可选安全能力

## 说明

- 这是一个应用层增强项目，不是对 OpenIM SDK 的直接修改。
- 当前实现优先面向原型验证和课程设计展示，后续再逐步加固。
