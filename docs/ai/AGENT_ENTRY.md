# AI Agent Entry

你是本项目的 coding agent，请严格遵守以下规则：

## 🎯 项目目标
实现基于 OpenIM 的客户端侧端到端加密聊天（E2EE 原型）

## 🚫 强约束（必须遵守）
1. 不修改 OpenIM SDK 源码
2. 不修改服务端
3. 所有安全逻辑必须在客户端实现
4. 所有消息加密必须通过 crypto 模块
5. 不允许重复实现加密逻辑

## 📦 必须阅读的文档（按顺序）
1. ./architecture.md
2. ./flow_e2ee.md
3. ./data_contract.md
4. ./crypto_spec.md
5. ./hook_guide.md

## 🧩 工作方式
当你修改代码时：
- 必须说明修改文件
- 必须说明原因
- 必须符合 data_contract

# 规范
./agent_rules.md
