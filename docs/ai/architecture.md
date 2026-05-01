# Architecture

## Electron 架构

- main process：系统能力（如防截屏）
- renderer process：UI + OpenIM SDK

## OpenIM 使用方式

- 发送消息：
    createTextMessage → sendMessage

- 接收消息：
    onRecvNewMessages 回调

## 安全策略

所有加密逻辑在 renderer 层完成：

发送：
UI → encrypt → OpenIM

接收：
OpenIM → decrypt → UI

## 修改边界

允许：
✅ UI 层
✅ 消息发送前
✅ 消息接收后

禁止：
❌ OpenIM SDK 内部
❌ 网络层
❌ 服务端
