# Hook Guide

## 发送消息拦截

文件：
src/chat/sendMessage.ts

函数：
handleSendMessage(text)

修改：
在 createTextMessage 前调用 encryptMessage

---

## 接收消息拦截

文件：
src/chat/messageListener.ts

函数：
onRecvNewMessages

修改：
在渲染前调用 decryptMessage

