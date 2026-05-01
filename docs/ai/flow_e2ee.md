# E2EE Flow

## 发送流程

UserInput
 → validateSensitiveWords(text)
 → encryptMessage(text)
 → openim.createTextMessage(ciphertext)
 → openim.sendMessage()

## 接收流程

onRecvNewMessages(msg)
 → if isSecurePayload(msg):
        plaintext = decryptMessage(msg)
        render(plaintext)
   else:
        render(msg)

## 错误处理

如果解密失败：
- UI显示："解密失败"
- 不抛异常
