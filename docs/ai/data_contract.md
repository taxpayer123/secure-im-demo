# Secure Message Contract

## 类型定义

```ts
type SecurePayload = {
  type: "secure_text_v1"
  alg: "AES-256-GCM"
  iv: string        // base64
  ciphertext: string // base64
  salt: string       // base64
  timestamp: number
  burnAfterRead?: boolean
}
```

## 规则
- 所有字段必须存在
- 所有二进制数据必须 base64 编码
- type !== secure_text_v1 时视为普通消息
-  JSON 序列化后作为 text message 发送

