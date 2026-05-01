## `crypto_spec.md`

```md
# Crypto Spec

## API 定义

```ts
encrypt(plaintext: string, key: CryptoKey): SecurePayload

decrypt(payload: SecurePayload, key: CryptoKey): string

deriveKey(password: string, salt: Uint8Array): CryptoKey
```
## 算法要求
- AES-256-GCM
- IV 长度：12 bytes
- Key 长度：256 bits
- 使用 Web Crypto API（SubtleCrypto）

## 禁止

❌ 使用 crypto-js 实现 AES-GCM
❌ 自定义加密算法

