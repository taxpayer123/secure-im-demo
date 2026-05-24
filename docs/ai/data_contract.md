# Secure Message Contract

## Local Session Store

```ts
type SecureSession = {
  sessionId: string;
  peerUserID: string;
  peerFingerprint: string;
  sessionKey: string; // base64 encoded AES-256 key
  active: boolean;
  createdAt: number;
  updatedAt: number;
};

type SecureSessionStore = {
  conversationKey: string;
  peerUserID: string;
  activeSessionId?: string;
  sessions: Record<string, SecureSession>;
};
```

Resetting a secure session keeps old sessions for historical messages:

```text
oldSession.active = false
newSession.sessionId = sess_...
newSession.active = true
activeSessionId = newSession.sessionId
```

## Secure Text Payload

```ts
type SecurePayload = {
  type: "secure_text_v1";
  version: 2;
  sessionId: string;
  alg: "AES-256-GCM";
  iv: string; // base64
  ciphertext: string; // base64
  salt: string; // base64
  timestamp: number;
  burnAfterRead?: boolean;
};
```

## Secure Session Invite

```ts
type SecureSessionInvitePayload = {
  type: "secure_session_invite_v2";
  sessionId: string;
  userID: string;
  fingerprint: string;
  ephemeralPublicKey: JsonWebKey;
  wrappedSessionKey: string; // base64
  iv: string; // base64
  salt: string; // base64
  timestamp: number;
  signature: string;
};
```

## Rules

- All binary data is base64 encoded.
- `secure_text_v1` version 2 messages must include `sessionId`.
- Receivers decrypt with the session key matching `payload.sessionId`.
- If the session key is missing, render `缺少历史会话密钥，无法解密`.
- Legacy `secure_text_v1` messages without `sessionId` are not valid secure messages.
- Session reset must not overwrite old session keys.
