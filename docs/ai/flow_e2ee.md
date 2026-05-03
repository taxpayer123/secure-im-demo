# E2EE Flow

## Session Negotiation

```text
ensureConversationSession(peer)
  -> get activeSessionId
  -> found active session: reuse session key
  -> missing active session:
       create sessionId
       create sessionKey
       send secure_session_invite_v2(sessionId, wrappedSessionKey)
       save session as active
```

On reset:

```text
mark all local sessions inactive
clear activeSessionId
create a new sessionId + sessionKey
send secure_session_invite_v2
set the new session active
```

## Send Flow

```text
UserInput
  -> validateSensitiveWords(text)
  -> get active session
  -> encryptMessage(text, activeSession.sessionKey)
  -> payload.sessionId = activeSession.sessionId
  -> openim.createTextMessage(JSON.stringify(payload))
  -> openim.sendMessage()
```

## Receive Flow

```text
onRecvNewMessages(msg)
  -> if secure_session_invite_v2:
       decrypt wrappedSessionKey
       save session under payload.sessionId
       set as active session when newer than the current active session
       stop rendering control message
  -> if secure_text_v1:
       read payload.sessionId
       get session key by sessionId
       found: decrypt and render plaintext
       missing: render "缺少历史会话密钥，无法解密"
  -> else:
       render(msg)
```

## Error Handling

- Missing historical session key: render `缺少历史会话密钥，无法解密`.
- Decrypt failure with an existing key: render `解密失败`.
- Secure control messages are not rendered in the chat list.
