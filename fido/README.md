# マイナンバーカードをFIDO2デバイスにする試み

## 概要
パスキーはスマホを無くしたら詰んでしまう。という所がよく心配されます。
2台目のスマホやFIDO2認証器を登録しておけば安心なのですが、
普通はスマホを何台も持っていないし、FIDOキーはなおさら持っている人は少ないです。
誰でも持っているマイナンバーカードをFIDOデバイスとして登録しておけば
スマホ紛失に対するリカバリー対策になるかもしれません。

証明書の更新やカードに穴を空けられてしまうという欠点はありますが、
無くしたと言って(お金を支払い)保有し続けることは可能です。

## 登録シーケンス

```mermaid
sequenceDiagram
    autonumber
    participant User as ユーザー
    participant Card as カード
    participant Ext as ブラウザ拡張
    participant RP as サーバー (RP)

    User->>RP: 新規登録操作
    RP-->>Ext: 登録オプション<br/>(challenge, rp.id, user.id, pubKeyCredParams)

    Ext->>User: PIN 入力要求
    User->>Ext: PIN 入力 (UV)

    Note over Ext: Ed25519鍵の導出開始

    Ext->>Card: RSA署名(PIN, rpId, userId)
    Card-->>Ext: RSA署名値

    Note over Ext: Ed25519鍵ペア導出<br/>credentialId = SHA-256(公開鍵)
    Note over Ext: chrome.storage.local に<br/>(rpId, userId, credentialId) 保存

    Ext->>RP: 登録応答<br/>(credentialId, Ed25519公開鍵, attestationObject)
    Note over RP: credentialId と公開鍵を保存
    RP->>User: 登録完了
```

## 認証シーケンス

allowCredentials指定ありの最もシンプルなケース

```mermaid
sequenceDiagram
    autonumber
    participant User as ユーザー
    participant Card as カード
    participant Ext as ブラウザ拡張
    participant RP as サーバー (RP)

    User->>RP: ログイン操作
    RP-->>Ext: 認証オプション<br/>(challenge, allowCredentials)
    Note over Ext: credentialId 照合 → userId 特定

    Ext->>User: PIN 入力要求
    User->>Ext: PIN 入力 (UV)

    Note over Ext: Ed25519鍵の導出開始

    Ext->>Card: RSA署名(PIN, rpId, userId)
    Card-->>Ext: RSA署名値

    Note over Ext: Ed25519鍵を導出、authenticatorDataに署名

    Ext->>RP: 認証応答
    Note over RP: Ed25519公開鍵で署名検証
    RP->>User: 認証成功・ログイン完了
```
