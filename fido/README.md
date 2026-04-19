# マイナンバーカードをFIDO2デバイスにする試み

## 概要
パスキーはスマホを無くしたら詰んでしまう。という所がよく心配されます。
2台目のスマホやFIDO2認証器を登録しておけば安心なのですが、
普通はスマホを何台も持っていないし、FIDOキーはなおさら持っている人は少ないです。
誰でも持っているマイナンバーカードをFIDOデバイスとして登録しておけば
スマホ紛失に対するリカバリー対策になるかもしれません。

証明書の更新やカードに穴を空けられてしまうという欠点はありますが、
無くしたと言って(お金を支払い)保有し続けることは可能です。

## 認証シーケンス

```mermaid
sequenceDiagram
    autonumber
    participant User as ユーザー
    participant Auth as 認証器 (Authenticator)
    participant Client as ブラウザ (WebAuthn API)
    participant RP as サーバー (Relying Party)

    User->>RP: ログイン開始リクエスト
    RP->>RP: チャレンジコード生成
    RP->>Client: 認証オプション (Challenge, AllowCredentials)

    Client->>Auth: 署名要求 (navigator.credentials.get)
    Note over Auth: ユーザーの存在確認<br/>(生体認証など)
    Auth->>Auth: 秘密鍵でチャレンジに署名
    Auth->>Client: 署名済みデータ (Signature, AuthenticatorData)

    Client->>RP: 認証応答 (Credential ID, Signature, ClientDataJSON)
    RP->>RP: 保存されている公開鍵を取得
    RP->>RP: 署名の検証 & チャレンジの確認
    RP->>User: 認証成功・ログイン完了
```
