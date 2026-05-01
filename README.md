myna - マイナンバーカード・ユーティリティ
=========================================

> **Note:** バージョン0.6よりRust実装に置き換わりました。
> コマンドラインオプションが一部変更されていますので、以下の利用方法を確認してください。

## できること

- 券面入力補助APの読み取り
- 券面確認APの読み取り
- 公的個人認証の各種証明書の読み取り
- 公的個人認証の署名
- 各種PINステータスの確認
- 各種PINの変更(未テスト)
- スマホJPKI対応

### サブプロジェクト

- [MPA for Linux](./mpa): Linuxでマイナポータルにログインするためのブラウザ拡張
- [Myna FIDO](./fido): マイナンバーカードをFIDO2キーにする試み

## 動作プラットホーム

- Linux
- Windows
- macOS(未検証)

## ビルド環境

Rust (Edition 2024)

### 依存パッケージのインストール

PC/SCライブラリの開発パッケージが必要です。

- Debian/Ubuntu

~~~
$ sudo apt-get install libpcsclite-dev
~~~

- RHEL/CentOS/Fedora

~~~
$ sudo yum install pcsc-lite-devel
~~~

- macOS

追加パッケージは不要です(PCSC.frameworkが標準搭載)。

- Windows

追加パッケージは不要です(WinSCardが標準搭載)。

## ビルド

~~~
$ cargo build --release
~~~

ビルド成果物は `target/release/myna` に生成されます。

## インストール

~~~
$ cargo install --path .
~~~

`~/.cargo/bin/myna` にインストールされます。`~/.cargo/bin` にパスが通っていれば `myna` コマンドが使えます。

## 使い方

詳しくは `myna --help` や `サブコマンド --help` `サブサブコマンド --help` を実行してください。

~~~
Usage:
  myna [command]

  Available Commands:
    text        券面事項入力補助AP
    visual      券面確認AP
    jpki        公的個人認証関連
    pin         PIN関連操作
    test        リーダーの動作確認
    help        Help about any command
~~~

### 券面入力補助APから4属性(氏名・住所・生年月日・性別)を取得

~~~
$ myna text attr
~~~

### 券面確認APから顔写真を取得

~~~
$ myna visual photo -o photo.jp2
~~~

### 券面確認APから氏名画像を取得 (PNG画像)

~~~
$ myna visual name -o name.png
~~~

### 券面確認APから住所画像を取得 (PNG画像)

~~~
$ myna visual addr -o addr.png
~~~

### 券面確認APから生年月日を表示

~~~
$ myna visual birth
~~~

### 券面確認APから性別を表示

~~~
$ myna visual sex
~~~

### PINのステータスを確認

~~~
$ myna pin status
~~~

### JPKI認証用証明書を取得

~~~
$ myna jpki cert -t auth
~~~

### JPKI署名用証明書を取得

JPKI署名用証明書は4属性(氏名・住所・生年月日・性別)を含みますので注意してください。

~~~
$ myna jpki cert -t sign
~~~

### JPKI署名用証明書でCMS署名

RFC 5652 CMS署名を行います。
JPKI署名用証明書は4属性(氏名・住所・生年月日・性別)を含みますので注意してください。

~~~
$ myna jpki cms sign 署名対象ファイル -o 署名ファイル
~~~

### JPKI署名用CA証明書でCMS署名を検証

~~~
$ myna jpki cms verify 署名ファイル
~~~

OpenSSLコマンドで検証

~~~
$ openssl cms -verify -CAfile 署名用CA証明書 -inform der -in 署名ファイル
~~~

### PDFに電子署名を付与

PAdES署名を行います。
JPKI署名用証明書は4属性(氏名・住所・生年月日・性別)を含みますので注意してください。

~~~
$ myna jpki pdf sign input.pdf -o signed.pdf
~~~

### PDF電子署名を検証

~~~
$ myna jpki pdf verify signed.pdf
~~~

## 電子署名検証について

公的個人認証法第17条では、業としてデジタル署名検証を行うことは総務大臣の認可が必要とされています。利用する際はこの点ご注意ください。

一方、個人的な用途や自分で行ったデジタル署名が正しくできたか確認する行為は禁止されていません。

これは物理判子に例えると、判子を正しく押せたかな?と確認する行為にあたります。
印影が欠けていれば押し直すと思います。

これに相当する行為として、mynaコマンドでは簡易的なデジタル署名検証機能を提供しています。

