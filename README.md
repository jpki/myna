myna - マイナンバーカード・ユーティリティ
=========================================

## できること

- 券面入力補助APの読み取り
- 券面確認APの読み取り
- 公的個人認証の各種証明書の読み取り
- 公的個人認証の署名
- 各種PINステータスの確認
- 各種PINの変更(未テスト)
- スマホJPKI対応

## 動作プラットホーム

- Windows(未検証)
- OS X(未検証)
- Linux
- FreeBSD(未検証)

## ダウンロード

TODO

## 使い方

詳しくは `myna --help` や `サブコマンド --help` `サブサブコマンド --help` を実行してください。

~~~
Usage:
  myna [command]

  Available Commands:
    text        券面事項入力補助AP
    visual      券面AP
    jpki        公的個人認証関連コマンド
    cms         CMS署名関連コマンド
    pin         PIN関連操作
    test        リーダーの動作確認
    help        Help about any command
~~~

### 4属性を取得

~~~
$ myna text attr
~~~

### 顔写真を取得

~~~
$ myna visual photo -o photo.jp2
~~~

### PINのステータスを確認

~~~
$ myna pin status
~~~


### JPKI認証用証明書を取得

~~~
$ myna jpki cert auth
~~~

### JPKI署名用証明書を取得

~~~
$ myna jpki cert sign
~~~

### JPKI署名用証明書でCMS署名

~~~
$ myna jpki cms sign -i 署名対象ファイル -o 署名ファイル
~~~

### JPKI署名用CA証明書でCMS署名を検証

~~~
$ myna jpki cms verify 署名ファイル
~~~

OpenSSLコマンドで検証

~~~
$ openssl cms -verify -CAfile 署名用CA証明書 -inform der -in 署名ファイル
~~~

## ビルド環境

rust

## mynaコマンドのビルド・インストール

TODO:

### 依存パッケージのインストール

- Debian/Ubuntu

~~~
# apt-get install libpcsclite-dev
~~~

- RHEL/CentOS

~~~
# yum install pcsc-lite-devel
~~~

- Windows

TODO: wingetで

~~~
PS> 
~~~

- macOS

~~~
# brew install rustup-init
~~~

- FreeBSD

~~~
# pkg install pcsc-lite ccid pkgconf
~~~
