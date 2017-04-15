myna - マイナンバーカード・ユーティリティ
==============================================

[![Build Status](https://travis-ci.org/jpki/myna.svg?branch=master)](https://travis-ci.org/jpki/myna)
[![codebeat](https://codebeat.co/badges/0bbab46f-5683-4848-92e7-eed36e660b0f)](https://codebeat.co/projects/github-com-jpki-myna-master)
[![Go Report Card](https://goreportcard.com/badge/jpki/myna)](https://goreportcard.com/report/jpki/myna)

## サポートOS

- Windows
- OS X
- Linux
- FreeBSD

## 使い方

myna --help や myna `サブコマンド` --help を見てください。

~~~
% myna --help
COMMANDS:
     card          券面事項を表示
     pin_status    PINステータスを表示
     sign_cert     署名用証明書を表示
     sign_ca_cert  署名用CA証明書を表示
     auth_cert     利用者認証用証明書を表示
     auth_ca_cert  利用者認証用CA証明書を表示
     tool          種々様々なツール
~~~

## ビルド環境

golang 1.6 or later

## mynaコマンドのビルド・インストール

~~~
% go get -u github.com/jpki/myna
~~~

### 依存パッケージのインストール(Debian/Ubuntu)

~~~
# apt-get install libpcsclite-dev
~~~

### 依存パッケージのインストール(RHEL/CentOS)

~~~
# yum install pcsc-lite-devel
~~~

### Windowsでビルド

~~~
PS> choco install -y git golang
~~~

### OSXでビルド

### FreeBSDでビルド

依存パッケージのインストール

~~~
# pkg install pcsc-lite ccid pkgconf
~~~
