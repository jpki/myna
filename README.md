jinc - Japanese Indivisual Number Card Utility
==============================================

[![Build Status](https://travis-ci.org/hamano/jinc.svg?branch=master)](https://travis-ci.org/hamano/jinc)

## Install

### Requirements for Debian/Ubuntu

~~~
# apt-get install golang libpcsclite-dev
~~~

### Set GOPATH
~~~
$ export GOPATH=~/go
$ export PATH=$GOPATH/bin:$PATH
~~~

### Install jinc command
~~~
% go get github.com/hamano/jinc
~~~

## Usage

See jinc --help and jinc <subcommand> --help

~~~
% jinc --help
COMMANDS:
     sign_cert     署名用証明書を表示
     sign_ca_cert  署名用CA証明書を表示
     auth_cert     利用者認証用証明書を表示
     auth_ca_cert  利用者認証用CA証明書を表示
     tool          種々様々なツール
~~~

