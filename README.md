myna - Japanese Individual Number Card Utility
==============================================

[![Build Status](https://travis-ci.org/jpki/myna.svg?branch=master)](https://travis-ci.org/jpki/myna)

## Build requirements
golang 1.6 or later

## Install myna command

~~~
% go get -u -v github.com/jpki/myna
~~~

## Usage

See myna --help and myna <subcommand> --help

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


### Build Requirements for Debian/Ubuntu

~~~
# apt-get install golang libpcsclite-dev
~~~

### Set GOPATH
~~~
$ export GOPATH=~/go
$ export PATH=$GOPATH/bin:$PATH
~~~

### Build Requirements for Windows

- Install golang and git
- github.com/ebfe/scard is not allow to build on windows. apply [the patch](https://github.com/ebfe/scard/pull/3)

### Build Requirements for OSX
