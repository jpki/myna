# MPA for Linux

Linuxでマイナポータルにログインするためのブラウザ拡張およびNativeMessagingホストアプリケーションです。

## ホストアプリケーションのインストール

このディレクトリで
```
cargo install --path .
```

もしくはプロジェクトrootで

```
cargo install --path mpa
```

`~/.cargo/bin/mpa`にインストールされます。

## ホストアプリケーションの登録

```
./install.sh
```

ChromeのProfileを指定する場合

```
./install.sh --user-data-dir /path/to/datadir
```

## ブラウザ拡張のインストール

右上のディベロッパーモードをON

`chrome://extensions/`を開いて「パッケージ化されていない拡張機能を読み込む」で
`./mpa/extension`を読み込む

右上の拡張機能のメニューから「MPA for Linux」を開く、
動作確認ボタンを押してエラーが出なければOK

## ログイン

マイナポータルのログイン画面で暗証番号入力ウィンドウが表示されます。

カードを設置した上でJPKI認証用の暗証番号(4桁)を入力

