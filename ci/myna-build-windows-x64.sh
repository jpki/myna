#!/bin/bash
set -eu
set -x

mkdir -p $GOPATH/src/github.com/jpki/
ln -sf $PWD $GOPATH/src/github.com/jpki/myna

make get-deps

go get -u github.com/inconshreveable/mousetrap

make win

mkdir -p ${DIST_DIR}

upx myna.exe
cp myna.exe ${DIST_DIR}/

exit 0

(cd mynaqt && qtdeploy build windows)

find mynaqt/deploy
upx mynaqt/deploy/windows/mynaqt.exe
cp mynaqt/deploy/windows/mynaqt.exe ${DIST_DIR}/

