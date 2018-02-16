#!/bin/bash
set -x

mkdir -p $GOPATH/src/github.com/jpki/
ln -sf $PWD $GOPATH/src/github.com/jpki/myna

make get-deps

make win

mkdir -p ${DIST_DIR}

cp myna.exe ${DIST_DIR}/
upx ${DIST_DIR}/myna.exe

(cd mynaqt && qtdeploy build windows)

find mynaqt/deploy
cp mynaqt/deploy/windows/mynaqt.exe ${DIST_DIR}/
upx ${DIST_DIR}/mynaqt.exe

