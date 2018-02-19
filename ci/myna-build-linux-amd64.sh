#!/bin/bash
set -x

mkdir -p $GOPATH/src/github.com/jpki/
ln -sf $PWD $GOPATH/src/github.com/jpki/myna

make get-deps
make

mkdir -p ${DIST_DIR}

cp myna ${DIST_DIR}/
strip ${DIST_DIR}/myna
upx ${DIST_DIR}/myna

(cd mynaqt && qtdeploy build)

find mynaqt/deploy
cp mynaqt/deploy/linux/mynaqt ${DIST_DIR}/
cp -rp mynaqt/deploy/linux/lib ${DIST_DIR}/
chrpath -r '$ORIGIN/lib' ${DIST_DIR}/mynaqt
cp ${DIST_DIR}/mynaqt ${DIST_DIR}/mynaqt.orig
upx ${DIST_DIR}/mynaqt
