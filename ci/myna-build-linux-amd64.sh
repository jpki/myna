#!/bin/bash
set -eu
set -x

mkdir -p $GOPATH/src/github.com/jpki/
ln -sf $PWD $GOPATH/src/github.com/jpki/myna

make get-deps
make

mkdir -p ${DIST_DIR}

strip myna
cp myna ${DIST_DIR}/
upx ${DIST_DIR}/myna

exit 0

(cd mynaqt && qtdeploy build)

find mynaqt/deploy
cp mynaqt/deploy/linux/mynaqt ${DIST_DIR}/
cp -rp mynaqt/deploy/linux/lib ${DIST_DIR}/
mkdir -p ${DIST_DIR}/plugins
cp -rp mynaqt/deploy/linux/plugins/platforms ${DIST_DIR}/plugins
chrpath -r '$ORIGIN/lib' ${DIST_DIR}/mynaqt
cp mynaqt/deploy/linux/mynaqt.sh ${DIST_DIR}/
upx ${DIST_DIR}/mynaqt
