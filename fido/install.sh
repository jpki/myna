#!/bin/bash
#
# JPKI FIDO2 Native Messaging Hostのインストールスクリプト
# Chrome / Chromium に対応
#
# 1. ホストアプリケーション myna-fido の配置
# 2. Native Messaging Host manifest の配置

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PATH="$HOME/.local/bin/myna-fido"
HOST_NAME="com.github.jpki.fido2"
HOST_DESC="JPKI FIDO2 Authenticator"

# Chrome拡張ID (manifest.json の key フィールドから算出された固定ID)
CHROME_EXTENSION_ID="jipibpghkmlalpmkcmnloejkobhijbbm"
CHROME_USER_DATA_DIR=""

usage() {
    echo "Usage: $0 [--user-data-dir DIR]"
    echo ""
    echo "Options:"
    echo "  --user-data-dir DIR    Chromeの--user-data-dirに対応するパスを指定"
    echo ""
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user-data-dir)
            CHROME_USER_DATA_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

install_chrome() {
    local dir="$1"
    mkdir -p "$dir"
    cat > "$dir/$HOST_NAME.json" <<MANIFEST
{
  "name": "$HOST_NAME",
  "description": "$HOST_DESC",
  "path": "$HOST_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$CHROME_EXTENSION_ID/"
  ]
}
MANIFEST
    echo "Installed: $dir/$HOST_NAME.json"
}

echo "=== Installing JPKI FIDO2 Native Messaging Host ==="

# myna-fido バイナリの配置
BIN_SRC=""
if [ -f "$SCRIPT_DIR/../target/release/myna-fido" ]; then
    BIN_SRC="$SCRIPT_DIR/../target/release/myna-fido"
elif [ -f "$SCRIPT_DIR/../target/debug/myna-fido" ]; then
    BIN_SRC="$SCRIPT_DIR/../target/debug/myna-fido"
elif [ -f "$SCRIPT_DIR/myna-fido" ]; then
    BIN_SRC="$SCRIPT_DIR/myna-fido"
fi

if [ -n "$BIN_SRC" ]; then
    mkdir -p "$(dirname "$HOST_PATH")"
    install -m 755 "$BIN_SRC" "$HOST_PATH"
    echo "Installed: $HOST_PATH (from $BIN_SRC)"
else
    echo "Warning: myna-fido binary not found. Run 'cargo build --release -p myna-fido' first."
fi

if [ -n "$CHROME_USER_DATA_DIR" ]; then
    install_chrome "$CHROME_USER_DATA_DIR/NativeMessagingHosts"
else
    install_chrome "$HOME/.config/google-chrome/NativeMessagingHosts"
    install_chrome "$HOME/.config/chromium/NativeMessagingHosts"
fi

echo ""
echo "Done!"
