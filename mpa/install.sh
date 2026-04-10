#!/bin/bash
#
# Native Messaging Hostのインストールスクリプト
# Chrome / Chromium / Firefox に対応
#
# インストールスクリプトで行うこと
# 1. ホストアプリケーションmpaの配置
# 2. manifest.jsonの配置
# 3. config.jsonの配置(UUID生成)

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PATH="$HOME/.local/bin/mpa"
HOST_NAME="com.github.jpki.mpa"
HOST_DESC="MPA for Linux"

# Chrome拡張ID (manifest.jsonのkeyフィールドから算出された固定ID)
CHROME_EXTENSION_ID="mpaohblnoacafmpfmimdpnngljefbhmf"
CHROME_USER_DATA_DIR=""

usage() {
    echo "Usage: $0 [--chrome-extension-id ID] [--user-data-dir DIR]"
    echo ""
    echo "Options:"
    echo "  --user-data-dir DIR        Chromeの--user-data-dirに対応するパスを指定"
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

# --- Chrome / Chromium ---
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

# --- Firefox ---
install_firefox() {
    local dir="$1"
    mkdir -p "$dir"
    cat > "$dir/$HOST_NAME.json" <<MANIFEST
{
  "name": "$HOST_NAME",
  "description": "$HOST_DESC",
  "path": "$HOST_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "test@example.com"
  ]
}
MANIFEST
    echo "Installed: $dir/$HOST_NAME.json"
}

echo "=== Installing MPA for Linux ==="

# --- mpa バイナリのインストール ---
if [ -f "$SCRIPT_DIR/mpa" ]; then
    mkdir -p "$(dirname "$HOST_PATH")"
    install -m 755 "$SCRIPT_DIR/mpa" "$HOST_PATH"
    echo "Installed: $HOST_PATH"
else
    echo "Warning: $SCRIPT_DIR/mpa not found, skipping binary install"
fi

# --user-data-dir が指定された場合はそこにインストール
if [ -n "$CHROME_USER_DATA_DIR" ]; then
    install_chrome "$CHROME_USER_DATA_DIR/NativeMessagingHosts"
else
    # Chrome
    install_chrome "$HOME/.config/google-chrome/NativeMessagingHosts"

    # Chromium
    install_chrome "$HOME/.config/chromium/NativeMessagingHosts"
fi

# Firefox
install_firefox "$HOME/.mozilla/native-messaging-hosts"

# --- config.json ---
CONFIG_DIR="$HOME/.config/mpa"
CONFIG_FILE="$CONFIG_DIR/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    UUID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<CONFIG
{"uuid": "$UUID"}
CONFIG
    echo "Created: $CONFIG_FILE"
else
    echo "Already exists: $CONFIG_FILE"
fi

echo ""
echo "Done!"
