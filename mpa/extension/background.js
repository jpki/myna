const HOST_NAME = "com.github.jpki.mpa";
const LOG_PREFIX = "[MPA:BG]";
let pinDialog = null;

function logInfo(...args) {
  console.log(LOG_PREFIX, ...args);
}

function logError(...args) {
  console.error(LOG_PREFIX, ...args);
}

// バックグラウンド(イベントページ/Service Worker)の起動・停止を記録する。
// 処理の途中で停止・再起動していると、応答が失われて原因不明のエラーになるため。
logInfo(
  `background started: version=${chrome.runtime.getManifest().version}, ua=${navigator.userAgent}`
);
if (chrome.runtime.onSuspend) {
  chrome.runtime.onSuspend.addListener(() => {
    logInfo("background suspending");
  });
}

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    const { installId } = await chrome.storage.local.get("installId");
    if (!installId) {
      await chrome.storage.local.set({ installId: crypto.randomUUID() });
    }
  }
});

chrome.windows.onRemoved.addListener((windowId) => {
  if (pinDialog && pinDialog.windowId === windowId) {
    pinDialog.resolve(null);
    pinDialog = null;
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (typeof request.message === "string") {
    request.message = JSON.parse(request.message);
  }
  if (request.type === "launch") {
    handleLaunch(request.message, (response) => sendResponse(response));
  } else if (request.type === "pin-dialog-result") {
    if (!pinDialog) {
      logError("pin-dialog-result received but no dialog is waiting");
      sendResponse({ ok: false });
      return;
    }
    const dialog = pinDialog;
    pinDialog = null;
    dialog.resolve(request.pin || null);
    sendResponse({ ok: true });
  } else if (request.type === "check") {
    sendNative(request.message, (response, error) => {
      sendResponse(response != null ? response : { result: "1", error: error });
    });
  }
  return true;
});

async function handleLaunch(msg, callback) {
  if (pinDialog) {
    logError("another PIN dialog is already open");
    callback(null);
    return;
  }
  const mode = msg.mode || "01";
  const pin = await inputPin(mode);
  if (pin === null) {
    logInfo(`PIN dialog canceled: mode=${mode}`);
    callback(null);
    return;
  }
  msg["pin"] = pin;
  sendNative(msg, callback);
}

function sendNative(msg, callback) {
  const mode = (msg && msg.mode) || "unknown";
  const started = Date.now();
  logInfo(`sendNativeMessage start: host=${HOST_NAME}, mode=${mode}`);
  try {
    chrome.runtime.sendNativeMessage(HOST_NAME, msg, (response) => {
      const elapsed = Date.now() - started;
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        handleNativeError(lastError.message, mode, elapsed, callback);
        return;
      }
      logInfo(
        `sendNativeMessage done: mode=${mode}, elapsed=${elapsed}ms, result=${response && response.result}`
      );
      if (response && response.result !== "0") {
        const message = response.message || response.error || "不明なエラーが発生しました";
        logError(`host returned an error: mode=${mode}, message=${message}`);
        showError(message);
      }
      callback(response, null);
    });
  } catch (error) {
    // Firefoxでは引数不正などが同期例外として投げられる場合がある
    const detail = describeError(error);
    logError(`sendNativeMessage threw: mode=${mode}, ${detail}`);
    showError(`ホストアプリケーションの呼び出しに失敗しました。\n${detail}`);
    callback(null, detail);
  }
}

// chrome.runtime.lastError や例外オブジェクトから可能な限り情報を取り出す
function describeError(error) {
  if (error == null) {
    return "不明なエラー";
  }
  if (typeof error === "string") {
    return error;
  }
  const parts = [];
  if (error.name) {
    parts.push(`name=${error.name}`);
  }
  parts.push(`message=${error.message || String(error)}`);
  if (error.stack) {
    parts.push(`stack=${error.stack}`);
  }
  return parts.join(", ");
}

// エラーメッセージから考えられる原因を提示する。
// 特にFirefoxは内部エラーを "An unexpected error occurred" に丸めてしまうため、
// 拡張機能側で候補を示し、確認手順を案内する。
function nativeErrorHint(message) {
  const text = message || "";
  if (/No such native application/i.test(text)) {
    return [
      "ホストアプリケーションのmanifestが見つかりません。",
      "・install.sh を実行したか確認してください",
      "・snap版Firefoxは ~/snap/firefox/common/.mozilla/native-messaging-hosts/",
      "  flatpak版Firefoxは ~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/",
      "  にmanifestを配置する必要があります",
    ].join("\n");
  }
  if (/permission|forbidden|not allowed/i.test(text)) {
    return [
      "manifestが拡張機能の利用を許可していません。",
      "・Firefox: allowed_extensions に拡張機能のIDが含まれているか",
      "・Chrome: allowed_origins に拡張機能のIDが含まれているか",
      "を確認してください。",
    ].join("\n");
  }
  if (/exited|closed|terminated/i.test(text)) {
    return [
      "ホストアプリケーションが応答を返さずに終了しました。",
      "MPA_LOG=/tmp/mpa.log を設定してブラウザーを起動し直し、ログを確認してください。",
    ].join("\n");
  }
  if (/unexpected error/i.test(text)) {
    return [
      "Firefoxが内部エラーの詳細を隠しています。考えられる原因:",
      "・ホストアプリケーション(~/.local/bin/mpa)を起動できない(未配置・実行権限・snap/flatpakの制限)",
      "・ホストアプリケーションが応答を返す前に異常終了した",
      "・応答の形式が不正、またはサイズが上限(1MB)を超えた",
      "詳細はブラウザーコンソール(Ctrl+Shift+J)に出力されています。",
    ].join("\n");
  }
  return "";
}

// エラー発生後にホストアプリケーションを起動できるか確認し、
// 「起動できない」のか「処理中に落ちた」のかを切り分ける
function probeHost() {
  return new Promise((resolve) => {
    const started = Date.now();
    try {
      chrome.runtime.sendNativeMessage(HOST_NAME, { mode: "check" }, (response) => {
        const elapsed = Date.now() - started;
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          resolve(`ホスト再確認: 起動できません (${lastError.message}, ${elapsed}ms)`);
          return;
        }
        resolve(
          `ホスト再確認: 起動OK (version=${response && response.version}, ${elapsed}ms)` +
            " → 処理中にホストが異常終了した可能性があります"
        );
      });
    } catch (error) {
      resolve(`ホスト再確認: 例外 (${describeError(error)})`);
    }
  });
}

async function handleNativeError(message, mode, elapsed, callback) {
  const detail = message || "不明なエラー";
  logError(
    `sendNativeMessage error: mode=${mode}, elapsed=${elapsed}ms, host=${HOST_NAME}, message=${detail}`
  );

  const lines = [
    "ホストアプリケーションとの通信に失敗しました。",
    `エラー: ${detail}`,
    `mode=${mode}, 経過時間=${elapsed}ms`,
  ];

  // checkは診断そのものなので再確認しない(無限に繰り返さないため)
  if (mode !== "check") {
    const probe = await probeHost();
    logInfo(probe);
    lines.push(probe);
  }

  const hint = nativeErrorHint(detail);
  if (hint) {
    lines.push("", hint);
  }

  const text = lines.join("\n");
  showError(text);
  callback(null, text);
}

function showError(message) {
  const popupWidth = 480;
  const lines = String(message).split("\n").length;
  const popupHeight = Math.min(560, 200 + lines * 20);
  chrome.windows.getCurrent().then((currentWindow) => {
    const left = Math.round(currentWindow.left + (currentWindow.width - popupWidth) / 2);
    const top = Math.round(currentWindow.top + (currentWindow.height - popupHeight) / 2);
    chrome.windows.create({
      url: chrome.runtime.getURL(`error-dialog.html?message=${encodeURIComponent(message)}`),
      type: "popup",
      width: popupWidth,
      height: popupHeight,
      left: left,
      top: top,
      focused: true,
    });
  });
}

async function inputPin(mode) {
  const popupWidth = 420;
  const popupHeight = 280;
  const currentWindow = await chrome.windows.getCurrent();
  const left = Math.round(currentWindow.left + (currentWindow.width - popupWidth) / 2);
  const top = Math.round(currentWindow.top + (currentWindow.height - popupHeight) / 2);
  const createdWindow = await chrome.windows.create({
    url: chrome.runtime.getURL(`pin-dialog.html?mode=${mode}`),
    type: "popup",
    width: popupWidth,
    height: popupHeight,
    left: left,
    top: top,
    focused: true
  });
  return new Promise((resolve) => {
    pinDialog = {
      resolve: resolve,
      windowId: createdWindow.id
    };
  });
}
