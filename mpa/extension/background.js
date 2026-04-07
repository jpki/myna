const HOST_NAME = "com.github.jpki.mpa";
let pinDialog = null;

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
    handleLaunch(request.message, sendResponse);
  } else if (request.type === "pin-dialog-result") {
    if (!pinDialog) {
      sendResponse({ ok: false });
      return;
    }
    const dialog = pinDialog;
    pinDialog = null;
    dialog.resolve(request.pin || null);
    sendResponse({ ok: true });
  } else if (request.type === "check") {
    sendNative(request.message, sendResponse);
  }
  return true;
});

async function handleLaunch(msg, callback) {
  if (pinDialog) {
    callback(null);
    return;
  }
  const mode = msg.mode || "01";
  const pin = await inputPin(mode);
  if (pin === null) {
    callback(null);
    return;
  }
  msg["pin"] = pin;
  sendNative(msg, callback);
}

function sendNative(msg, callback) {
  chrome.runtime.sendNativeMessage(HOST_NAME, msg, (response) => {
    if (chrome.runtime.lastError) {
      console.error("[MPA:BG] sendNativeMessage error:", chrome.runtime.lastError.message);
      callback(null);
      return;
    }
    if (response && response.result !== "0") {
      showError(response.message || "不明なエラーが発生しました");
    }
    callback(response);
  });
}

function showError(message) {
  const popupWidth = 420;
  const popupHeight = 200;
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
