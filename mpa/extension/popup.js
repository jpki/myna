// ブラウザ拡張のバージョン表示
document.addEventListener("DOMContentLoaded", () => {
  const versionElement = document.getElementById("version");
  if (versionElement) {
    const version = chrome.runtime.getManifest().version;
    versionElement.textContent = `Extension Version: ${version}`;
  }
});

const form = document.getElementById("check-form");
const result = document.getElementById("result");

function log(value) {
  result.textContent += typeof value === "string" ? value : JSON.stringify(value, null, 2);
  result.textContent += "\n";
}

function sendBackground(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const runtimeError = chrome.runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }
      resolve(response);
    });
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  result.textContent = "";
  log("動作確認...");

  try {
    const res = await sendBackground({
      type: "check",
      message: {
        mode: "check",
      }
    });
    if (res["result"] !== "0") {
      throw new Error(res?.error ?? "Unknown error");
    }

    log("Host Version: " + res.version);
    log("Host UUID: " + res.uuid);
    log("Host PID: " + res.pid);
  } catch (error) {
    log({
        ok: false,
        error: error.message
    });
  }
});
