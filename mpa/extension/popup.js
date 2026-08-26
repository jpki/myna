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
const copyButton = document.getElementById("copy");

// 項目名の表示ラベル(未定義の項目は名前をそのまま表示する)
const CHECK_LABELS = {
  connect: "カード接続",
  select_jpki: "JPKI AP選択",
  jpki_auth_pin_counter: "認証用暗証番号",
  jpki_sign_pin_counter: "署名用パスワード",
};

// 出力した行。コピーボタンは<pre>の中にあるため、
// pre全体ではなくこの配列をコピー対象にする
let lines = [];

function log(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  lines.push(text);
  result.append(document.createTextNode(`${text}\n`));
  copyButton.hidden = false;
}

function clearLog() {
  lines = [];
  for (const node of [...result.childNodes]) {
    if (node !== copyButton) {
      node.remove();
    }
  }
  copyButton.hidden = true;
}

async function copyLog() {
  const text = lines.join("\n");
  try {
    if (!navigator.clipboard) {
      throw new Error("clipboard is not available");
    }
    await navigator.clipboard.writeText(text);
  } catch {
    // クリップボードAPIが使えない場合のフォールバック
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
  copyButton.textContent = "コピーしました";
  setTimeout(() => {
    copyButton.textContent = "コピー";
  }, 1500);
}

copyButton.addEventListener("click", copyLog);

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
  clearLog();
  log("動作確認...");

  try {
    const res = await sendBackground({
      type: "check",
      message: {
        mode: "check",
      }
    });
    if (!res) {
      throw new Error("バックグラウンドから応答がありません(拡張機能のコンソールを確認してください)");
    }
    if (res["result"] !== "0") {
      throw new Error(res.error ?? res.message ?? "Unknown error");
    }

    log("Host Version: " + res.version);
    log("Host UUID: " + res.uuid);
    log("Host PID: " + res.pid);
    for (const item of res.check ?? []) {
      const name = CHECK_LABELS[item.name] ?? item.name;
      const detail = item.detail ? ` (${item.detail})` : "";
      log(`${name}: ${item.status}${detail}`);
    }
  } catch (error) {
    log({
        ok: false,
        error: error.message
    });
  }
});
