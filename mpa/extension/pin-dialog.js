const form = document.getElementById("pin-form");
const pinInput = document.getElementById("pin");
const cancelButton = document.getElementById("cancel");

const params = new URLSearchParams(window.location.search);
const mode = params.get("mode");

const MODES = {
  "01": {
    title: "認証用暗証番号入力",
    lead: "ログインのため、公的個人認証の認証用暗証番号(4桁)を入力してください。",
    label: "認証用暗証番号(4桁)",
    inputMode: "numeric",
    maxLength: 4,
    pattern: "\\d{4}",
  },
  "02": {
    title: "署名用パスワード入力",
    lead: "署名のため、公的個人認証の署名用パスワード(6〜16文字の英数字)を入力してください。",
    label: "署名用パスワード",
    inputMode: "text",
    maxLength: 16,
    pattern: "[a-zA-Z0-9]{6,16}",
  },
  "04": {
    title: "券面入力補助用暗証番号入力",
    lead: "券面情報取得のため、券面入力補助用暗証番号(4桁)を入力してください。",
    label: "券面入力補助用暗証番号(4桁)",
    inputMode: "numeric",
    maxLength: 4,
    pattern: "\\d{4}",
  },
};

const config = MODES[mode];

if (config) {
  document.getElementById("dialog-title").textContent = config.title;
  document.getElementById("dialog-lead").textContent = config.lead;
  document.getElementById("pin-label").textContent = config.label;
  pinInput.inputMode = config.inputMode;
  pinInput.maxLength = config.maxLength;
  pinInput.pattern = config.pattern;
} else {
  document.getElementById("dialog-title").textContent = "非対応";
  document.getElementById("dialog-lead").textContent = `モード「${mode}」には対応していません。`;
  form.style.display = "none";
}

function sendResult(pin) {
  chrome.runtime.sendMessage({
    type: "pin-dialog-result",
    pin
  }, () => {
    window.close();
  });
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  sendResult(pinInput.value);
});

cancelButton.addEventListener("click", () => {
  sendResult(null);
});
