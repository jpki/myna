"use strict";

const params = new URLSearchParams(location.search);
const message = params.get("message") || "不明なエラーが発生しました";
document.getElementById("message").textContent = message;

document.getElementById("ok").addEventListener("click", () => {
  window.close();
});
