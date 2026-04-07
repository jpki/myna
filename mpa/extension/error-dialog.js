const params = new URLSearchParams(window.location.search);
const message = params.get("message") || "不明なエラー";
document.getElementById("error-message").textContent = message;
document.getElementById("close").addEventListener("click", () => {
  window.close();
});
